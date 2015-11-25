(* $Id$ *)

class type tls_channel = object
  inherit Netchannels.raw_io_channel
  method tls_endpoint : Netsys_crypto_types.tls_endpoint
end


class type crypto_out_filter = object
  inherit Netchannels.out_obj_channel
  method supports_aead : bool
  method mac : unit -> string
end


class type crypto_in_filter = object
  inherit Netchannels.in_obj_channel
  method supports_aead : bool
  method mac : unit -> string
end


(************************** TLS *****************************)

class tls_layer ?(start_pos_in=0) ?(start_pos_out=0) ?resume
                ~role ~rd ~wr ~peer_name config =
  let sbuf = Bytes.create 65536 in
  let recv buf =
    try
      let buf_len = min (Bigarray.Array1.dim buf) (Bytes.length sbuf) in
      let n = rd # input sbuf 0 buf_len in
      if n = 0 then raise(Unix.Unix_error(Unix.EAGAIN, "", ""));
      Netsys_mem.blit_bytes_to_memory sbuf 0 buf 0 n;
      n
    with
      | Sys_blocked_io ->  raise(Unix.Unix_error(Unix.EAGAIN, "", ""))
      | End_of_file -> 0 in
  let send buf size =
    try
      let send_len = min size (Bytes.length sbuf) in
      Netsys_mem.blit_memory_to_bytes buf 0 sbuf 0 send_len;
      let n = ref 0 in
      while !n < send_len do
        let p = wr # output sbuf !n (send_len - !n) in
        n := !n + p
      done;
      wr # flush();
      send_len
    with
      | Sys_blocked_io ->  raise(Unix.Unix_error(Unix.EAGAIN, "", "")) in
  let endpoint = 
    let module Config = (val config : Netsys_crypto_types.TLS_CONFIG) in
    let module P = Config.TLS in
    let ep =
      match resume with
        | None ->
             P.create_endpoint ~role ~recv ~send ~peer_name Config.config
        | Some data ->
             if role <> `Client then 
               failwith
                 "Netchannels.tls_layer: can only resume clients";
             P.resume_client ~recv ~send ~peer_name Config.config data in
    let module Endpoint = struct
      module TLS = P
      let endpoint = ep
    end in
    (module Endpoint : Netsys_crypto_types.TLS_ENDPOINT) in
  ( object(self)
      val mutable in_closed = false
      val mutable out_closed = false
      val mutable pos_in = start_pos_in
      val mutable pos_out = start_pos_out

      method input buf pos len = 
        if in_closed then raise Netchannels.Closed_channel;
        try
          if len=0 then raise Sys_blocked_io;
          let n = Netsys_tls.recv endpoint buf pos len in
          pos_in <- pos_in + n;
          if n=0 then raise End_of_file else n
        with
	  | Sys_blocked_io -> 0
          | Netsys_types.EAGAIN_RD -> 0
          | Netsys_types.EAGAIN_WR -> 0
          | Unix.Unix_error(Unix.EINTR,_,_) -> 0

      method close_in () =
        if not in_closed then (
          in_closed <- true;
          if out_closed then (
            Netsys_tls.shutdown endpoint Unix.SHUTDOWN_ALL;
            wr # close_out();
            rd # close_in();
          )
        )

      method pos_in = pos_in

      method output buf pos len =
        if out_closed then raise Netchannels.Closed_channel;
        try
          if len=0 then raise Sys_blocked_io;
          let n = Netsys_tls.send endpoint buf pos len in
          pos_out <- pos_out + n;
          n
        with
	  | Sys_blocked_io -> 0
          | Netsys_types.EAGAIN_RD -> 0
          | Netsys_types.EAGAIN_WR -> 0
          | Unix.Unix_error(Unix.EINTR,_,_) -> 0
         
      method flush () =
        if out_closed then raise Netchannels.Closed_channel;
        Netsys_tls.handshake endpoint

      method close_out() =
        if not out_closed then (
          out_closed <- true;
          if in_closed then (
            Netsys_tls.shutdown endpoint Unix.SHUTDOWN_ALL;
            wr # close_out();
            rd # close_in();            
          )
          else
            Netsys_tls.shutdown endpoint Unix.SHUTDOWN_SEND
        )

      method pos_out = pos_out

      method tls_endpoint = endpoint
    end
  )


class tls_endpoint ?(start_pos_in=0) ?(start_pos_out=0) ?resume 
                   ~role ~peer_name fd config =
  let endpoint = 
    Netsys_tls.create_file_endpoint
      ?resume ~role ~rd:fd ~wr:fd ~peer_name config in
  let fd_style = `TLS endpoint in
  ( object (self)
      inherit Netchannels.socket_descr ~fd_style fd as super
  
      method flush() =
        Netsys_tls.handshake (Netsys_tls.endpoint endpoint);
        super # flush()


      method tls_endpoint = (Netsys_tls.endpoint endpoint)
    end
  )



(*************** SYMM CRYPTO ************)


let process_out proc ctx ch =
  let buf, free_buf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let out_buf, free_out_buf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let str_buf =
    Bytes.create (Bigarray.Array1.dim out_buf) in
  let buf_pos = ref 0 in
  let buf_len = Bigarray.Array1.dim buf in
  let closed = ref false in
  let pos_out = ref 0 in
  ( object(self)
      inherit Netchannels.augment_raw_out_channel

      method output s pos len =
        if !closed then raise Netchannels.Closed_channel;
        let n = min len (buf_len - !buf_pos) in
        Netsys_mem.blit_bytes_to_memory s pos buf !buf_pos n;
        buf_pos := !buf_pos + n;
        if !buf_pos = buf_len then
          self#flush();
        pos_out := !pos_out + n;
        n

      method flush() =
        if !closed then raise Netchannels.Closed_channel;
        if !buf_pos > 0 then (
          let buf1 = Bigarray.Array1.sub buf 0 !buf_pos in
          let consumed, generated = proc ~last:false buf1 out_buf in
          Netsys_mem.blit_memory_to_bytes out_buf 0 str_buf 0 generated;
          ch # really_output str_buf 0 generated;
          let remaining = buf_len - consumed in
          if remaining > 0 then
            Bigarray.Array1.blit
              (Bigarray.Array1.sub buf consumed remaining)
              (Bigarray.Array1.sub buf 0 remaining);
          buf_pos := remaining;
        )

      method private final_flush() =
        (* tricky: call [proc ~last:true] at least once. Call it again if there
           is not enough space in out_buf (the encrypted msg can get longer), 
           which is indicated by not consuming all data
         *)
        if !closed then raise Netchannels.Closed_channel;
        while !buf_pos >= 0 do
          let buf_sub = Bigarray.Array1.sub buf 0 !buf_pos in
          let consumed, generated = proc ~last:true buf_sub out_buf in
          Netsys_mem.blit_memory_to_bytes out_buf 0 str_buf 0 generated;
          ch # really_output str_buf 0 generated;
          let remaining = !buf_pos - consumed in
          if remaining > 0 then
            Bigarray.Array1.blit
              (Bigarray.Array1.sub buf consumed remaining)
              (Bigarray.Array1.sub buf 0 remaining);
          buf_pos := remaining;
          if !buf_pos = 0 then buf_pos := (-1)
        done;
        buf_pos := 0;
        ()

      method close_out() =
        if not !closed then (
          self # final_flush();
          closed := true;
          free_buf();
          free_out_buf();
          ch # close_out()
        )

      method pos_out = !pos_out

      method supports_aead = ctx # supports_aead
      method mac() = ctx # mac()
    end
  )


let encrypt_out ctx ch =
  let proc = ctx # encrypt in
  process_out proc ctx ch


let decrypt_out ctx ch =
  let proc = ctx # decrypt in
  process_out proc ctx ch


let process_in proc ctx ch =
  let buf, free_buf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let in_buf, free_in_buf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let str_buf =
    Bytes.create (Bigarray.Array1.dim in_buf) in
  let buf_pos = ref 0 in
  let buf_len = ref 0 in
  let in_buf_len = ref 0 in
  let closed = ref false in
  let eof = ref false in
  let pos_in = ref 0 in
  ( object(self)
      inherit Netchannels.augment_raw_in_channel

      method input s pos len =
        if !closed then raise Netchannels.Closed_channel;
        if !buf_pos = !buf_len && not !eof then (
          try
            let l = Bigarray.Array1.dim in_buf - !in_buf_len in
            let n = ch # input str_buf 0 l in
            Netsys_mem.blit_bytes_to_memory str_buf 0 in_buf !in_buf_len n;
            in_buf_len := !in_buf_len + n;
            let consumed, generated =
              proc
                ~last:false
                (Bigarray.Array1.sub in_buf 0 !in_buf_len)
                buf in
            buf_pos := 0;
            buf_len := generated;
            let remaining = !in_buf_len - consumed in
            if remaining > 0 then
              Bigarray.Array1.blit
                (Bigarray.Array1.sub in_buf consumed remaining)
                (Bigarray.Array1.sub in_buf 0 remaining);
            in_buf_len := remaining;
          with
            | End_of_file ->
                eof := true;
                buf_pos := 0;
                buf_len := 0;
                while !in_buf_len >= 0 do
                  let consumed, generated =
                    proc
                      ~last:true
                      (Bigarray.Array1.sub in_buf 0 !in_buf_len)
                      buf in
                  buf_len := generated;
                  in_buf_len := !in_buf_len - consumed;
                  if !in_buf_len = 0 then in_buf_len := (-1)
                done;
                in_buf_len := 0;
        );
        let n = min len (!buf_len - !buf_pos) in
        if !eof && n=0 && len>0 then raise End_of_file;
        Netsys_mem.blit_memory_to_bytes buf !buf_pos s pos n;
        buf_pos := !buf_pos + n;
        pos_in := !pos_in + n;
        n

      method close_in() =
        if not !closed then (
          closed := true;
          free_buf();
          free_in_buf();
          ch # close_in()
        )

      method pos_in = !pos_in
      method supports_aead = ctx # supports_aead
      method mac() = ctx # mac()
    end
  )


let encrypt_in ctx ch =
  let proc = ctx # encrypt in
  process_in proc ctx ch


let decrypt_in ctx ch =
  let proc = ctx # decrypt in
  process_in proc ctx ch
