(* $Id$ *)

class type tls_channel = object
  inherit Netchannels.raw_io_channel
  method tls_endpoint : Netsys_crypto_types.tls_endpoint
end



(************************** TLS *****************************)

class tls_layer ?(start_pos_in=0) ?(start_pos_out=0) ?resume
                ~role ~rd ~wr ~peer_name config =
  let sbuf = String.create 65536 in
  let recv buf =
    try
      let buf_len = min (Bigarray.Array1.dim buf) (String.length sbuf) in
      let n = rd # input sbuf 0 buf_len in
      if n = 0 then raise(Unix.Unix_error(Unix.EAGAIN, "", ""));
      Netsys_mem.blit_string_to_memory sbuf 0 buf 0 n;
      n
    with
      | Sys_blocked_io ->  raise(Unix.Unix_error(Unix.EAGAIN, "", ""))
      | End_of_file -> 0 in
  let send buf size =
    try
      let send_len = min size (String.length sbuf) in
      Netsys_mem.blit_memory_to_string buf 0 sbuf 0 send_len;
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



