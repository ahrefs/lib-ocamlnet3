(* $Id$ *)

open Printf

type padding =
    [ `None
    | `Length
    | `_8000
    | `CTS
    ]

class type cipher_ctx =
object
  method block_constraint : int
  method supports_aead : bool
  method padding : padding
  method set_iv : string -> unit
  method set_header : string -> unit
  method encrypt : last:bool -> 
                   Netsys_types.memory -> Netsys_types.memory -> int * int
  method decrypt : last:bool -> 
                   Netsys_types.memory -> Netsys_types.memory -> int * int
  method encrypt_bytes : Bytes.t -> Bytes.t
  method encrypt_string : string -> string
  method decrypt_bytes : Bytes.t -> Bytes.t
  method decrypt_string : string -> string
  method mac : unit -> string
end


class type cipher =
object
  method name : string
  method mode : string
  method key_lengths : (int * int) list
  method iv_lengths : (int * int) list
  method block_constraint : int
  method supports_aead : bool
  method create : string -> padding -> cipher_ctx
end


let process_substring proc s pos len =
  let inbuf, free_inbuf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let outbuf, free_outbuf =
    Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
  let collect = ref [] in
  let k = ref pos in
  while !k < len do
    let n = min (len - !k) (Bigarray.Array1.dim inbuf) in
    Netsys_mem.blit_string_to_memory s !k inbuf 0 n;
    let inbuf1 = Bigarray.Array1.sub inbuf 0 n in
    let (n_in, n_out) = proc ~last:(n = len - !k) inbuf1 outbuf in
    if n_in = 0 then failwith "encryption/decryption: would loop";
    let u =
      Netsys_mem.string_of_memory (Bigarray.Array1.sub outbuf 0 n_out) in
    collect := u :: !collect;
    k := !k + n_in
  done;
  free_inbuf();
  free_outbuf();
  String.concat "" (List.rev !collect)


let process_string proc s =
  process_substring proc s 0 (String.length s)


let process_subbytes proc s pos len =
  Bytes.unsafe_of_string
    (process_substring
       proc (Bytes.unsafe_to_string s) pos len
    )

let process_bytes proc s =
  Bytes.unsafe_of_string
    (process_string
       proc (Bytes.unsafe_to_string s)
    )


module Cipher(Impl : Netsys_crypto_types.SYMMETRIC_CRYPTO) = struct
  let ctx_obj_no_padding c ctx : cipher_ctx =
    let bs = Impl.block_constraint c in
    object(self)
      method padding = `None
      method block_constraint = bs
      method supports_aead = Impl.supports_aead c
      method set_iv iv = Impl.set_iv ctx iv
      method set_header hdr = Impl.set_header ctx hdr
      method encrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l = min l_inbuf l_outbuf in
        let m = l mod bs in
        let n = if last then l else l - m in
        if n > 0 then
          Impl.encrypt 
            ctx
            (Bigarray.Array1.sub inbuf 0 n)
            (Bigarray.Array1.sub outbuf 0 n);
        (n,n)
      method decrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l = min l_inbuf l_outbuf in
        let m = l mod bs in
        let n = if last then l else l - m in
        if n > 0 then (
          let ok =
            Impl.decrypt 
              ctx
              (Bigarray.Array1.sub inbuf 0 n)
              (Bigarray.Array1.sub outbuf 0 n) in
          if not ok then failwith "decrypt";
        );
        (n,n)
      method encrypt_bytes s = process_bytes self#encrypt s
      method encrypt_string s = process_string self#encrypt s
      method decrypt_bytes s = process_bytes self#decrypt s
      method decrypt_string s = process_string self#decrypt s
      method mac() = Impl.mac ctx
    end


  let ctx_obj_simple_padding c ctx p : cipher_ctx =
    let bs = Impl.block_constraint c in
    let pad_e = Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
    let pad_d = Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
    let pad_d_set = ref false in
    object(self)
      method padding = (p :> padding)
      method block_constraint = bs
      method supports_aead = Impl.supports_aead c
      method set_iv iv = Impl.set_iv ctx iv
      method set_header hdr = Impl.set_header ctx hdr
      method encrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_inbuf1 = l_inbuf - l_inbuf mod bs in
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l_outbuf1 = l_outbuf - l_outbuf mod bs in
        let l_out_needed = if last then l_inbuf1 + bs else l_inbuf1 in
        let n1 = min l_inbuf1 l_outbuf1 in        (* whole blocks *)
        let n2 = min l_out_needed l_outbuf1 in    (* output size w/ padding *)
        let n3 = if n2>n1 then l_inbuf else n1 in (* input size w/ padding *)
        if n1 > 0 then
          Impl.encrypt 
            ctx
            (Bigarray.Array1.sub inbuf 0 n1)
            (Bigarray.Array1.sub outbuf 0 n1);
        if n2 > n1 then (
          let k1 = l_inbuf - l_inbuf1 in
          let k2 = bs - k1 in
          Bigarray.Array1.blit
            (Bigarray.Array1.sub inbuf l_inbuf1 k1)
            (Bigarray.Array1.sub pad_e 0 k1);
          ( match p with
              | `Length ->
                  Bigarray.Array1.fill
                    (Bigarray.Array1.sub pad_e k1 k2)
                    (Char.chr k2);
              | `_8000 ->
                  pad_e.{ k1 } <- '\x80';
                  Bigarray.Array1.fill
                    (Bigarray.Array1.sub pad_e (k1+1) (k2-1))
                    '\x00'
          );
          Impl.encrypt
            ctx
            pad_e
            (Bigarray.Array1.sub outbuf n1 bs)
        );
        (n3,n2)
      method decrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_inbuf1 = l_inbuf - l_inbuf mod bs in
        if last && (l_inbuf > l_inbuf1 || l_inbuf=0)  then failwith "decrypt";
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l_outbuf1 = l_outbuf - l_outbuf mod bs in
        let l_inbuf2 = l_inbuf1 - bs in
            (* w/o the last block, which could be the padding block *)
        let n1 = min l_inbuf2 l_outbuf1 in        (* whole blocks *)
        if n1 > 0 then (
          let ok =
            Impl.decrypt 
              ctx
              (Bigarray.Array1.sub inbuf 0 n1)
              (Bigarray.Array1.sub outbuf 0 n1) in
          if not ok then failwith "decrypt";
        );
        if last then (
          (* Ensure that we decrypt the padding block only once (AEAD) *)
          if not !pad_d_set then (
            let ok =
              Impl.decrypt
                ctx
                 (Bigarray.Array1.sub inbuf l_inbuf2 bs)
                 pad_d in
            if not ok then failwith "decrypt";
            pad_d_set := true;
          );
          let k1 =
            match p with
              | `Length ->
                  let k2 = Char.code pad_d.{ bs-1 } in
                  if k2 > bs then failwith "decrypt";
                  bs - k2
              | `_8000 ->
                  let j = ref (bs-1) in
                  while !j > 0 && pad_d.{ !j } = '\x00' do decr j done;
                  if pad_d.{ !j } <> '\x80' then failwith "decrypt";
                  !j in
          let l_out_needed = n1 + k1 in
          if l_outbuf > l_out_needed then (
            Bigarray.Array1.blit
              (Bigarray.Array1.sub pad_d 0 k1)
              (Bigarray.Array1.sub outbuf n1 k1);
            (l_inbuf, l_out_needed)
          )
          else
            (n1,n1)    (* do not process the padding block! *)
        )
        else
          (n1,n1)
      method encrypt_bytes s = process_bytes self#encrypt s
      method encrypt_string s = process_string self#encrypt s
      method decrypt_bytes s = process_bytes self#decrypt s
      method decrypt_string s = process_string self#decrypt s
      method mac() = Impl.mac ctx
    end


  let ctx_obj_cts c ctx key : cipher_ctx =
    let mode = Impl.mode c in
    if mode <> "ECB" && mode <> "CBC" then
      failwith "CTS padding is only defined for ECB and CBC modes";
    let bs = Impl.block_constraint c in
    let pad_e = Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
    let pad_d = Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
    object(self)
      method padding = `CTS
      method block_constraint = bs
      method supports_aead = Impl.supports_aead c
      method set_iv iv = Impl.set_iv ctx iv
      method set_header hdr = Impl.set_header ctx hdr
      method encrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_inbuf1 = l_inbuf - l_inbuf mod bs in
        let l_inbuf2 =  (* w/o the last two blocks *)
          if l_inbuf=l_inbuf1 then l_inbuf - 2*bs else l_inbuf1-bs in
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l_outbuf1 = l_outbuf - l_outbuf mod bs in
        let n1 = max (min l_inbuf2 l_outbuf1) 0 in        (* whole blocks *)
        if n1 > 0 then
          Impl.encrypt 
            ctx
            (Bigarray.Array1.sub inbuf 0 n1)
            (Bigarray.Array1.sub outbuf 0 n1);
        if last then (
          if l_inbuf <= bs then failwith "encrypt: message too short";
          let l_out_needed = l_inbuf in
          if l_outbuf > l_out_needed then (
            Impl.encrypt
              ctx
              (Bigarray.Array1.sub inbuf l_inbuf2 bs)
              pad_e;
            let m = l_inbuf - l_inbuf2 - bs in
            (* In CBC mode delete the second part of pad_e: *)
            if mode = "CBC" then
              Bigarray.Array1.fill
                (Bigarray.Array1.sub pad_e m (bs-m))
                '\000';
            Bigarray.Array1.blit
              (Bigarray.Array1.sub pad_e 0 m)
              (Bigarray.Array1.sub outbuf (n1+bs) m);
            Bigarray.Array1.blit
              (Bigarray.Array1.sub inbuf (l_inbuf2+bs) m)
              (Bigarray.Array1.sub pad_e 0 m);
            Impl.encrypt
              ctx
              pad_e
              (Bigarray.Array1.sub outbuf n1 bs);
            (l_inbuf, l_out_needed)
          )
          else (n1,n1)
        )
        else (n1,n1)
      method decrypt ~last inbuf outbuf =
        let l_inbuf = Bigarray.Array1.dim inbuf in
        let l_inbuf1 = l_inbuf - l_inbuf mod bs in
        let l_inbuf2 =  (* w/o the last two blocks *)
          if l_inbuf=l_inbuf1 then l_inbuf - 2*bs else l_inbuf1-bs in
        let l_outbuf = Bigarray.Array1.dim outbuf in
        let l_outbuf1 = l_outbuf - l_outbuf mod bs in
        let n1 = max (min l_inbuf2 l_outbuf1) 0 in        (* whole blocks *)
        if n1 > 0 then (
          let ok =
            Impl.decrypt 
              ctx
              (Bigarray.Array1.sub inbuf 0 n1)
              (Bigarray.Array1.sub outbuf 0 n1) in
          if not ok then failwith "decrypt";
        );
        if last then (
          if l_inbuf <= bs then failwith "decrypt";
          let l_out_needed = l_inbuf in
          if l_outbuf > l_out_needed then (
            let m = l_inbuf - l_inbuf2 - bs in
            if mode = "CBC" then (
              (* This is very different due to the mods in encryption *)
              let ctx_ecb = Impl.create c key in
              Impl.set_iv ctx_ecb (String.make bs '\000');
              let ok =
                Impl.decrypt
                  ctx_ecb
                  (Bigarray.Array1.sub inbuf n1 bs)
                  pad_d in
              if not ok then failwith "decrypt";
              Bigarray.Array1.blit
                (Bigarray.Array1.sub inbuf (l_inbuf2+bs) m)
                (Bigarray.Array1.sub pad_d 0 m);
              let ok =
                Impl.decrypt
                  ctx
                  pad_d
                  (Bigarray.Array1.sub outbuf n1 bs) in
              if not ok then failwith "decrypt";
              let ok =
                Impl.decrypt
                  ctx
                  (Bigarray.Array1.sub inbuf n1 bs)
                  pad_d in
              if not ok then failwith "decrypt";
              Bigarray.Array1.blit
                (Bigarray.Array1.sub pad_d 0 m)
                (Bigarray.Array1.sub outbuf (n1+bs) m);
            )            
            else (
              let ok =
                Impl.decrypt
                  ctx
                  (Bigarray.Array1.sub inbuf n1 bs)
                  pad_d in
              if not ok then failwith "decrypt";
              Bigarray.Array1.blit
                (Bigarray.Array1.sub pad_d 0 m)
                (Bigarray.Array1.sub outbuf (n1+bs) m);
              Bigarray.Array1.blit
                (Bigarray.Array1.sub inbuf (l_inbuf2+bs) m)
                (Bigarray.Array1.sub pad_d 0 m);
              let ok =
                Impl.decrypt
                  ctx
                  pad_d
                  (Bigarray.Array1.sub outbuf n1 bs) in
              if not ok then failwith "decrypt";
            );
            (l_inbuf, l_out_needed)
          )
          else (n1,n1)          
        )
        else (n1,n1)
      method encrypt_bytes s = process_bytes self#encrypt s
      method encrypt_string s = process_string self#encrypt s
      method decrypt_bytes s = process_bytes self#decrypt s
      method decrypt_string s = process_string self#decrypt s
      method mac() = Impl.mac ctx
    end


  let cipher_obj (c : Impl.scipher) : cipher =
    object
      method name = Impl.name c
      method mode = Impl.mode c
      method key_lengths = Impl.key_lengths c
      method iv_lengths = Impl.iv_lengths c
      method block_constraint = Impl.block_constraint c
      method supports_aead = Impl.supports_aead c
      method create key (p:padding) =
        let ctx = Impl.create c key in
        match p with
          | `None ->
              ctx_obj_no_padding c ctx
          | `Length ->
              ctx_obj_simple_padding c ctx `Length
          | `_8000 ->
              ctx_obj_simple_padding c ctx `_8000
          | `CTS ->
              ctx_obj_cts c ctx key
    end

  let list() =
    List.map cipher_obj Impl.ciphers

  let find (name,mode) =
    cipher_obj (Impl.find (name,mode))

end


let ciphers ?(impl = Netsys_crypto.current_symmetric_crypto()) () =
  let module I = (val impl : Netsys_crypto_types.SYMMETRIC_CRYPTO) in
  let module C = Cipher(I) in
  C.list()


let find ?(impl = Netsys_crypto.current_symmetric_crypto()) (name,mode) =
  let module I = (val impl : Netsys_crypto_types.SYMMETRIC_CRYPTO) in
  let module C = Cipher(I) in
  C.find (name,mode)
