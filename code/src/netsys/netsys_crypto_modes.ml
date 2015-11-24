(* $Id$ *)

open Printf

module StrPair = struct
  type t = string * string
  let compare : t -> t -> int =
    fun (n1,m1) (n2,m2) ->
      let p = String.compare n1 n2 in
      if p <> 0 then p else String.compare m1 m2
end

module StrPairMap = Map.Make(StrPair)

module Symmetric_cipher = struct
  type sc_ctx =
      { set_iv : string -> unit;
        set_header : string -> unit;
        encrypt : Netsys_types.memory -> Netsys_types.memory -> unit;
        decrypt : Netsys_types.memory -> Netsys_types.memory -> bool;
        mac : unit -> string;
      }
      
  type sc =
      { name : string;
        mode : string;
        key_lengths : (int * int) list;
        iv_lengths : (int * int) list;
        block_constraint : int;
        supports_aead : bool;
        create : string -> sc_ctx;
      }

  module Extract(SC : Netsys_crypto_types.SYMMETRIC_CRYPTO) = struct
    let extract_one sc =
      let create key =
        let ctx = SC.create sc key in
        { set_iv = SC.set_iv ctx;
          set_header = SC.set_header ctx;
          encrypt = SC.encrypt ctx;
          decrypt = SC.decrypt ctx;
          mac = (fun () -> SC.mac ctx)
        } in
      { name = SC.name sc;
        mode = SC.mode sc;
        key_lengths = SC.key_lengths sc;
        iv_lengths = SC.iv_lengths sc;
        block_constraint = SC.block_constraint sc;
        supports_aead = SC.supports_aead sc;
        create;
      }
  end

  let extract sc_mod (name,mode) =
    let module SC = (val sc_mod : Netsys_crypto_types.SYMMETRIC_CRYPTO) in
    let module X = Extract(SC) in
    let sc = SC.find (name,mode) in
    X.extract_one sc

  let extract_all sc_mod =
    let module SC = (val sc_mod : Netsys_crypto_types.SYMMETRIC_CRYPTO) in
    let module X = Extract(SC) in
    List.map X.extract_one SC.ciphers

  let no_mac _ =
    failwith "mac: not supported by this cipher"

  let mem_copy m =
    let l = Bigarray.Array1.dim m in
    let c = Bigarray.Array1.create Bigarray.char Bigarray.c_layout l in
    Bigarray.Array1.blit m c;
    c
      
  let mem_xor out in1 in2 =
    let l_out = Bigarray.Array1.dim out in
    let l_in1 = Bigarray.Array1.dim in1 in
    let l_in2 = Bigarray.Array1.dim in2 in
    let l = min (min l_out l_in1) l_in2 in
    for k = 0 to l - 1 do
      let x1 = Char.code (Bigarray.Array1.unsafe_get in1 k) in
      let x2 = Char.code (Bigarray.Array1.unsafe_get in2 k) in
      let x = x1 lxor x2 in
      Bigarray.Array1.unsafe_set out k (Char.chr x)
    done
      
  let mem_incr m =
    (* Increment the value in m, interpreted in network byte order *)
    let l = Bigarray.Array1.dim m in
    if l > 0 then (
      let x0 = Char.code(Bigarray.Array1.unsafe_get m (l-1)) in
      let x0_plus = (x0 + 1) land 255 in
      Bigarray.Array1.unsafe_set m (l-1) (Char.chr x0_plus);
      if x0_plus = 0 then (
        for j = l-2 downto 0 do
          let xj = Char.code(Bigarray.Array1.unsafe_get m j) in
          let xj_plus = (xj + 1) land 255 in
          Bigarray.Array1.unsafe_set m j (Char.chr xj_plus);
        done
      )
    )
                    
  let cbc_of_ecb c =
    if c.mode <> "ECB" then raise Not_found;
    let bs = c.block_constraint in
    let create key =
      let orig_ctx = c.create key in
      let xorbuf =
        Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
      let ivbuf =
        ref (Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs) in
      let set_iv s =
        if String.length s <> bs then
          invalid_arg "set_iv: invalid length";
        Netsys_mem.blit_string_to_memory s 0 !ivbuf 0 bs in
      let set_header _ = () in
      let encrypt inbuf outbuf =
        let lbuf = Bigarray.Array1.dim inbuf in
        if lbuf <> Bigarray.Array1.dim outbuf then
          invalid_arg "encrypt: output buffer must have same size \
                       as input buffer";
        if lbuf mod bs <> 0 then
          invalid_arg (sprintf "encrypt: buffers must be multiples \
                                of %d" bs);
        let k = ref 0 in
        while !k < lbuf do
          let inblock = Bigarray.Array1.sub inbuf !k bs in
          let outblock = Bigarray.Array1.sub outbuf !k bs in
          mem_xor xorbuf !ivbuf inblock;
          orig_ctx.encrypt xorbuf outblock;
          ivbuf := outblock;
          k := !k + bs;
        done;
        Bigarray.Array1.fill xorbuf 'X';
        ivbuf := mem_copy !ivbuf in
      let decrypt inbuf outbuf =
        let ok = orig_ctx.decrypt inbuf outbuf in
        ok && (
          let lbuf = Bigarray.Array1.dim inbuf in
          let k = ref 0 in
          while !k < lbuf do
            let inblock = Bigarray.Array1.sub inbuf !k bs in
            let outblock = Bigarray.Array1.sub outbuf !k bs in
            mem_xor outblock outblock !ivbuf;
            ivbuf := inblock;
            k := !k + bs
          done;
          Bigarray.Array1.fill xorbuf 'X';
          ivbuf := mem_copy !ivbuf;
          true
        ) in
      { set_iv;
        set_header;
        encrypt;
        decrypt;
        mac = no_mac;
      } in
    { name = c.name;
      mode = "CBC";
      key_lengths = c.key_lengths;
      iv_lengths = [ bs, bs ];
      block_constraint = bs;
      supports_aead = false;
      create;
    }

(*
  (* Commented out because only accelerated encryption would help for the
     other modes
   *)
  let accel_ecb_from_cbc c_ecb c_cbc =
    (* ECB decryption can be easily reduced to CBC decryption, and if the
       latter is accelerated, ECB decryption will also be accelerated. There
       is no way to do this for encryption, though.
     *)
    if c_ecb.mode <> "ECB" then raise Not_found;
    if c_cbc.mode <> "CBC" then raise Not_found;
    let bs = c_ecb.block_constraint in
    let create key =
      let orig_ctx_ecb_lz = lazy (c_ecb.create key) in
      let set_iv s =
        if s <> "" then
          invalid_arg "set_iv: empty string expected" in
      let set_header s =
        () in
      let encrypt inbuf outbuf =
        let ctx = Lazy.force orig_ctx_ecb_lz in
        ctx.encrypt inbuf outbuf in
      let decrypt inbuf outbuf =
        let ctx = c_cbc.create key in
        ctx.set_iv (String.make bs "\000");
        let ok = c_cbc.decrypt inbuf outbuf in
        ok && (
          let lbuf = Bigarray.Array1.dim inbuf in
          mem_xor
            (Bigarray.Array1.sub outbuf bs (lbuf-bs))
            (Bigarray.Array1.sub outbuf bs (lbuf-bs))
            (Bigarray.Array1.sub inbuf 0 (lbuf-bs));
          true
        ) in
      { set_iv;
        set_header;
        encrypt;
        decrypt;
        mac = no_mac;
      } in
    { c_cbc with
      create;
    }
 *)

  let ofb_of_ecb c =
    if c.mode <> "ECB" then raise Not_found;
    let bs = c.block_constraint in
    let create key =
      let orig_ctx = c.create key in
      let xorbuf =
        Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
      let ivbuf =
        ref (Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs) in
      let set_iv s =
        if String.length s <> bs then
          invalid_arg "set_iv: invalid length";
        Netsys_mem.blit_string_to_memory s 0 !ivbuf 0 bs in
      let set_header _ = () in
      let encrypt_decrypt name inbuf outbuf =
        let lbuf = Bigarray.Array1.dim inbuf in
        if lbuf <> Bigarray.Array1.dim outbuf then
          invalid_arg (name ^ ": output buffer must have same size \
                               as input buffer");
        if lbuf mod bs <> 0 then
          invalid_arg (sprintf "%s: buffers must be multiples \
                                of %d" name bs);
        let k = ref 0 in
        while !k < lbuf do
          let inblock = Bigarray.Array1.sub inbuf !k bs in
          let outblock = Bigarray.Array1.sub outbuf !k bs in
          orig_ctx.encrypt !ivbuf xorbuf;
          mem_xor outblock inblock xorbuf;
          ivbuf := xorbuf;
          k := !k + bs;
        done;
        ivbuf := mem_copy !ivbuf;
        Bigarray.Array1.fill xorbuf 'X' in
      let encrypt =
        encrypt_decrypt "encrypt" in
      let decrypt inbuf outbuf =
        encrypt_decrypt "decrypt" inbuf outbuf;
        true in
      { set_iv;
        set_header;
        encrypt;
        decrypt;
        mac = no_mac;
      } in
    { name = c.name;
      mode = "OFB";
      key_lengths = c.key_lengths;
      iv_lengths = [ bs, bs ];
      block_constraint = bs;
      supports_aead = false;
      create;
    }

  let ctr_of_ecb c =
    (* In order to support parallelization for c (which is not done yet),
       we proceed in chunks of 64 Kbytes. This way the encryption function
       of c is called with enough data that speedups are imaginable.
     *)
    if c.mode <> "ECB" then raise Not_found;
    let bs = c.block_constraint in
    let create key =
      let orig_ctx = c.create key in
      let chunksize = Netsys_mem.default_block_size in
      let noncebuf =
        Netsys_mem.pool_alloc_memory Netsys_mem.default_pool in
      let xorbuf =
        Netsys_mem.pool_alloc_memory Netsys_mem.default_pool in
      let ivbuf =
        Bigarray.Array1.create Bigarray.char Bigarray.c_layout bs in
      let ivuse = ref 0 in
      let set_iv s =
        if String.length s <> bs then
          invalid_arg "set_iv: invalid length";
        Netsys_mem.blit_string_to_memory s 0 ivbuf 0 bs;
        ivuse := 0 in
      let set_header _ = () in
      let encrypt_decrypt name inbuf outbuf =
        let lbuf = Bigarray.Array1.dim inbuf in
        if lbuf <> Bigarray.Array1.dim outbuf then
          invalid_arg (name ^ ": output buffer must have same size \
                               as input buffer");
        let k = ref 0 in
        while !k < lbuf do
          let j = ref 0 in
          let j_end = min chunksize (lbuf - !k) in 
          let j_end_full = j_end - j_end mod bs in
          if !ivuse > 0 then (
            (* partially used ivbuf from last invocation *)
            let n = min (bs - !ivuse) (j_end - !j) in
            Bigarray.Array1.blit 
              (Bigarray.Array1.sub ivbuf !ivuse n)
              (Bigarray.Array1.sub noncebuf !j n);
            ivuse := !ivuse + n;
            if !ivuse = bs then (
              ivuse := 0;
              mem_incr ivbuf;
            );
            j := n;
          );
          while !j < j_end_full do
            Bigarray.Array1.blit ivbuf (Bigarray.Array1.sub noncebuf !j bs);
            mem_incr ivbuf;
            j := !j + bs;
          done;
          if j_end_full < j_end then (
            (* partiall used ivbuf at the end *)
            ivuse := j_end - j_end_full;
            Bigarray.Array1.blit 
              (Bigarray.Array1.sub ivbuf 0 !ivuse)
              (Bigarray.Array1.sub noncebuf !j !ivuse);
          );
          let inchunk = Bigarray.Array1.sub inbuf !k j_end in
          let outchunk = Bigarray.Array1.sub outbuf !k j_end in
          orig_ctx.encrypt noncebuf xorbuf;
          mem_xor outchunk xorbuf inchunk;
          k := !k + chunksize;
        done;
        Bigarray.Array1.fill noncebuf 'X';
        Bigarray.Array1.fill xorbuf 'X';
        () in
      let encrypt =
        encrypt_decrypt "encrypt" in
      let decrypt inbuf outbuf =
        encrypt_decrypt "decrypt" inbuf outbuf;
        true in
      { set_iv;
        set_header;
        encrypt;
        decrypt;
        mac = no_mac;
      } in
    { name = c.name;
      mode = "CTR";
      key_lengths = c.key_lengths;
      iv_lengths = [ bs, bs ];
      block_constraint = 1;  (* no constraint anymore! *)
      supports_aead = false;
      create;
    }

end

module type CIPHERS = sig val ciphers : Symmetric_cipher.sc list end

module Bundle (L : CIPHERS) = struct
  open Symmetric_cipher
  type scipher = sc
  type scipher_ctx = sc_ctx
  let ciphers_m =
    List.fold_left
      (fun acc sc -> StrPairMap.add (sc.name,sc.mode) sc acc)
      StrPairMap.empty
      L.ciphers
  let ciphers =
    StrPairMap.fold (fun _ v acc -> v :: acc) ciphers_m []

  let find (name,mode) =
    StrPairMap.find (name,mode) ciphers_m
                    
  let name c = c.name
  let mode c = c.mode
  let key_lengths c = c.key_lengths
  let iv_lengths c = c.iv_lengths
  let block_constraint c = c.block_constraint
  let supports_aead c = c.supports_aead
  let create c = c.create
  let set_iv ctx = ctx.set_iv
  let set_header ctx = ctx.set_header
  let encrypt ctx = ctx.encrypt
  let decrypt ctx = ctx.decrypt
  let mac ctx = ctx.mac ()
end

module Add_modes (SC : Netsys_crypto_types.SYMMETRIC_CRYPTO) = struct
  open Symmetric_cipher
  module L = struct
    let exists name mode =
      try ignore(SC.find (name,mode)); true with Not_found -> false
    let ciphers =
      List.flatten
        (List.map
           (fun sc ->
              let name = sc.name in
              if sc.mode = "ECB" then (
                let cbc_l =
                  if exists name "CBC" then
                    []
                  else
                    [cbc_of_ecb sc] in
                let ofb_l =
                  if exists name "OFB" then
                    []
                  else
                    [ofb_of_ecb sc] in
                let ctr_l =
                  if exists name "CTR" then
                    []
                  else
                    [ctr_of_ecb sc] in
                [sc] @ cbc_l @ ofb_l @ ctr_l
              )
              else
                [sc]
           )
           (extract_all (module SC))
        )
  end
               
  include Bundle(L)
end
