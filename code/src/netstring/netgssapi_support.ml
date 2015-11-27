(* $Id$ *)

open Printf

(* Encodings *)

let encode_subidentifier buf n =
  (* See 8.19 of ITU.T X.690 *)
  let rec encode n =
    if n < 128 then
      [ n ]
    else
      (n land 127) :: encode (n lsr 7) in
  if n < 0 then failwith "Netgssapi_support.encode_subidentifier";
  let l = List.rev(encode n) in
  let len = List.length l in
  let l =
    List.mapi
      (fun i k ->
         if i < len-1 then Char.chr(k lor 128) else Char.chr k
      )
      l in
  List.iter (Buffer.add_char buf) l

let decode_subidentifier s cursor =
  let n = ref 0 in
  let s_len = String.length s in
  while !cursor < s_len && s.[ !cursor ] >= '\x80' do
    let c = Char.code (s.[ !cursor ]) - 128 in
    n := (!n lsl 7) lor c;
    incr cursor
  done;
  if !cursor < s_len then (
    let c = Char.code (s.[ !cursor ]) in
    n := (!n lsl 7) lor c;
    incr cursor;
    !n
  )
  else failwith "Netgssapi_support.decode_subidentifier"

let encode_definite_length buf n =
  (* See 8.1.3 of ITU-T X.690 *)
  let rec encode n =
    if n < 256 then
      [ n ]
    else
      (n land 255) :: encode (n lsr 8) in
  if n < 128 then (
    Buffer.add_char buf (Char.chr n)
  ) else (
    let l = List.map Char.chr (List.rev(encode n)) in
    Buffer.add_char buf (Char.chr (List.length l + 128));
    List.iter (Buffer.add_char buf) l
  )

let decode_definite_length s cursor =
  let s_len = String.length s in
  if !cursor < s_len then (
    let c = s.[ !cursor ] in
    incr cursor;
    if c < '\x80' then (
      Char.code c
    )
    else (
      let p = Char.code c - 128 in
      let n = ref 0 in
      for q = 1 to p do
	if !cursor < s_len then (
	  let c = s.[ !cursor ] in
	  incr cursor;
	  n := (!n lsl 8) lor Char.code c;
	)
	else failwith "Netgssapi_support.decode_definite_length"
      done;
      !n
    )
  )
  else failwith "Netgssapi_support.decode_definite_length"

let oid_to_der_value oid =
  match Array.to_list oid with
    | [] ->
	failwith "Netgssapi_support.oid_to_der: empty OID"
    | [ _ ] ->
	failwith "Netgssapi_support.oid_to_der: invalid OID"
    | top :: second :: subids ->
	if top < 0 || top > 5 then  (* actually only 0..2 possible *)
	  failwith "Netgssapi_support.oid_to_der: invalid OID";
	if second < 0 || second > 39 then
	  failwith "Netgssapi_support.oid_to_der: invalid OID";
	let subids_buf = Buffer.create 50 in
	List.iter (encode_subidentifier subids_buf) subids;
	let buf = Buffer.create 50 in
	Buffer.add_char buf (Char.chr (top * 40 + second));
	Buffer.add_buffer buf subids_buf;
	Buffer.contents buf


let oid_to_der oid =
  let buf = Buffer.create 50 in
  let s = oid_to_der_value oid in
  Buffer.add_char buf '\x06';
  encode_definite_length buf (String.length s);
  Buffer.add_string buf s;
  Buffer.contents buf


let der_value_to_oid der cursor oid_len =
  try
    let lim = !cursor + oid_len in
    let c = Char.code der.[ !cursor ] in
    incr cursor;
    let top = c / 40 in
    let second = c mod 40 in
    let oid = ref [ second; top ] in
    while !cursor < lim do
      let subid = decode_subidentifier der cursor in
      oid := subid :: !oid;
    done;
    if !cursor <> lim then raise Not_found;
    Array.of_list (List.rev !oid)
  with
    | _ -> failwith "Netgssapi_support.der_value_to_oid"


let der_to_oid der cursor =
  try
    let der_len = String.length der in
    if !cursor >= der_len then raise Not_found;
    let c = der.[ !cursor ] in
    incr cursor;
    if c <> '\x06' then raise Not_found;
    let oid_len = decode_definite_length der cursor in
    let lim = !cursor + oid_len in
    if lim > der_len then raise Not_found;
    if oid_len = 0 then raise Not_found;
    der_value_to_oid der cursor oid_len
  with
    | _ -> failwith "Netgssapi_support.der_to_oid"


let wire_encode_token oid token =
  try
    let buf = Buffer.create (50 + String.length token) in
    Buffer.add_char buf '\x60';
    let oid_as_der = oid_to_der oid in
    let len = String.length oid_as_der + String.length token in
    encode_definite_length buf len;
    Buffer.add_string buf oid_as_der;
    Buffer.add_string buf token;
    Buffer.contents buf
  with
    | _ -> failwith "Netgssapi_support.wire_encode_token"

let wire_decode_token s cursor =
  try
    let s_len = String.length s in
    if !cursor > s_len then raise Not_found;
    let c = s.[ !cursor ] in
    incr cursor;
    if c <> '\x60' then raise Not_found;
    let len = decode_definite_length s cursor in
    let lim = !cursor + len in
    if lim > s_len then raise Not_found;
    let oid = der_to_oid s cursor in
    if !cursor > lim then raise Not_found;
    let token = String.sub s !cursor (lim - !cursor) in
    cursor := lim;
    (oid, token)
  with 
    | _ -> failwith "Netgsspi.wire_decode_token"


let encode_exported_name mech_oid name =
  let buf = Buffer.create (50 + String.length name) in
  Buffer.add_string buf "\x04\x01";
  let mech_oid_der = oid_to_der mech_oid in
  let mech_oid_len = String.length mech_oid_der in
  if mech_oid_len > 65535 then 
    failwith "Netgssapi_support.encode_exported_name: OID too long";
  Buffer.add_char buf (Char.chr (mech_oid_len / 256));
  Buffer.add_char buf (Char.chr (mech_oid_len mod 256));
  Buffer.add_string buf mech_oid_der;
  let name_len = String.length name in
  let n3 = (name_len lsr 24) land 0xff in
  let n2 = (name_len lsr 16) land 0xff in
  let n1 = (name_len lsr 8) land 0xff in
  let n0 = name_len land 0xff in
  Buffer.add_char buf (Char.chr n3);
  Buffer.add_char buf (Char.chr n2);
  Buffer.add_char buf (Char.chr n1);
  Buffer.add_char buf (Char.chr n0);
  Buffer.add_string buf name;
  Buffer.contents buf


let decode_exported_name s cursor =
  try
    let s_len = String.length s in
    if !cursor + 4 > s_len then raise Not_found;
    let c0 = s.[ !cursor ] in
    incr cursor;
    let c1 = s.[ !cursor ] in
    incr cursor;
    let c2 = s.[ !cursor ] in
    incr cursor;
    let c3 = s.[ !cursor ] in
    incr cursor;
    if c0 <> '\x04' || c1 <> '\x01' then raise Not_found;
    let mech_oid_len =  (Char.code c2 lsl 8) + Char.code c3 in
    let mech_start = !cursor in
    if mech_start + mech_oid_len > s_len then raise Not_found;
    let mech_oid = der_to_oid s cursor in
    if !cursor <> mech_start + mech_oid_len then raise Not_found;
    if !cursor + 4 > s_len then raise Not_found;
    let n0 = Char.code s.[ !cursor ] in
    incr cursor;
    let n1 = Char.code s.[ !cursor ] in
    incr cursor;
    let n2 = Char.code s.[ !cursor ] in
    incr cursor;
    let n3 = Char.code s.[ !cursor ] in
    incr cursor;
    let name_len = (n0 lsl 24) lor (n1 lsl 16) lor (n2 lsl 8) lor (n3) in
    if !cursor + name_len > s_len then raise Not_found;
    let name = String.sub s !cursor name_len in
    cursor := !cursor + name_len;
    (mech_oid, name)
  with
    | _ -> failwith "Netgssapi_support.decode_exported_name"


let comma_equals_re = Netstring_str.regexp "[,=]"

let rev_comma_equals_re = Netstring_str.regexp "\\(=2C\\|=3D\\|=\\|,\\)"


let gs2_encode_saslname s =
  ( try
      Netconversion.verify `Enc_utf8 s;
      if String.contains s '\000' then raise Not_found;
    with _ -> failwith "gs2_encode_saslname"
  );
  Netstring_str.global_substitute
    comma_equals_re
    (fun r s ->
       match Netstring_str.matched_string r s with
	 | "," -> "=2C"
	 | "=" -> "=3D"
	 | _ -> assert false
    )
    s

let gs2_decode_saslname s =
  let s' =
    Netstring_str.global_substitute
      rev_comma_equals_re
      (fun r s ->
	 match Netstring_str.matched_string r s with
	   | "=2C" -> ","
	   | "=3D" -> "="
	   | "=" | "," -> failwith "gs2_decode_saslname"
	   | _ -> assert false
      )
      s in
  ( try
      Netconversion.verify `Enc_utf8 s';
      if String.contains s' '\000' then raise Not_found;
    with _ -> failwith "gs2_decode_saslname"
  );
  s'


let encode_seq_nr x =
  let n7 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 56)
                           0xffL) in
  let n6 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 48)
                           0xffL) in
  let n5 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 40)
                           0xffL) in
  let n4 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 32)
                           0xffL) in
  let n3 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 24)
                           0xffL) in
  let n2 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 16)
                           0xffL) in
  let n1 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 8)
                           0xffL) in
  let n0 = Int64.to_int (Int64.logand x 0xffL) in
  let s = Bytes.create 8 in
  Bytes.set s 0 (Char.chr n7);
  Bytes.set s 1 (Char.chr n6);
  Bytes.set s 2 (Char.chr n5);
  Bytes.set s 3 (Char.chr n4);
  Bytes.set s 4 (Char.chr n3);
  Bytes.set s 5 (Char.chr n2);
  Bytes.set s 6 (Char.chr n1);
  Bytes.set s 7 (Char.chr n0);
  Bytes.unsafe_to_string s


let decode_seq_nr s =
  assert(String.length s = 8);
  let n7 = Int64.of_int (Char.code s.[0]) in
  let n6 = Int64.of_int (Char.code s.[1]) in
  let n5 = Int64.of_int (Char.code s.[2]) in
  let n4 = Int64.of_int (Char.code s.[3]) in
  let n3 = Int64.of_int (Char.code s.[4]) in
  let n2 = Int64.of_int (Char.code s.[5]) in
  let n1 = Int64.of_int (Char.code s.[6]) in
  let n0 = Int64.of_int (Char.code s.[7]) in
  Int64.logor
    (Int64.shift_left n7 56)
    (Int64.logor
       (Int64.shift_left n6 48)
       (Int64.logor
          (Int64.shift_left n5 40)
          (Int64.logor
             (Int64.shift_left n4 32)
             (Int64.logor
                (Int64.shift_left n3 24)
                (Int64.logor
                   (Int64.shift_left n2 16)
                   (Int64.logor
                      (Int64.shift_left n1 8)
                      n0))))))


let parse_kerberos_name s =
  (* http://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_parse_name.html *)
  let l = String.length s in
  let rec parse_nc prev_nc buf k =
    if k >= l then
      (prev_nc @ [Buffer.contents buf], None)
    else
      match s.[k] with
        | '/' ->
            parse_nc (prev_nc @ [Buffer.contents buf]) (Buffer.create 20) (k+1)
        | '@' ->
            let realm = String.sub s (k+1) (l-k-1) in
            (prev_nc @ [Buffer.contents buf], Some realm)
        | '\\' ->
            if k+1 >= l then failwith "parse_kerberos_name";
            ( match s.[k+1] with
                | '\\' -> Buffer.add_char buf '\\'
                | '/' -> Buffer.add_char buf '/'
                | '@' -> Buffer.add_char buf '@'
                | 'n' -> Buffer.add_char buf '\n'
                | 't' -> Buffer.add_char buf '\t'
                | 'b' -> Buffer.add_char buf '\b'
                | '0' -> Buffer.add_char buf '\000'
                | _ ->  failwith "parse_kerberos_name"
            );
            parse_nc prev_nc buf (k+2)
        | c ->
            Buffer.add_char buf c;
            parse_nc prev_nc buf (k+1) in
  parse_nc [] (Buffer.create 20) 0


let create_mic_token ~sent_by_acceptor ~acceptor_subkey ~sequence_number
                     ~get_mic ~message =
  let header =
    sprintf
      "\x04\x04%c\xff\xff\xff\xff\xff%s"
      (Char.chr ( (if sent_by_acceptor then 1 else 0) lor
		    (if acceptor_subkey then 4 else 0) ) )
      (encode_seq_nr sequence_number) in
  let mic =
    get_mic (message @ [Netxdr_mstring.string_to_mstring header] ) in
  header ^ mic

    
let parse_mic_token_header s =
  try
    if String.length s < 16 then raise Not_found;
    if s.[0] <> '\x04' || s.[1] <> '\x04' then raise Not_found;
    if String.sub s 3 5 <> "\xff\xff\xff\xff\xff" then raise Not_found;
    let flags = Char.code s.[2] in
    if flags land 7 <> flags then raise Not_found;
    let sent_by_acceptor = (flags land 1) <> 0 in
    let acceptor_subkey = (flags land 4) <> 0 in
    let sequence_number = decode_seq_nr (String.sub s 8 8) in
    (sent_by_acceptor, acceptor_subkey, sequence_number)
  with Not_found ->    failwith "Netgssapi_support.parse_mic_token_header"


let verify_mic_token ~get_mic ~message ~token =
  try
    ignore(parse_mic_token_header token);
    let header = String.sub token 0 16 in
    let mic = get_mic (message @ [Netxdr_mstring.string_to_mstring header]) in
    mic = (String.sub token 16 (String.length token - 16))
  with
    | _ -> false


let create_wrap_token_conf ~sent_by_acceptor ~acceptor_subkey
                           ~sequence_number ~get_ec ~encrypt_and_sign 
			   ~message =
  let ec = get_ec (Netxdr_mstring.length_mstrings message + 16) in
  let header =
    sprintf
      "\x05\x04%c\xff%c%c\000\000%s"
      (Char.chr ( (if sent_by_acceptor then 1 else 0) lor
		    (if acceptor_subkey then 4 else 0) lor 2 ) )
      (Char.chr ((ec lsr 8) land 0xff))
      (Char.chr (ec land 0xff))
      (encode_seq_nr sequence_number) in
  let filler =
    String.make ec '\000' in
  let encrypted =
    encrypt_and_sign (message @ 
			[ Netxdr_mstring.string_to_mstring
			    (filler ^ header) 
			]
		     ) in
  Netxdr_mstring.string_to_mstring header :: encrypted


let parse_wrap_token_header m =
  try
    let l = Netxdr_mstring.length_mstrings m in
    if l < 16 then raise Not_found;
    let s = Netxdr_mstring.prefix_mstrings m 16 in
    if s.[0] <> '\x05' || s.[1] <> '\x04' then raise Not_found;
    if s.[3] <> '\xff' then raise Not_found;
    let flags = Char.code s.[2] in
    if flags land 7 <> flags then raise Not_found;
    let sent_by_acceptor = (flags land 1) <> 0 in
    let sealed = (flags land 2) <> 0 in
    let acceptor_subkey = (flags land 4) <> 0 in
    let sequence_number = decode_seq_nr (String.sub s 8 8) in
    (sent_by_acceptor, sealed, acceptor_subkey, sequence_number)
  with Not_found -> failwith "Netgssapi_support.parse_wrap_token_header"


let unwrap_wrap_token_conf ~decrypt_and_verify ~token =
  let (_, sealed, _, _) = parse_wrap_token_header token in
  if not sealed then
    failwith "Netgssapi_support.unwrap_wrap_token_conf: not sealed";
  let s = Netxdr_mstring.prefix_mstrings token 16 in
  let ec = ((Char.code s.[4]) lsl 8) lor (Char.code s.[5]) in
  let rrc = ((Char.code s.[6]) lsl 8) lor (Char.code s.[7]) in
  let l_decrypt = Netxdr_mstring.length_mstrings token - 16 in
  let rrc_eff = rrc mod l_decrypt in
  let u =
    if rrc = 0 then
      Netxdr_mstring.shared_sub_mstrings token 16 l_decrypt
    else (
      Netxdr_mstring.shared_sub_mstrings token (rrc_eff+16) (l_decrypt - rrc_eff)
      @ Netxdr_mstring.shared_sub_mstrings token 16 rrc_eff
    ) in
(*
  let u = String.create l_decrypt in
  String.blit token (rrc_eff+16) u 0 (l_decrypt - rrc_eff);
  String.blit token 16 u (l_decrypt - rrc_eff) rrc_eff;
 *)
  let decrypted = 
    try decrypt_and_verify u
    with _ ->
      failwith "Netgssapi_support.unwrap_wrap_token_conf: cannot decrypt" in
  let l_decrypted = Netxdr_mstring.length_mstrings decrypted in
  if l_decrypted < ec + 16 then
    failwith "Netgssapi_support.unwrap_wrap_token_conf: bad EC";
  let h1 = Netxdr_mstring.prefix_mstrings token 16 in
  let h2 = 
    Netxdr_mstring.concat_mstrings
      (Netxdr_mstring.shared_sub_mstrings decrypted (l_decrypted - 16) 16) in
  if h1 <> h2 then
    failwith "Netgssapi_support.unwrap_wrap_token_conf: header integrity mismatch";
  Netxdr_mstring.shared_sub_mstrings decrypted 0 (l_decrypted - ec - 16)
