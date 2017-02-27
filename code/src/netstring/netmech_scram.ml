(* $Id$ *)

(* Steps:

   client               <->               server
   ----------------------------------------------------------------------
   username, nonce       ->
                         <-               salt, i, nonce'
   clientproof, nonce'   ->
     (=algo(password, salt, i))
                         <-               serversignature
 *)

open Printf

type ptype = [ `GSSAPI | `SASL ]

type profile =
    { ptype : ptype;
      hash_function : Netsys_digests.iana_hash_fn;
      return_unknown_user : bool;
      iteration_count_limit : int;
    }

type credentials =
  [ `Salted_password of string * string * int
  | `Stored_creds of string * string * string * int
  ]

type cb = Netsys_sasl_types.cb

type gs2_header =
    { gs2_cb : cb;
      gs2_authzname : string option
    }

type client_first =  (* actually client_first_bare *)
    { c1_username : string;  (* "=xx" encoding not yet applied *)
      c1_gs2 : gs2_header;
      c1_nonce : string;     (* anything but comma *)
      c1_extensions : (string * string) list
    }

type server_first =
    { s1_nonce : string;     (* anything but comma *)
      s1_salt : string;      (* decoded *)
      s1_iteration_count : int;
      s1_extensions : (string * string) list
    }

type client_final =
    { cf_gs2 : gs2_header;
      cf_nonce : string;     (* anything but comma *)
      cf_extensions : (string * string) list;
      cf_proof : string option;   (* decoded *)
    }

type server_error =
    [ `Invalid_encoding
    | `Extensions_not_supported
    | `Invalid_proof
    | `Channel_bindings_dont_match
    | `Server_does_support_channel_binding
    | `Channel_binding_not_supported
    | `Unsupported_channel_binding_type
    | `Unknown_user
    | `Invalid_username_encoding
    | `No_resources
    | `Other_error
    | `Extension of string
    ]

type server_error_or_verifier =
    [ `Error of server_error
    | `Verifier of string
    ]

type server_final =
    { sf_error_or_verifier : server_error_or_verifier;
      sf_extensions : (string * string) list;
    }

type specific_keys =
    { kc : string;
      ke : string;
      ki : string
    }

type client_session =
    { cs_profile : profile;
      cs_state : [ `Start | `C1 | `S1 | `CF | `SF | 
                   `Restart of int | `CR of int | `SR of int |
                   `Connected | `Error of exn
                 ];
      cs_c1 : client_first option;
      cs_s1 : server_first option;
      cs_s1_raw : string;
      cs_cf : client_final option;
      cs_sf : server_final option;
      cs_salted_pw : string;
      cs_auth_message : string;
      cs_client_key : string option;
      cs_proto_key : string option;
      cs_username : string;
      cs_authzname : string;
      cs_password : string;
      cs_nonce : string option;
      cs_cb : cb;
    }


type server_session =
    { ss_profile : profile;
      ss_state : [ `Start | `C1 | `S1 | `CF | `SF | `Connected | `Error ];
      ss_c1 : client_first option;
      ss_c1_raw : string;
      ss_s1 : server_first option;
      ss_s1_raw : string;
      ss_cf : client_final option;
      ss_cf_raw : string;
      ss_sf : server_final option;
      ss_creds: (string * string) option;
      ss_err : server_error option;
      ss_client_key : string option;
      ss_proto_key : string option;
      ss_nonce : string option;
      ss_authenticate_opt : (string -> string -> credentials) option
    }

(* Exported: *)
exception Invalid_encoding of string * string
exception Invalid_username_encoding of string * string
exception Extensions_not_supported of string * string
exception Protocol_error of string
exception Invalid_server_signature
exception Server_error of server_error

(* Not exported: *)
exception Invalid_proof of string


module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netmech_scram" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netmech_scram" Debug.enable

let () =
  Netlog.Debug.register_module "Netmech_scram" Debug.enable



let profile ?(return_unknown_user=false) ?(iteration_count_limit=100000) 
	    pt h =
  { ptype = pt;
    hash_function = h;
    return_unknown_user = return_unknown_user;
    iteration_count_limit = iteration_count_limit;
  }

let mechanism_name p =
  let iana_name = List.assoc p.hash_function Netsys_digests.iana_rev_alist in
  let uc = STRING_UPPERCASE iana_name in
  "SCRAM-" ^ uc


let string_of_server_error =
  function
    | `Invalid_encoding -> "invalid-encoding"
    | `Extensions_not_supported -> "extensions-not-supported"
    | `Invalid_proof -> "invalid-proof"
    | `Channel_bindings_dont_match -> "channel-bindings-dont-match"
    | `Server_does_support_channel_binding -> 
	"server-does-support-channel-binding"
    | `Channel_binding_not_supported -> "channel-binding-not-supported"
    | `Unsupported_channel_binding_type -> "unsupported-channel-binding-type"
    | `Unknown_user -> "unknown-user"
    | `Invalid_username_encoding -> "invalid-username-encoding"
    | `No_resources -> "no-resources"
    | `Other_error -> "other-error"
    | `Extension s -> s

let server_error_of_string =
  function
    | "invalid-encoding" -> `Invalid_encoding
    | "extensions-not-supported" -> `Extensions_not_supported
    | "invalid-proof" -> `Invalid_proof
    | "channel-bindings-dont-match" -> `Channel_bindings_dont_match
    | "server-does-support-channel-binding" ->
	`Server_does_support_channel_binding
    | "channel-binding-not-supported" -> `Channel_binding_not_supported
    | "unsupported-channel-binding-type" -> `Unsupported_channel_binding_type
    | "unknown-user" -> `Unknown_user
    | "invalid-username-encoding" -> `Invalid_username_encoding
    | "no-resources" -> `No_resources
    | "other-error" -> `Other_error
    | s -> `Extension s


let error_of_exn =
  function
  | Invalid_encoding(m,_) ->
      "Invalid encoding: " ^ m
  | Invalid_username_encoding(m,_) ->
      "Invalid user name encoding: " ^ m
  | Extensions_not_supported(m,_) ->
      "Extensions not supported: " ^ m
  | Protocol_error m ->
      "Protocol error: " ^ m
  | Invalid_server_signature ->
      "Invalid server signature"
  | Server_error code ->
      let m = string_of_server_error code in
      "Server error code: " ^ m
  | _ ->
      assert false
             


let saslprep s = 
  (* We don't call SASLprep here, but leave this to the users. Only check
     for valid UTF-8.
   *)
  try 
    Netconversion.verify `Enc_utf8 s;
    s
  with
    | _ ->
         raise(Invalid_encoding("Invalid UTF-8", s))


let username_saslprep s =
  try
    saslprep s
  with
    | Invalid_encoding(s1,s2) ->
	raise(Invalid_username_encoding(s1,s2))


let comma_re = Netstring_str.regexp ","

let comma_split s =
  Netstring_str.split_delim comma_re s

let n_value_re = Netstring_str.regexp "\\([a-zA-Z]\\)=\\(.*\\)"

let n_value_split s =
  match Netstring_str.string_match n_value_re s 0 with
    | None -> raise (Invalid_encoding("n_value_split", s))
    | Some r ->
	(Netstring_str.matched_group r 1 s,
	 Netstring_str.matched_group r 2 s)

let check_value_safe_chars s =
  let enc =
    `Enc_subset(`Enc_utf8,
	    fun i -> i <> 0 && i <> 0x2c && i <> 0x3d) in
  try
    Netconversion.verify enc s
  with _ -> raise(Invalid_encoding("check_value_safe_chars",s))

let check_value_chars s =
  let enc =
    `Enc_subset(`Enc_utf8,
		fun i -> i <> 0 && i <> 0x2c) in
  try
    Netconversion.verify enc s
  with _ -> raise(Invalid_encoding("check_value_chars",s))

let check_printable s =
  for i = 0 to String.length s - 1 do
    match s.[i] with
      | '\x21'..'\x2b' -> ()
      | '\x2d'..'\x7e' -> ()
      | _ -> raise(Invalid_encoding("check_printable",s))
  done

let pos_re = Netstring_str.regexp "[1-9][0-9]+$"

let check_positive_number s =
  match Netstring_str.string_match pos_re s 0 with
    | None -> raise(Invalid_encoding("check_positive_number",s))
    | Some _ -> ()

let encode_saslname s =
  try
    Netgssapi_support.gs2_encode_saslname s
  with
    | Failure _ ->
        raise(Invalid_username_encoding("encode_saslname",s))

let decode_saslname s =
  try
    Netgssapi_support.gs2_decode_saslname s
  with
    | Failure _ ->
        raise(Invalid_username_encoding("decode_saslname",s))


let encode_gs2_sasl gs2 =
  (match gs2.gs2_cb with
     | `None -> "n"
     | `SASL_none_but_advertise -> "y"
     | `SASL_require(v,_) -> "p=" ^ v
     | `GSSAPI _ -> assert false
  ) ^ 
    (match gs2.gs2_authzname with
       | None | Some "" -> ","
       | Some name -> ",a=" ^ encode_saslname name
    (* RFC 4422 does not allow SASLprep for the auth string *)
    ) ^ ","

let encode_gs2_http gs2 =
  (match gs2.gs2_cb with
     | `None -> "n"
     | `SASL_none_but_advertise -> "y"
     | `SASL_require(v,_) -> "p=" ^ v
     | `GSSAPI _ -> assert false
  ) ^ ","

let encode_gs2 ptype gs2 =
  match ptype with
    | `SASL -> encode_gs2_sasl gs2
    | `GSSAPI -> assert false


let encode_cbind_input ptype gs2 =
  ( match ptype with
      | `SASL -> encode_gs2_sasl gs2
      | `GSSAPI -> ""
  ) ^ 
    ( match gs2.gs2_cb with
        | `SASL_require(_,data) -> data
        | _ -> ""
    )



let gs2_sasl_re = Netstring_str.regexp "\\(y\\|n\\|p=[^,]*\\),\\(a=[^,]*\\)?,"

let gs2_http_re = Netstring_str.regexp "\\(y\\|n\\|p=[^,]*\\),"

let decode_gs2 ?(cb_includes_data=false) ptype s =
  let re, has_authz =
    match ptype with
      | `SASL -> gs2_sasl_re, true
      | `GSSAPI -> assert false in
  match Netstring_str.string_match re s 0 with
    | Some m ->
         let m_end = Netstring_str.match_end m in
         let rest = String.sub s m_end (String.length s - m_end) in
         let cb = Netstring_str.matched_group m 1 s in
         let gs2_cb =
           if cb = "n" then
             `None
           else if cb = "y" then
             `SASL_none_but_advertise
           else (
             let (n,v) = n_value_split cb in
             if n <> "p" then
               raise(Invalid_encoding("decode_gs2 [1]", s));
             let data =
               if cb_includes_data then
                 rest
               else
                 "" in
             `SASL_require(v, data)
           ) in
         let authzname =
           if has_authz then
             try Netstring_str.matched_group m 2 s with Not_found -> ""
           else "" in
         let gs2_authzname =
           if authzname = "" then
             None
           else (
             let (authzname_n, authzname_v) = n_value_split authzname in
             if authzname_n <> "a" then
               raise(Invalid_encoding("decode_gs2 [2]", s));
	     let authzname_v = decode_saslname authzname_v in
             (* No SASLprep. RFC 4422 is very clear that the auth string can
                use any Unicode chars.
              *)
             Some authzname_v
           ) in
         let gs2 = { gs2_cb; gs2_authzname } in
         (gs2, rest)
    | _ ->
         raise(Invalid_encoding("decode_gs2", s))


let remove_gs2 ptype s =
  match ptype with
    | `GSSAPI -> s
    | `SASL -> snd(decode_gs2 ptype s)


let encode_c1_message ptype c1 =
  let gs2_header =
    match ptype with
      | `SASL -> Some(encode_gs2 ptype c1.c1_gs2)
      | `GSSAPI -> None in
  (gs2_header,
   [ "n", encode_saslname(username_saslprep c1.c1_username);
     "r", c1.c1_nonce;
   ] @ c1.c1_extensions
  )


let format_msg l =
  String.concat "," (List.map (fun (n,v) -> n ^ "=" ^ v) l)

let format_client_msg (gs2_opt,l) =
  (match gs2_opt with
     | None -> ""
     | Some gs2_header -> gs2_header
  ) ^ 
    format_msg l


let decode_c1_message_after_gs2 s l gs2_header =
  match l with
    | [] ->
	raise(Invalid_encoding("decode_c1_mesage: empty", s))
    | ("m",_) :: _ ->
	raise(Extensions_not_supported("decode_c1_mesage: unsupported", s))
    | ("n", username_raw) :: ("r", nonce) :: l' ->
	let username = decode_saslname username_raw in
	let username' = username_saslprep username in
	if username <> username' then
	  raise(Invalid_username_encoding("Netmech_scram.decode_c1_message",
					  s));
	{ c1_username = username;
          c1_gs2 = gs2_header;
	  c1_nonce = nonce;
	  c1_extensions = l'
	}
    | _ ->
	raise(Invalid_encoding("decode_c1_mesage", s))

let decode_c1_message ptype s =
  match ptype with
    | `GSSAPI ->
         let l1 = comma_split s in
         let l2 = List.map n_value_split l1 in
         let gs2 = { gs2_authzname = None; gs2_cb = `None } in
         decode_c1_message_after_gs2 s l2 gs2 
    | `SASL ->
         let (gs2, rest) = decode_gs2 ptype s in
         let l1 = comma_split rest in
         let l2 = List.map n_value_split l1 in
         decode_c1_message_after_gs2 s l2 gs2
                  

let encode_s1_message s1 =
  [ "r", s1.s1_nonce;
    "s", Netencoding.Base64.encode s1.s1_salt;
    "i", string_of_int s1.s1_iteration_count;
  ] @ s1.s1_extensions


let decode_s1_message s =
  let l = List.map n_value_split (comma_split s) in
  match l with
    | [] ->
	raise(Invalid_encoding("decode_s1_mesage: empty", s))
    | ("m",_) :: _ ->
	raise(Extensions_not_supported("decode_s1_mesage: unsupported", s))
    | ("r",nonce) :: ("s",salt_b64) :: ("i",icount_raw) :: l' ->
	let salt =
	  try Netencoding.Base64.decode salt_b64
	  with _ ->
	    raise(Invalid_encoding("decode_s1_message: invalid s", s)) in
	check_positive_number icount_raw;
	let icount = 
	  try int_of_string icount_raw 
	  with _ -> 
	    raise(Invalid_encoding("decode_s1_message: invalid i", s)) in
	{ s1_nonce = nonce;
	  s1_salt = salt;
	  s1_iteration_count = icount;
	  s1_extensions = l'
	}
    | _ ->
	raise(Invalid_encoding("decode_s1_mesage", s))


(* About the inclusion of "c": RFC 5802 is not entirely clear about this.
   I asked the authors of the RFC what to do. The idea is that the 
   GSS-API flavor of SCRAM is obtained by removing the GS2 (RFC 5801)
   part from the description in RFC 5802 for SASL. This leads to the
   interpretation that the "c" parameter is required, and it includes the
   channel binding string as-is, without any prefixed gs2-header.
   (Remember that GS2 is a wrapper around GSS-API, and it can then
   pass the right channel binding string down, i.e. a string that includes
   the gs2-header.)
 *)
	
let encode_cf_message ptype cf =
  let cbind_input = encode_cbind_input ptype cf.cf_gs2 in
  [ "c", Netencoding.Base64.encode cbind_input;
    "r", cf.cf_nonce;
  ] @ cf.cf_extensions @
    ( match cf.cf_proof with
        | None -> []
        | Some p ->
	    [ "p", Netencoding.Base64.encode p ]
    )
      

let decode_cf_message ptype expect_proof s =
  let l = List.map n_value_split (comma_split s) in
  match l with
    | [] ->
	raise(Invalid_encoding("decode_cf_mesage: empty", s))
    | ("c",chanbind_b64) :: ("r",nonce) :: l' ->
	let chanbind =
	  try Netencoding.Base64.decode chanbind_b64 
	  with _ ->
	    raise(Invalid_encoding("decode_cf_mesage: invalid c",
				   s)) in
        let cf_gs2 =
          match ptype with
            | `GSSAPI ->
                 { gs2_authzname = None;
                   gs2_cb = `GSSAPI chanbind
                 }
            | `SASL | `HTTP ->
                 let gs2,_ = decode_gs2 ~cb_includes_data:true ptype chanbind in
                 gs2 in

	let p, l'' =
	  if expect_proof then
	    match List.rev l' with
	      | ("p", proof_b64) :: l''_rev ->
		  let p = 
		    try Netencoding.Base64.decode proof_b64 
		    with _ ->
		      raise(Invalid_encoding("decode_cf_mesage: invalid p",
					     s)) in
		  (Some p, List.rev l''_rev)
	      | _ ->
		  raise(Invalid_encoding("decode_cf_mesage: proof not found",
					 s))
	  else
	    None, l' in
	{ cf_gs2;
	  cf_nonce = nonce;
	  cf_extensions = l'';
	  cf_proof = p
	}
    | _ ->
	raise(Invalid_encoding("decode_cf_mesage", s))

let strip_cf_proof s =
  let l = List.rev (List.map n_value_split (comma_split s)) in
  match l with
    | ("p",_) :: l' ->
	String.concat "," (List.map (fun (n,v) -> n ^ "=" ^ v) (List.rev l'))
    | _ ->
	assert false


let () =
  Netexn.register_printer
    (Server_error `Invalid_encoding)
    (fun e ->
       match e with
	 | Server_error token ->
	     sprintf "Server_error(%s)" (string_of_server_error token)
	 | _ -> assert false
    )


let encode_sf_message sf =
  ( match sf.sf_error_or_verifier with
      | `Error e ->
	  [ "e", string_of_server_error e ]
      | `Verifier v ->
	  [ "v", Netencoding.Base64.encode v ]
  ) @ sf.sf_extensions


let decode_sf_message s =
  let l = List.map n_value_split (comma_split s) in
  match l with
    | [] ->
	raise(Invalid_encoding("decode_cf_mesage: empty", s))
    | ("v",verf_raw) :: l' ->
	let verf =
	  try Netencoding.Base64.decode verf_raw 
	  with _ -> 
	    raise(Invalid_encoding("decode_sf_message: invalid v", s)) in
	{ sf_error_or_verifier = `Verifier verf;
	  sf_extensions = l'
	}
    | ("e",error_s) :: l' ->
	let error = server_error_of_string error_s in
	{ sf_error_or_verifier = `Error error;
	  sf_extensions = l'
	}
    | _ ->
	raise(Invalid_encoding("decode_sf_mesage", s))




let hash h =
  try Netsys_digests.iana_find h
  with Not_found ->
    let name = List.assoc h Netsys_digests.name_rev_alist in
    failwith ("Netmech_scram: cannot find digest " ^ name ^ 
                ". Is the crypto support initialized?")

let hash_string h s =
  let dg = hash h in
  Netsys_digests.digest_string dg s

let hmac h key =
  Netsys_digests.hmac (hash h) key

let hmac_string h key str =
  let dg = hmac h key in
  Netsys_digests.digest_string dg str

let hmac_mstrings h key ms_list =
  let dg = hmac h key in
  Netsys_digests.digest_mstrings dg ms_list

let int_s i =
  let s = Bytes.make 4 '\000' in
  Bytes.set s 0 (Char.chr ((i lsr 24) land 0xff));
  Bytes.set s 1 (Char.chr ((i lsr 16) land 0xff));
  Bytes.set s 2 (Char.chr ((i lsr 8) land 0xff));
  Bytes.set s 3 (Char.chr (i land 0xff));
  Bytes.unsafe_to_string s

let hi h str salt i =
  let rec uk k =
    if k=1 then
      let u = hmac_string h str (salt ^ int_s 1) in
      let h = u in
      (u,h)
    else (
      let (u_pred, h_pred) = uk (k-1) in
      let u = hmac_string h str u_pred in
      let h = Netauth.xor_s u h_pred in
      (u,h)
    ) in
  snd (uk i)


let lsb128 s =
  (* The least-significant 128 bits *)
  let l = String.length s in
  if l < 16 then
    failwith "Netmech_scram.lsb128";
  String.sub s (l-16) 16


let create_random() =
  let s = Bytes.make 16 ' ' in
  Netsys_rng.fill_random s;
  Digest.to_hex (Bytes.to_string s)


let create_nonce() =
  create_random()

let create_salt() =
  create_random()


let create_client_session2 ?nonce profile username authzname password =
  ignore(saslprep username);
  ignore(saslprep authzname);
  ignore(saslprep password);  (* Check for errors *)
  { cs_profile = profile;
    cs_state = `Start;
    cs_c1 = None;
    cs_s1 = None;
    cs_s1_raw = "";
    cs_cf = None;
    cs_sf = None;
    cs_auth_message = "";
    cs_salted_pw = "";
    cs_username = username;
    cs_authzname = authzname;
    cs_password = password;
    cs_client_key = None;
    cs_proto_key = None;
    cs_cb = `None;
    cs_nonce = nonce;
  }

let create_client_session ?nonce profile username password =
  create_client_session2 ?nonce profile username "" password

 

let client_emit_flag cs =
  match cs.cs_state with
    | `Start | `S1 | `Restart _ -> true
    | _ -> false


let client_recv_flag cs =
  match cs.cs_state with
    | `C1 | `CF | `CR _ -> true
    | _ -> false


let client_finish_flag cs =
  match cs.cs_state with
    | `Connected
    | `SR _ -> true
    | _ -> false

let client_semifinish_flag cs =
  match cs.cs_state with
    | `CF
    | `CR _
    | `Connected
    | `SR _ -> true
    | _ -> false


let client_error_flag cs =
  match cs.cs_state with `Error e -> Some e | _ -> None


let catch_error cs onerror f arg =
  try
    f arg
  with
    | error ->
	dlog (sprintf "Client caught error: %s"
		(Netexn.to_string error));
        onerror { cs with cs_state = `Error error }


let client_protocol_key cs =
  cs.cs_proto_key

let client_user_name cs =
  cs.cs_username

let client_authz_name cs =
  cs.cs_authzname

let client_password cs =
  cs.cs_password

let client_configure_channel_binding cs cb =
  ( match cs.cs_state with
      | `Start | `C1 | `S1 -> ()
      | _ -> failwith "Netmech_scram.client_configure_channel_binding"
  );
  ( match cs.cs_profile.ptype, cb with
      | _, `None -> ()
      | `GSSAPI, `GSSAPI _ -> ()
      | `SASL, (`SASL_none_but_advertise | `SASL_require _) -> ()
      | _ -> failwith "Netmech_scram.client_configure_channel_binding"
  );
  { cs with cs_cb = cb }

let client_channel_binding cs =
  cs.cs_cb

let client_export cs =
  Marshal.to_string cs []

let client_import s =
  ( Marshal.from_string s 0 : client_session)

let client_prop cs key =
  match key with
    | "snonce" ->
        ( match cs.cs_s1 with
            | None -> raise Not_found
            | Some s1 -> s1.s1_nonce
        )
    | "cnonce" ->
        ( match cs.cs_c1 with
            | None -> raise Not_found
            | Some c1 -> c1.c1_nonce
        )
    | "salt" ->
        ( match cs.cs_s1 with
            | None -> raise Not_found
            | Some s1 -> s1.s1_salt
        )
    | "i" ->
        ( match cs.cs_s1 with
            | None -> raise Not_found
            | Some s1 -> string_of_int s1.s1_iteration_count
        )
    | "client_key" ->
        ( match cs.cs_client_key with
            | None -> raise Not_found
            | Some key -> key
        )
    | "protocol_key" ->
        ( match client_protocol_key cs with
            | None -> raise Not_found
            | Some key -> key
        )
    | "error" ->
        ( match cs.cs_state with
            | `Error e -> Netexn.to_string e
            | _ -> raise Not_found
        )
    | _ -> raise Not_found


let salt_password h password salt iteration_count =
  let sp = hi h (saslprep password) salt iteration_count in
  (* eprintf "salt_password(%S,%S,%d) = %S\n" password salt iteration_count sp; *)
  sp


let stored_key h password salt iteration_count =
  let salted_pw = salt_password h password salt iteration_count in
  let client_key = hmac_string h salted_pw "Client Key" in
  let stored_key = hash_string h client_key in
  let server_key = hmac_string h salted_pw "Server Key" in
  (stored_key, server_key)

let client_restart cs sr =
  match cs.cs_state with
    | `SF ->
        ( match cs.cs_c1, cs.cs_s1 with
            | Some c1, Some s1 ->
                let c1_nlen = String.length c1.c1_nonce in
                let s1_sr =
                  String.sub
                    s1.s1_nonce c1_nlen (String.length s1.s1_nonce - c1_nlen) in
                if sr = s1_sr then
                  { cs with cs_state = `Restart s1.s1_iteration_count }
                else
                  let e = Protocol_error ("bad sr attribute") in
                  { cs with cs_state = `Error e }
            | _ ->
                assert false
        )
    | `SR n ->
        { cs with cs_state = `Restart (n+1) }
    | _ ->
        let e = Failure "Netmech_scram.client_restart" in
        { cs with cs_state = `Error e }

let client_restart_stale cs sr =
  match cs.cs_state with
    | `CR ncount ->
        ( match cs.cs_c1, cs.cs_s1 with
            | Some c1, Some s1 ->
                let s1' =
                  { s1 with s1_nonce = c1.c1_nonce ^ sr } in
                { cs with
                  cs_s1 = Some s1';
                  cs_state = `Restart ncount
                    (* not successful, so use same nonce-count again *)
                }
            | _ ->
                assert false
        )
    | _ ->
        let e = Failure "Netmech_scram.client_restart" in
        { cs with cs_state = `Error e }


let client_emit_message_kv cs =
  let p = cs.cs_profile in
  let h = p.hash_function in
  let gs2 =
    { gs2_authzname = Some cs.cs_authzname;
      gs2_cb = cs.cs_cb
    } in
  catch_error
    cs
    (fun cs -> (cs,None,["m","invalid_message"]))
    (fun () ->
       match cs.cs_state with
	 | `Start ->
	     let c1 =
	       { c1_username = cs.cs_username;
                 c1_gs2 = gs2;
		 c1_nonce = 
                   ( match cs.cs_nonce with
                       | Some n -> n
                       | None -> create_nonce()
                   );
		 c1_extensions = []
	       } in
             let cs' = { cs with cs_c1 = Some c1; cs_state = `C1 } in
	     let (gs2_opt,m) = encode_c1_message p.ptype c1 in
	     dlogr
               (fun () ->
                  let ms = format_client_msg (gs2_opt,m) in
                  sprintf "Client state `Start emitting message: %s" ms
               );
	     (cs',gs2_opt,m)
	       
	 | `S1 ->
	     let c1 =
	       match cs.cs_c1 with None -> assert false | Some c1 -> c1 in
	     let s1 =
	       match cs.cs_s1 with None -> assert false | Some s1 -> s1 in
	     let salted_pw = 
	       salt_password 
                 h cs.cs_password s1.s1_salt s1.s1_iteration_count in
	     let client_key = hmac_string h salted_pw "Client Key" in
	     let stored_key = hash_string h client_key in
	     let cf_no_proof =
               format_msg
	         (encode_cf_message
                    p.ptype
                    { cf_gs2 = gs2;
		      cf_nonce = s1.s1_nonce;
		      cf_extensions = [];
		      cf_proof = None
		    } 
                 ) in
             let c1_str =
               format_client_msg (None, snd (encode_c1_message p.ptype c1)) in
	     let auth_message =
	       c1_str ^ "," ^  cs.cs_s1_raw ^ "," ^ cf_no_proof in
             dlogr (fun () -> "Client auth_message: " ^ auth_message);
	     let client_signature = hmac_string h stored_key auth_message in
	     let proof = Netauth.xor_s client_key client_signature in
	     let cf =
	       { cf_gs2 = gs2;
		 cf_nonce = s1.s1_nonce;
		 cf_extensions = [];
		 cf_proof = Some proof;
	       } in
             let cs' =
               { cs with
	         cs_cf = Some cf;
	         cs_state = `CF;
	         cs_auth_message = auth_message;
	         cs_salted_pw = salted_pw;
                 cs_client_key = Some client_key;
	         cs_proto_key = Some ( lsb128
					 (hmac_string
                                            h
					    stored_key
					    ("GSS-API session key" ^ 
					       client_key ^ auth_message)));
               } in
	     let m = encode_cf_message p.ptype cf in
	     dlogr
               (fun () ->
                  let ms = format_msg m in
	          sprintf "Client state `S1 emitting message: %s" ms
               );
	     (cs',None,m)

         | `Restart ncount ->
	     let c1 =
	       match cs.cs_c1 with None -> assert false | Some c1 -> c1 in
	     let s1 =
	       match cs.cs_s1 with None -> assert false | Some s1 -> s1 in
	     let client_key = hmac_string h cs.cs_salted_pw "Client Key" in
	     let stored_key = hash_string h client_key in
             let c1_nlen = String.length c1.c1_nonce in
             let sr =
               String.sub
                 s1.s1_nonce c1_nlen (String.length s1.s1_nonce - c1_nlen) in
             let cf_nonce = c1.c1_nonce ^ string_of_int ncount ^ sr in
	     let cf_no_proof =
               format_msg
	         (encode_cf_message
                    p.ptype
                    { cf_gs2 = gs2;
		      cf_nonce;
		      cf_extensions = [];
		      cf_proof = None
		    } 
                 ) in
             let c1_str =
               format_client_msg (None, snd (encode_c1_message p.ptype c1)) in
             let s1_str =
               (* "When constructing AuthMessage ... server-first-message [is]
                  reconstructed ..." - note that sr may have changed.
                *)
               format_msg (encode_s1_message s1) in
	     let auth_message =
	       c1_str ^ "," ^ s1_str ^ "," ^ cf_no_proof in
             dlogr (fun () -> "Client auth_message: " ^ auth_message);
	     let client_signature = hmac_string h stored_key auth_message in
	     let proof = Netauth.xor_s client_key client_signature in
	     let cf =
	       { cf_gs2 = gs2;
		 cf_nonce;
		 cf_extensions = [];
		 cf_proof = Some proof;
	       } in
             let cs' =
               { cs with
	         cs_cf = Some cf;
	         cs_state = `CR ncount;
	         cs_auth_message = auth_message;
                 cs_client_key = Some client_key;
	         cs_proto_key = Some ( lsb128
					 (hmac_string
                                            h
					    stored_key
					    ("GSS-API session key" ^ 
					       client_key ^ auth_message)));
               } in
	     let m = encode_cf_message p.ptype cf in
	     dlogr
               (fun () ->
                  let ms = format_msg m in
	          sprintf "Client state `S1 emitting message: %s" ms
               );
	     (cs',None,m)
	       
	 | _ ->
	     failwith "Netmech_scram.client_emit_message"
    )
    ()


let client_emit_message cs =
  let (cs',gs2_opt,m) = client_emit_message_kv cs in
  (cs',format_client_msg (gs2_opt,m))


let client_recv_message cs message =
  let p = cs.cs_profile in
  let h = p.hash_function in
  catch_error
    cs
    (fun cs -> cs)
    (fun () ->
       match cs.cs_state with
	 | `C1 ->
	     dlog (sprintf "Client state `C1 receiving message: %s" message);
	     let s1 = decode_s1_message message in
	     let c1 =
	       match cs.cs_c1 with None -> assert false | Some c1 -> c1 in
	     if String.length s1.s1_nonce < String.length c1.c1_nonce then
	       raise (Protocol_error
			"client_recv_message: Nonce from the server is too short");
	     if String.sub s1.s1_nonce 0 (String.length c1.c1_nonce) <> c1.c1_nonce
	     then
	       raise (Protocol_error
			"client_recv_message: bad nonce from the server");
	     if s1.s1_iteration_count > cs.cs_profile.iteration_count_limit then
	       raise (Protocol_error
			"client_recv_message: iteration count too high");
             dlog (sprintf "s-nonce=%S salt=%S i=%d" s1.s1_nonce s1.s1_salt
                  s1.s1_iteration_count);
	     { cs with
               cs_state = `S1;
	       cs_s1 = Some s1;
	       cs_s1_raw = message
             }
	       
	 | `CF ->
	     dlog (sprintf "Client state `CF receiving message: %s" message);
	     let sf = decode_sf_message message in
	     ( match sf.sf_error_or_verifier with
		 | `Verifier v ->
                     dlog (sprintf "CF got verifier=%S" v);
		     let salted_pw = cs.cs_salted_pw in
                     dlog (sprintf "CF salted_pw=%S" salted_pw);
		     let server_key =
		       hmac_string h salted_pw "Server Key" in
                     dlog (sprintf "CF server_key=%S" server_key);
		     let server_signature =
		       hmac_string h server_key cs.cs_auth_message in
                     dlog (sprintf "CF expected signature=%S" server_signature);
		     if v <> server_signature then
		       raise Invalid_server_signature;
		     dlog "Client is authenticated";
                     { cs with cs_state = `Connected }
		 | `Error e ->
		     dlog (sprintf "Client got error token from server: %s"
			     (string_of_server_error e));
		     raise(Server_error e)
	     )

         | `CR ncount ->
	     dlog (sprintf "Client state `CR receiving message: %s" message);
	     let sf = decode_sf_message message in
	     ( match sf.sf_error_or_verifier with
		 | `Verifier v ->
		     let salted_pw = cs.cs_salted_pw in
		     let server_key =
		       hmac_string h salted_pw "Server Key" in
		     let server_signature =
		       hmac_string h server_key cs.cs_auth_message in
		     if v <> server_signature then
		       raise Invalid_server_signature;
		     dlog "Client is authenticated";
                     { cs with cs_state = `SR ncount }
		 | `Error e ->
		     dlog (sprintf "Client got error token from server: %s"
			     (string_of_server_error e));
		     raise(Server_error e)
	     )
	       
	 | _ ->
	     failwith "Netmech_scram.client_recv_message"
    )
    ()


let create_server_session2 ?nonce profile auth =
  (* auth: called as: let (salted_pw, salt, i) = auth username *)
  { ss_profile = profile;
    ss_state = `Start;
    ss_c1 = None;
    ss_c1_raw = "";
    ss_s1 = None;
    ss_s1_raw = "";
    ss_cf = None;
    ss_cf_raw = "";
    ss_sf = None;
    ss_authenticate_opt = Some auth;
    ss_creds = None;
    ss_err = None;
    ss_nonce = nonce;
    ss_client_key = None;
    ss_proto_key = None;
  }


let create_server_session ?nonce profile auth =
  create_server_session2 ?nonce profile (fun username _ -> auth username)


let server_emit_flag ss =
  match ss.ss_state with
    | `C1 | `CF -> true
    | _ -> false

let server_recv_flag ss =
  match ss.ss_state with
    | `Start | `S1 -> true
    | _ -> false

let server_finish_flag ss =
  ss.ss_state = `Connected

let server_error_flag ss =
  ss.ss_state = `Error

let server_protocol_key ss =
  ss.ss_proto_key

let server_export ss =
  Marshal.to_string { ss with ss_authenticate_opt = None } []

let server_import s =
  let ss = ( Marshal.from_string s 0 : server_session) in
  if ss.ss_state <> `Connected then
    failwith "Netmech_scram.server_import: session not finished";
  ss

let server_import_any2 s auth =
  let ss = ( Marshal.from_string s 0 : server_session) in
  { ss with ss_authenticate_opt = Some auth }

let server_import_any s auth =
  server_import_any2 
    s
    (fun username _ -> auth username)


let catch_condition ss f arg =
  let debug e =
    dlog (sprintf "Server caught error: %s"
	    (Netexn.to_string e)) in
  try
    f arg
  with
    (* After such an error the protocol will continue, but the final
       server message will return the condition
     *)
    | Invalid_encoding(_,_) as e ->
	debug e;
        (if ss.ss_err = None then
	   { ss with ss_err = Some `Invalid_encoding }
         else
           ss
        )
    | Invalid_username_encoding _ as e ->
	debug e;
        (if ss.ss_err = None then
	   { ss with ss_err = Some `Invalid_username_encoding }
         else
           ss
        )
    | Extensions_not_supported(_,_) as e ->
	debug e;
        (if ss.ss_err = None then
	   { ss with ss_err = Some `Extensions_not_supported }
         else
           ss
        )
    | Invalid_proof _ as e ->
	debug e;
        (if ss.ss_err = None then
	   { ss with ss_err = Some `Invalid_proof }
         else
           ss
        )
	

exception Skip_proto


let server_emit_message_kv ss =
  let p = ss.ss_profile in
  let h = p.hash_function in
  match ss.ss_state with
    | `C1 ->
	let (ss',m) =
	  try
	    let c1 = 
	      match ss.ss_c1 with
		| None -> raise Skip_proto | Some c1 -> c1 in
	    let creds =
	      match ss.ss_authenticate_opt with
		| Some auth ->
                     let authzname =
                       match c1.c1_gs2.gs2_authzname with
                         | None -> c1.c1_username
                         | Some n -> n in
                     auth c1.c1_username authzname
		| None -> assert false in
            let (stkey,srvkey,salt, i) =
              match creds with
                | `Salted_password(spw,salt,i) -> 
		     let srvkey =
		       hmac_string h spw "Server Key" in
	             let client_key = 
                       hmac_string h spw "Client Key" in
	             let stored_key =
                       hash_string h client_key in
                     (stored_key,srvkey,salt,i)
                | `Stored_creds(stkey,srvkey,salt,i) -> 
                     (stkey,srvkey,salt,i) in
            let nonce =
              match ss.ss_nonce with
                | None -> create_nonce()
                | Some n -> n in
	    let s1 =
	      { s1_nonce = c1.c1_nonce ^ nonce;
		s1_salt = salt;
		s1_iteration_count = i;
		s1_extensions = []
	      } in
	    let s1_enc = encode_s1_message s1 in
            let ss' =
              { ss with
	        ss_state = `S1;
	        ss_s1 = Some s1;
	        ss_creds = Some(stkey,srvkey);
	        ss_s1_raw = format_msg s1_enc;
              } in
	    (ss',s1_enc)
	  with Not_found | Skip_proto ->
	    (* continue with a dummy auth *)
	    dlog "Server does not know this user";
	    let c1_nonce =
	      match ss.ss_c1 with
		| None -> create_nonce() | Some c1 -> c1.c1_nonce in
	    let s1 =
	      { s1_nonce = c1_nonce ^ create_nonce();
		s1_salt = create_nonce();
		s1_iteration_count = 4096;
		s1_extensions = []
	      } in
	    let s1_enc = encode_s1_message s1 in
            let ss' =
              { ss with
	        ss_state = `S1;
	        ss_s1 = Some s1;
                ss_err = (if ss.ss_err = None then
	                    Some (if ss.ss_profile.return_unknown_user then
				   `Unknown_user
				 else
				   `Invalid_proof)
                          else
                            ss.ss_err
                         );
	        ss_s1_raw = format_msg s1_enc;
              } in
	    (ss',s1_enc)
	in
	dlogr
          (fun () ->
             sprintf "Server state `C1 emitting message: %s" (format_msg m)
          );
	(ss',m)
	  
    | `CF ->
	( match ss.ss_err with
	    | Some err ->
		let sf =
		  { sf_error_or_verifier = `Error err;
		    sf_extensions = []
		  } in
		let m = encode_sf_message sf in
		dlogr
                  (fun () ->
                    let ms = format_msg m in
                    sprintf "Server state `CF[Err] emitting message: %s" ms
                  );
                let ss' =
                  { ss with
                    ss_sf = Some sf;
                    ss_state = `Error;
                  } in
		(ss',m)
		  
	    | None ->
		let server_key =
		  match ss.ss_creds with
		    | None -> assert false | Some(_,srvkey) -> srvkey in
                dlog (sprintf "CF server_key=%S" server_key);
		let cf_no_proof = strip_cf_proof ss.ss_cf_raw in
                let c1_bare = remove_gs2 p.ptype ss.ss_c1_raw in
		let auth_message =
		  c1_bare ^ "," ^ 
		    ss.ss_s1_raw ^ "," ^ 
		    cf_no_proof in
                dlog (sprintf "CF auth_message=%S" auth_message);
		let server_signature =
		  hmac_string h server_key auth_message in
                dlog (sprintf "CF signature=%S" server_signature);
		let sf =
		  { sf_error_or_verifier = `Verifier server_signature;
		    sf_extensions = []
		  } in
		let ss' =
                  { ss with 
                    ss_sf = Some sf;
		    ss_state = `Connected;
                  } in
		let m = encode_sf_message sf in
		dlogr
                  (fun () ->
                     sprintf "Server state `CF emitting message: %s" 
                             (format_msg m)
                  );
		(ss',m)
	)
	  
    | _ ->
	failwith "Netmech_scram.server_emit_message"


let server_emit_message ss =
  let ss', m = server_emit_message_kv ss in
  (ss', format_msg m)


let gs2_compatibility c1_gs2 cf_gs2 =
  (* check whether the GS2 headers from c1 and cf are the same *)
  c1_gs2.gs2_authzname = cf_gs2.gs2_authzname &&
    match c1_gs2.gs2_cb, cf_gs2.gs2_cb with
      | `None, `None -> true
      | `SASL_none_but_advertise, `SASL_none_but_advertise -> true
      | `SASL_require(ty1,_), `SASL_require(ty2,_) -> ty1=ty2
      | `None, `GSSAPI _ -> true  (* c1_gs2 does not really exist... *)
      | `GSSAPI _, `GSSAPI _ -> true
      | _ -> false
               

let server_recv_message ss message =
  let p = ss.ss_profile in
  let h = p.hash_function in
  match ss.ss_state with
    | `Start ->
	dlog (sprintf "Server state `Start receiving message: %s" message);

	catch_condition
          ss
	  (fun () ->
	     let c1 = decode_c1_message p.ptype message in
	     { ss with
               ss_c1_raw = message;
	       ss_state = `C1;
               ss_c1 = Some c1;
             }
	  ) ()
        (* Username is checked later *)
    | `S1 ->
	dlog (sprintf "Server state `S1 receiving message: %s" message);

        let ss =
          { ss with
            ss_cf_raw = message;
            ss_state = `CF
          } in

	catch_condition
          ss
	  (fun () ->
	     try
               let c1 =
                 match ss.ss_c1 with
                   | None -> assert false | Some c1 -> c1 in
	       let s1 =
		 match ss.ss_s1 with
		   | None -> raise Skip_proto | Some s1 -> s1 in
	       let stored_key =
		 match ss.ss_creds with
		   | None -> raise Skip_proto | Some(stkey,_) -> stkey in
	       let cf = decode_cf_message p.ptype true message in
	       if s1.s1_nonce <> cf.cf_nonce then
		 raise (Invalid_proof "nonce mismatch");
	       let cf_no_proof = strip_cf_proof message in
               let c1_bare = remove_gs2 p.ptype ss.ss_c1_raw in
	       let auth_message =
		 c1_bare ^ "," ^ 
		   ss.ss_s1_raw ^ "," ^ 
		   cf_no_proof in
               dlogr (fun () -> "Server auth_message: " ^ auth_message);
	       let client_signature =
                 hmac_string h stored_key auth_message in
	       let decoded_client_key = 
                 match cf.cf_proof with
                   | None -> assert false
                   | Some cf_proof -> 
                        Netauth.xor_s cf_proof client_signature in
	       let decoded_stored_key = hash_string h decoded_client_key in
	       if decoded_stored_key <> stored_key then
		 raise (Invalid_proof "bad client signature");
               if not(gs2_compatibility c1.c1_gs2 cf.cf_gs2) then
                 raise (Invalid_proof "invalid gs2 header");
               { ss with
	         ss_cf = Some cf;
                 ss_client_key = Some decoded_client_key;
	         ss_proto_key = Some ( lsb128
					 (hmac_string
                                            h
					    stored_key
					    ("GSS-API session key" ^ 
					       decoded_client_key ^ 
                                                 auth_message)));
               }
	     with
	       | Skip_proto -> ss
	  ) ()
    | _ ->
	failwith "Netmech_scram.server_recv_message"


let server_channel_binding ss =
  match ss.ss_cf with
    | None -> `None
    | Some cf -> cf.cf_gs2.gs2_cb


let server_user_name ss =
  match ss.ss_c1 with
    | None -> None
    | Some c1 -> Some c1.c1_username


let server_authz_name ss =
  match ss.ss_c1 with
    | None -> None
    | Some c1 -> c1.c1_gs2.gs2_authzname


let server_prop ss key =
  match key with
    | "snonce" ->
        ( match ss.ss_s1 with
            | None -> raise Not_found
            | Some s1 -> s1.s1_nonce
        )
    | "cnonce" ->
        ( match ss.ss_c1 with
            | None -> raise Not_found
            | Some c1 -> c1.c1_nonce
        )
    | "salt" ->
        ( match ss.ss_s1 with
            | None -> raise Not_found
            | Some s1 -> s1.s1_salt
        )
    | "i" ->
        ( match ss.ss_s1 with
            | None -> raise Not_found
            | Some s1 -> string_of_int s1.s1_iteration_count
        )
    | "client_key" ->
        ( match ss.ss_client_key with
            | None -> raise Not_found
            | Some key -> key
        )
    | "protocol_key" ->
        ( match server_protocol_key ss with
            | None -> raise Not_found
            | Some key -> key
        )
    | _ -> raise Not_found

(* Encryption for GSS-API *)

module AES_CTS = struct
  (* FIXME: avoid copying strings all the time *)

  let aes128_err() =
    failwith "Netmech_scram: cannot find cipher AES-128. Is the crypto \
              support initialized?"

  let aes128_ecb() =
    try
      Netsys_ciphers.find ("AES-128", "ECB")
    with
      | Not_found -> aes128_err()

  let aes128_cbc() =
    try
      Netsys_ciphers.find ("AES-128", "CBC")
    with
      | Not_found -> aes128_err()

  let c = 128 (* bits *)

  let m = 1 (* byte *)

  let encrypt key s =
    (* AES with CTS as defined in RFC 3962, section 5. It is a bit unclear
       why the RFC uses CTS because the upper layer already ensures that
       s consists of a whole number of cipher blocks
     *)
    let l = String.length s in
    if l <= 16 then (
      (* Corner case: exactly one AES block of 128 bits or less *)
      let cipher = aes128_ecb() in
      let ctx = cipher # create key `Length in  (* any padding is ok here *)
      ctx # encrypt_string s
    )
    else (
      (* Cipher-text stealing, also see
	 http://en.wikipedia.org/wiki/Ciphertext_stealing
       *)
      let cipher = aes128_cbc() in
      let ctx = cipher # create key `CTS in
      ctx # set_iv (String.make 16 '\000');
      ctx # encrypt_string s
    )

  let encrypt_mstrings key ms_list =
    (* Exactly the same, but we get input as "mstring list" and return output
       in the same way
     *)
    let l = Netxdr_mstring.length_mstrings ms_list in
    if l <= 16 then (
      let s = encrypt key (Netxdr_mstring.concat_mstrings ms_list) in
      [ Netxdr_mstring.string_to_mstring s ]
    )
    else (
      let cipher = aes128_cbc() in
      let ctx = cipher # create key `CTS in
      ctx # set_iv (String.make 16 '\000');
      let ch = Netxdr_mstring.in_channel_of_mstrings ms_list in
      let enc_ch = Netchannels_crypto.encrypt_in ctx ch in
      Netxdr_mstring.mstrings_of_in_channel (enc_ch :> Netchannels.in_obj_channel)
    )
    

  let decrypt key s =
    let l = String.length s in
    if l <= 16 then (
      if l <> 16 then
	invalid_arg "Netmech_scram.AES256_CTS: bad length of plaintext";
      let cipher = aes128_ecb() in
      let ctx = cipher # create key `None in
      ctx # set_iv (String.make 16 '\000');
      ctx # decrypt_string s  (* This string is still padded! *)
    ) else (
      let cipher = aes128_cbc() in
      let ctx = cipher # create key `CTS in
      ctx # set_iv (String.make 16 '\000');
      ctx # decrypt_string s
    )


  let decrypt_mstrings key ms_list =
    let l = Netxdr_mstring.length_mstrings ms_list in
    if l <= 16 then (
      let s = decrypt key (Netxdr_mstring.concat_mstrings ms_list) in
      [ Netxdr_mstring.string_to_mstring s ]
    ) else (
      let cipher = aes128_cbc() in
      let ctx = cipher # create key `CTS in
      ctx # set_iv (String.make 16 '\000');
      let ch = Netxdr_mstring.in_channel_of_mstrings ms_list in
      let dec_ch = Netchannels_crypto.decrypt_in ctx ch in
      Netxdr_mstring.mstrings_of_in_channel (dec_ch :> Netchannels.in_obj_channel)
    )

  (* Test vectors from the RFC (for 128 bit AES): *)

  let k_128 =
    "\x63\x68\x69\x63\x6b\x65\x6e\x20\x74\x65\x72\x69\x79\x61\x6b\x69"

  let v1_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\x20"

  let v1_out =
    "\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f\x97"

  let v2_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\x20\
     \x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20"

  let v2_out =
    "\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22\
     \x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5"

  let v3_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\
     \x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43"

  let v3_out =
    "\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8\
     \x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84"

  let v4_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\
     \x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43\
     \x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c"

  let v4_out =
    "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\
     \xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e\
     \x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5"

  let v5_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\
     \x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43\
     \x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20"

  let v5_out =
    "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\
     \x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8\
     \x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8"

  let v6_in =
    "\x49\x20\x77\x6f\x75\x6c\x64\x20\x6c\x69\x6b\x65\x20\x74\x68\x65\
     \x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x47\x61\x75\x27\x73\x20\x43\
     \x68\x69\x63\x6b\x65\x6e\x2c\x20\x70\x6c\x65\x61\x73\x65\x2c\x20\
     \x61\x6e\x64\x20\x77\x6f\x6e\x74\x6f\x6e\x20\x73\x6f\x75\x70\x2e"

  let v6_out =
    "\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\
     \x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8\
     \x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40\
     \x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8"

  let tests =
    [ k_128, v1_in, v1_out;
      k_128, v2_in, v2_out;
      k_128, v3_in, v3_out;
      k_128, v4_in, v4_out;
      k_128, v5_in, v5_out;
      k_128, v6_in, v6_out;
    ]

  let run_tests() =
    let j = ref 1 in
    List.for_all
      (fun (k, v_in, v_out) ->
	 prerr_endline("Test: " ^ string_of_int !j);
         let e1 = encrypt k v_in in
         prerr_endline "  enc ok";
         let d1 = decrypt k v_out in
         prerr_endline "  dec ok";
         let ok1 = e1 = v_out in
         if not ok1 then prerr_endline "  enc unexpected result";
         let ok2 = d1 = v_in in
         if not ok2 then prerr_endline "  dec unexpected result";
         incr j;
         ok1 && ok2
      )
      tests

  let run_mtests() =
    let j = ref 1 in
    List.for_all
      (fun (k, v_in, v_out) ->
	 prerr_endline("Test: " ^ string_of_int !j);
	 let v_in_ms = Netxdr_mstring.string_to_mstring v_in in
	 let v_out_ms = Netxdr_mstring.string_to_mstring v_out in
	 let e = 
	   Netxdr_mstring.concat_mstrings (encrypt_mstrings k [v_in_ms]) in
	 prerr_endline "  enc ok";
	 let d =
	   Netxdr_mstring.concat_mstrings (decrypt_mstrings k [v_out_ms]) in
	 prerr_endline "  dec ok";
	 incr j;
	 e = v_out && d = v_in
      )
      tests
end


module Cryptosystem = struct
  (* RFC 3961 section 5.3 *)

  module C = AES_CTS
    (* Cipher *)

  module I = struct   (* Integrity *)
    let hmac = hmac_string `SHA_1  (* hmac-sha1 *)
    let hmac_mstrings = hmac_mstrings `SHA_1
    let h = 12
  end

  exception Integrity_error

  let derive_keys protocol_key usage =
    let k = 8 * String.length protocol_key in
    if k <> 128 && k <> 256 then
      invalid_arg "Netmech_scram.Cryptosystem.derive_keys";
    let derive kt =
      Netauth.derive_key_rfc3961_simplified
	~encrypt:(C.encrypt protocol_key)
	~random_to_key:(fun s -> s)
	~block_size:C.c
	~k
	~usage
	~key_type:kt in
    { kc = derive `Kc;
      ke = derive `Ke;
      ki = derive `Ki;
    }

  let rec identity x = x

  let encrypt_and_sign s_keys message =
    let c_bytes = C.c/8 in
    let confbuf = Bytes.make c_bytes '\000' in
    Netsys_rng.fill_random confbuf;
    let conf = Bytes.to_string confbuf in
    let l = String.length message in
    let p = (l + c_bytes) mod (identity C.m) in
      (* Due to a bug in the ARM code generator, avoid "... mod 1" *)
    let pad = 
      if p = 0 then "" else String.make (C.m - p) '\000' in
    let p1 = conf ^ message ^ pad in
    let c1 = C.encrypt s_keys.ke p1 in
    let h1 = I.hmac s_keys.ki p1 in
    c1 ^ String.sub h1 0 I.h

  let encrypt_and_sign_mstrings s_keys message =
    let c_bytes = C.c/8 in
    let confbuf = Bytes.make c_bytes '\000' in
    Netsys_rng.fill_random confbuf;
    let conf = Bytes.to_string confbuf in
    let l = Netxdr_mstring.length_mstrings message in
    let p = (l + c_bytes) mod C.m in
    let pad = 
      if p = 0 then "" else String.make (C.m - p) '\000' in
    let p1 =
      ( ( Netxdr_mstring.string_to_mstring conf ) :: message ) @
	[ Netxdr_mstring.string_to_mstring pad ] in
    let c1 = C.encrypt_mstrings s_keys.ke p1 in
    let h1 = I.hmac_mstrings s_keys.ki p1 in
    c1 @ [ Netxdr_mstring.string_to_mstring(String.sub h1 0 I.h) ]

  let decrypt_and_verify s_keys ciphertext =
    let c_bytes = C.c/8 in
    let l = String.length ciphertext in
    if l < I.h then
      invalid_arg "Netmech_scram.Cryptosystem.decrypt_and_verify";
    let c1 = String.sub ciphertext 0 (l - I.h) in
    let h1 = String.sub ciphertext (l - I.h) I.h in
    let p1 = C.decrypt s_keys.ke c1 in
    let h1' = String.sub (I.hmac s_keys.ki p1) 0 I.h in
    if h1 <> h1' then
      raise Integrity_error;
    let q = String.length p1 in
    if q < c_bytes then
      raise Integrity_error;
    String.sub p1 c_bytes (q-c_bytes)
      (* This includes any padding or residue from the lower layer! *)


  let decrypt_and_verify_mstrings s_keys ciphertext =
    let c_bytes = C.c/8 in
    let l = Netxdr_mstring.length_mstrings ciphertext in
    if l < I.h then
      invalid_arg "Netmech_scram.Cryptosystem.decrypt_and_verify";
    let c1 = Netxdr_mstring.shared_sub_mstrings ciphertext 0 (l - I.h) in
    let h1 = 
      Netxdr_mstring.concat_mstrings
	(Netxdr_mstring.shared_sub_mstrings ciphertext (l - I.h) I.h) in
    let p1 = C.decrypt_mstrings s_keys.ke c1 in
    let h1' = String.sub (I.hmac_mstrings s_keys.ki p1) 0 I.h in
    if h1 <> h1' then
      raise Integrity_error;
    let q = Netxdr_mstring.length_mstrings p1 in
    if q < c_bytes then
      raise Integrity_error;
    Netxdr_mstring.shared_sub_mstrings p1 c_bytes (q-c_bytes)
      (* This includes any padding or residue from the lower layer! *)

  let get_ec s_keys n =
    if n < 16 then invalid_arg "Netmech_scram.Cryptosystem.get_ec";
    0

  let get_mic s_keys message =
    String.sub (I.hmac s_keys.kc message) 0 I.h

  let get_mic_mstrings s_keys message =
    String.sub (I.hmac_mstrings s_keys.kc message) 0 I.h

end


(* SASL *)
(*
#use "topfind";;
#require "netstring,nettls-gnutls";;
open Netmech_scram;;
Debug.enable := true;;
let p = { ptype = `SASL; hash_function = `SHA_1; return_unknown_user=false;
         iteration_count_limit = 100000 };;

test_nonce := Some "fyko+d2lbbFgONRv9qkxdawL";;
let cs = create_client_session p "user" "pencil";;
let c1 = client_emit_message cs;;
assert(c1 = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");;
client_recv_message cs "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";;
let c2 = client_emit_message cs;;
assert(c2 = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");;
client_recv_message cs "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";;
assert(client_finish_flag cs);;

test_nonce := Some "3rfcNHYJY1ZVvWVs7j";;
let salt = Netencoding.Base64.decode "QSXCR+Q6sek8bf92";;
let ss = create_server_session p (fun _ -> salt_password `SHA_1 "pencil" salt 4096, salt, 4096);;
server_recv_message ss "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";;
let s1 = server_emit_message ss;;
assert(s1 = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096");;
server_recv_message ss "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";;
let s2 = server_emit_message ss;;
assert(s2 = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");;
assert(server_finish_flag ss);;
 *)
