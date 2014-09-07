(* $Id$ *)

(* For parsing the messages, we just reuse the Nethttp
   function for the www-authenticate HTTP header.
 *)

let parse_message s =
  let u = "dummy," ^ s in
  let mh = Netmime.basic_mime_header ["WWW-Authenticate", u ] in
  snd (Nethttp.Header.get_www_authenticate mh)

(* Quotes strings: *)

let qstring =
  Nethttp.qstring_of_value

module StrMap = Map.Make(String)
module StrSet = Set.Make(String)

module DIGEST_MD5 : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "DIGEST-MD5"
  let client_first = `No
  let server_sends_final_data = true
  let supports_authz = true

  type credentials =
      (string * string * (string * string) list) list

  let init_credentials l =
    (l:credentials)

  type response_params =
      { r_user : string;           (* UTF-8 or ISO-8859-1 *)
        r_authz : string option;
        r_realm : string;
        r_nonce : string;
        r_cnonce : string;
        r_nc : int;
        r_digest_uri : string;
        r_utf8 : bool;
      }

  type server_session = 
      { mutable sstate : Netsys_sasl_types.server_state;
        mutable sresponse : (response_params * string * string) option;
        mutable snextnc : int;
        mutable sstale : bool;
        mutable snonce : string;
        srealm : string option;
        lookup : string -> string -> credentials option;
      }

  let compute_response (p:response_params) password a2_prefix =
    (* a2_prefix: either "AUTHENTICATE:" or ":" *)
    XXX

  let server_state ss = ss.sstate

  let create_nonce() =
    let nonce_data = String.create 16 in
    Netsys_rng.fill_random nonce_data;
    Netencoding.to_hex nonce_data

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_server_session:"
        [ "realm" ]
        params in
    let srealm =
      try Some(List.assoc "realm" params)
      with Not_found -> None in
    let nonce = create_nonce() in
    { sstate = `Emit;
      srealm;
      snonce = nonce;
      sresponse = None;
      snextnc = 1;
      sstale = false;
      lookup
    }

  let verify_utf8 s =
    try
      Netconversion.verify `Enc_utf8 s
    with _ -> raise Not_found

  let to_utf8 is_utf8 s =
    (* Convert from client encoding to UTF-8 *)
    if is_utf8 then (
      verify_utf8 s;
      s
    )
    else
      (* it is ISO-8859-1 *)
      Netconversion.convert
        ~in_enc:`Enc_iso88591
        ~out_enc:`Enc_utf8
        s

  let to_client is_utf8 s =
    (* Convert from UTF-8 to client encoding *)
    if is_utf8 then (
      verify_utf8 s;
      s   (* client uses utf-8, too *)
    )
    else
      try
        Netconversion.convert
          ~in_enc:`Enc_utf8
          ~out_enc:`Enc_iso88591
          s
      with
        | Netconversion.Malformed_code -> raise Not_found

  let server_emit_challenge ss =
    if ss.sstate <> `Emit then
      failwith "Netmech_digestmd5_sasl.server_emit_challenge: bad state";
    match ss.sresponse with
      | None ->
           (* initial challenge *)
           let l =
             ( match ss.srealm with
                 | None -> []
                 | Some realm -> "realm=" ^ qstring realm
             ) @
             [ "nonce=" ^ qstring ss.snonce;
               "qpop=auth"
             ] @
             ( if ss.sstale then [ "stale=true" ] else [] ) @
             [ "charset=utf-8";
               "algorithm=md5-sess";
             ] in
           ss.sstate <- `Wait;
           ss.sstale <- false;
           String.concat "," l
      | Some(_,_,srv_resp) ->
           (* second message *)
           srv_resp

  let to_strmap l =
    (* will raise Not_found if a key appears twice *)
    List.fold_left
      (fun (m,s) (name,value) ->
         if StrSet.mem name s then raise Not_found;
         (StrMap.add name value m, StrSet.add name s)
      )
      (StrMap.empty, StrSet.empty)
      l

  let nc_re =
    let hex = "[0-9a-f]" in
    Netstring_str.regexp (hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ "$")

  let get_nc s =
    match Netstring_str.string_match nc_re s 0 with
      | None ->
           raise Not_found
      | Some _ ->
           ( try int_of_string ("0x" ^ s)
             with Failure _ -> raise Not_found
           )

  let decode_response msg =
    let m = to_strmap (parse_message msg) in
    let user = StrMap.find "username" m in
    let realm = try StrMap.find "realm" m with Not_found -> "" in
    let nonce = StrMap.find "nonce" m in
    let cnonce = StrMap.find "cnonce" m in
    let nc_str = StrMap.find "nc" m in
    let nc = get_nc nc_str in
    let qop = try StrMap.find "qop" m with Not_found -> "auth" in
    if qop <> "auth" then raise Not_found;
    let digest_uri = StrMap.find "digest-uri" m in
    let response = StrMap.find "response" m in
    let utf8 =
      if StrMap.mem "charset" m then (
        let v = StrMap.find "charset" m in
        if v <> "utf-8" then raise Not_found;
        true
      )
      else
        false in
    let authz =
      try Some(StrMap.find "authzid" m) with Not_found -> None in
    let r =
      { r_user = user;
        r_authz = authz;
        r_realm = realm;
        r_nonce = nonce;
        r_cnonce = cnonce;
        r_nc = nc;
        r_digest_uri = digest_uri;
        r_utf8 = utf8
      } in
    (r, response)

  let validate_response ss r response =
    let user_utf8 = to_utf8 r.r_utf8 r.r_user in
    verify_utf8 r.r_authz;
    let password_utf8 =
      match ss.lookup user_utf8 r.r_authz with
        | None ->
             raise Not_found
        | Some creds ->
             Netsys_sasl_util.extract_password creds in
    let password = to_client r.r_utf8 password_utf8 in
    let expected_response = compute_response r password "AUTHENTICATE:" in
    if response <> expected_response then raise Not_found;
    ()

  exception Restart of string

  let server_process_response ss msg =
    try
      let (r, response) = decode_response msg in
      if r.r_nc <> ss.snextnc then raise Not_found;
      if r.r_nc > 1 then raise(Restart nonce);
      if ss.sstate <> `Wait then raise Not_found;
      validate_response ss r response;
      (* success: *)
      let srv_response = compute_response r password ":" in
      ss.snextnc <- new_r.r_nc + 1;
      ss.sresponse <- Some(r, response, srv_response);
      ss.sstate <- `Emit;
    with
      | Nethttp.Bad_header_field _  (* from parse_message *)
      | Not_found ->
           ss.sstate <- `Auth_error
      | Restart id ->
           ss.sstate <- `Restart id

  let server_process_response_restart ss msg set_stale =
    let state_ok =
      match ss.state with
        | `Restart id -> ss.snonce = id && ss.sstate = `OK
        | _ -> false in
    if not state_ok then
      failwith "Netmech_digestmd5_sasl.server_process_response_restart: \
                bad state";
    try
      let old_r =
        match ss.sresponse with
          | None -> assert false
          | Some (r, _, _) -> r in
      let (r, response) = decode_response msg in
      if old_r.r_user <> new_r.r_user
         || old_r.r_authz <> new_r.r_authz
         || old_r.r_realm <> new_r.r_realm
         || old_r.r_nonce <> new_r.r_nonce
         || old_r.r_cnonce <> new_r.r_cnonce
         || old_r.r_nc + 1 <> new_r.r_nc
         || old_r.r_digest_uri <> new_r.r_digest_uri
         || old_r.r_utf8 <> new_r.r_utf8 then raise Not_found;
      validate_response ss r response;
      (* success *)
      if set_stale then (
        ss.sstale <- true;
        raise Not_found
      ) else (
        let srv_response = compute_response r password ":" in
        ss.snextnc <- new_r.r_nc + 1;
        ss.sresponse <- Some(r, response, srv_response);
        ss.sstate <- `Emit;
        true
      )
    with
      | Not_found ->
           ss.nonce <- create_nonce();
           ss.snextnc <- 1;
           ss.sresponce <- None;
           ss.sstate <- `Emit;
           false

             
  let server_channel_binding ss =
    `None

  let server_stash_session ss =
    let tuple =
      (ss.sstate, ss.sresponse, ss.snextnc, ss.sstale, ss.srealm, ss.snonce) in
    "server,t=DIGEST-MD5;" ^ 
      Marshal.to_string tuple []

  let ss_re = 
    Netstring_str.regexp "server,t=DIGEST-MD5;"

  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_digestmd5_sasl.server_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let (sstate, sresponse, snextnc, sstale, srealm, snonce) =
             Marshal.from_string data 0 in
           { sstate;
             sresponse;
             snextnc;
             sstale;
             srealm;
             snonce;
             lookup
           }

  let server_session_id ss =
    Some ss.snonce

  let server_prop ss key =
    (* TODO: digest_uri, ... *)
    raise Not_found

  let server_user ss =
    match ss.suser with
      | None -> raise Not_found
      | Some name -> name

  let server_authz ss =
    match ss.sauthz with
      | None -> raise Not_found
      | Some name -> name

  type client_session =
      { mutable cstate : Netsys_sasl_types.client_state;
        cuser : string;
        cauthz : string;
        cpasswd : string;
      }

  let create_client_session ~user ~authz ~creds ~params () =
    let _params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_client_session:"
        []
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_digestmd5_sasl.create_client_session: no password \
                  found in credentials" in
    { cstate = `Emit;
      cuser = user;
      cauthz = authz;
      cpasswd = pw;
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_digestmd5_sasl.client_configure_channel_binding: \
                not supported"

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_digestmd5_sasl.client_restart: unfinished auth";
    XXX

  let client_process_challenge cs msg =
    XXX

  let client_emit_response cs =
    if cs.cstate <> `Emit then
      failwith "Netmech_digestmd5_sasl.client_emit_response: bad state";
    XXX

  let client_stash_session cs =
    "client,t=DIGEST-MD5;" ^ 
      Marshal.to_string cs []

  let cs_re = 
    Netstring_str.regexp "client,t=DIGEST-MD5;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_digestmd5_sasl.client_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let cs = Marshal.from_string data 0 in
           (cs : client_session)
    
  let client_session_id cs =
    None
      
  let client_prop cs key =
    (* TODO: realm, stale ... *)
    raise Not_found

  let client_user_name cs =
    cs.cuser

  let client_authz_name cs =
    cs.cauthz
end
