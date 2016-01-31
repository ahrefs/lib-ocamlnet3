(* $Id$ *)

(* Unit tests: tests/netstring/bench/test_netmech.ml *)

module PLAIN : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "PLAIN"
  let client_first = `Required
  let server_sends_final_data = false
  let supports_authz = true
  let available() = true

  type credentials =
      (string * string * (string * string) list) list

  let init_credentials l =
    (l:credentials)

  type server_session = 
      { sstate : Netsys_sasl_types.server_state;
        suser : string option;
        sauthz : string option;
        lookup : string -> string -> credentials option;
      }

  let server_state ss = ss.sstate

  let no_mutual = "The PLAIN mechanism does not support mutual authentication"
  let no_secure = "The PLAIN mechanism is not a secure mechanism"

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_plain_sasl.create_server_session:"
        [ "mutual"; "secure" ]
        params in
    let req_mutual =
      try List.assoc "mutual" params = "true" with Not_found -> false in
    let req_secure =
      try List.assoc "secure" params = "true" with Not_found -> false in
    { sstate = ( if req_mutual then `Auth_error no_mutual
                 else if req_secure then `Auth_error no_secure
                 else `Wait
               );
      suser = None;
      sauthz = None;
      lookup
    }

  let server_configure_channel_binding ss cb_list =
    failwith "Netmach_plain_sasl.server_configure_channel_binding: \
              not supported"

  let verify_utf8 s =
    try
      Netconversion.verify `Enc_utf8 s
    with _ -> failwith "UTF-8 mismatch"

  let server_process_response ss msg =
    try
      if ss.sstate <> `Wait then failwith "protocol error";
      let n = String.length msg in
      let k1 = String.index_from msg 0 '\000' in
      if k1 = n-1 then raise Not_found;
      let k2 = String.index_from msg (k1+1) '\000' in
      let authz = String.sub msg 0 k1 in
      let user = String.sub msg (k1+1) (k2-k1-1) in
      let passwd = String.sub msg (k2+1) (n-k2-1) in
      verify_utf8 authz;
      verify_utf8 user;
      verify_utf8 passwd;
      match ss.lookup user authz with
        | None ->
             failwith "unknown user"
        | Some creds ->
             let expected_passwd = Netsys_sasl_util.extract_password creds in
             if passwd <> expected_passwd then failwith "bad password";
             { ss with
               sstate = `OK;
               suser = Some user;
               sauthz = Some authz;
             }
    with
      | Failure msg ->
           { ss with sstate = `Auth_error msg }

  let server_process_response_restart ss msg set_stale =
    failwith "Netmech_plain_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    failwith "Netmech_plain_sasl.server_emit_challenge: no challenge"

  let server_channel_binding ss =
    `None

  let server_stash_session ss =
    "server,t=PLAIN;" ^ 
      Marshal.to_string (ss.sstate, ss.suser, ss.sauthz) []

  let ss_re = 
    Netstring_str.regexp "server,t=PLAIN;"

  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_plain_sasl.server_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let (state,user,authz) = Marshal.from_string data 0 in
           { sstate = state;
             suser = user;
             sauthz = authz;
             lookup
           }

  let server_session_id ss =
    None

  let server_prop ss key =
    raise Not_found

  let server_gssapi_props ss =
    raise Not_found

  let server_user_name ss =
    match ss.suser with
      | None -> raise Not_found
      | Some name -> name

  let server_authz_name ss =
    match ss.sauthz with
      | None -> raise Not_found
      | Some name -> name

  type client_session =
      { cstate : Netsys_sasl_types.client_state;
        cuser : string;
        cauthz : string;
        cpasswd : string;
      }

  let create_client_session ~user ~authz ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_plain_sasl.create_client_session:"
        [ "mutual"; "secure" ]
        params in
    let req_mutual =
      try List.assoc "mutual" params = "true" with Not_found -> false in
    let req_secure =
      try List.assoc "secure" params = "true" with Not_found -> false in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_plain_sasl.create_client_session: no password \
                  found in credentials" in
    { cstate = ( if req_mutual then `Auth_error no_mutual
                 else if req_secure then `Auth_error no_secure
                 else `Emit
               );
      cuser = user;
      cauthz = authz;
      cpasswd = pw;
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_plain_sasl.client_configure_channel_binding: \
                not supported"
    else
      cs

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_plain_sasl.client_restart: unfinished auth";
    { cs with cstate = `Emit }

  let client_process_challenge cs msg =
    { cs with cstate = `Auth_error "protocol error" }

  let client_emit_response cs =
    if cs.cstate <> `Emit then
      failwith "Netmech_plain_sasl.client_emit_response: bad state";
    ( { cs with 
        cstate = `OK;
      },
      cs.cauthz ^ "\000" ^ cs.cuser ^ "\000" ^ cs.cpasswd
    )

  let client_stash_session cs =
    "client,t=PLAIN;" ^ 
      Marshal.to_string cs []

  let cs_re = 
    Netstring_str.regexp "client,t=PLAIN;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_plain_sasl.client_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let cs = Marshal.from_string data 0 in
           (cs : client_session)
    
  let client_session_id cs =
    None
      
  let client_prop cs key =
    raise Not_found

  let client_gssapi_props cs =
    raise Not_found

  let client_user_name cs =
    cs.cuser

  let client_authz_name cs =
    cs.cauthz
end
