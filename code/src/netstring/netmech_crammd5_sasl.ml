(* $Id$ *)

(* TODO: add saslprep to at least the server, so far we have it *)

(* Unit tests: tests/netstring/bench/test_netmech.ml *)

let next_challenge = ref None  (* testing *)

let override_challenge s =
  next_challenge := Some s

module CRAM_MD5 : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "CRAM-MD5"
  let client_first = `No
  let server_sends_final_data = false
  let supports_authz = false
  let available() = true

  type credentials =
      (string * string * (string * string) list) list

  let init_credentials l =
    (l:credentials)

  type server_session = 
      { sstate : Netsys_sasl_types.server_state;
        schallenge : string;
        suser : string option;
        lookup : string -> string -> credentials option;
      }

  let server_state ss = ss.sstate

  let no_mutual =
    "The CRAM-MD5 mechanism does not support mutual authentication"

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_crammd5_sasl.create_server_session:"
        [ "mutual"; "secure" ]
        params in
    let req_mutual =
      try List.assoc "mutual" params = "true" with Not_found -> false in
    (* Ignore "secure" *)
    let r = Bytes.create 16 in
    Netsys_rng.fill_random r;
    let c1 = Netencoding.to_hex ~lc:true (Bytes.to_string r) in
    let c =
      match !next_challenge with
        | None -> c1
        | Some c -> c in
    next_challenge := None;
    { sstate = if req_mutual then `Auth_error no_mutual else `Emit;
      schallenge = "<" ^ c ^ ">";
      suser = None;
      lookup
    }

  let server_configure_channel_binding ss cb_list =
    failwith "Netmach_crammd5_sasl.server_configure_channel_binding: \
              not supported"

  let compute_response user password challenge =
    let k =
      if String.length password < 64 then
        password  (* padding is done by hmac anyway *)
      else
        Digest.string password in
    let r =
      Netauth.hmac
        ~h:Digest.string   (* MD5, actually *)
        ~b:64
        ~l:16
        ~k
        ~message:challenge in
    let r_hex = Netencoding.to_hex ~lc:true r in
    user ^ " " ^ r_hex


  let verify_utf8 s =
    try
      Netconversion.verify `Enc_utf8 s
    with _ -> failwith "UTF-8 mismatch"

  let server_process_response ss msg =
    try
      if ss.sstate <> `Wait then failwith "protocol error";
      (* let n = String.length msg in *)
      let k1 = String.rindex msg ' ' in
      let user = String.sub msg 0 k1 in
      (* let resp = String.sub msg (k1+1) (n-k1-1) in *)
      let expected_password =
        match ss.lookup user "" with
          | None ->
              failwith "unknown user"
          | Some creds ->
               Netsys_sasl_util.extract_password creds in
      let expected_msg =
        compute_response user expected_password ss.schallenge in
      if msg <> expected_msg then failwith "bad password";
      verify_utf8 user;
      verify_utf8 expected_password;
      { ss with
        sstate = `OK;
        suser = Some user;
      }
    with
      | Failure msg ->
           { ss with sstate = `Auth_error msg }

  let server_process_response_restart ss msg set_stale =
    failwith "Netmech_crammd5_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    if ss.sstate <> `Emit then
      failwith "Netmech_crammd5_sasl.server_emit_challenge: bad state";
    let data = ss.schallenge in
    ( { ss with sstate = `Wait },
      data
    )

  let server_channel_binding ss =
    `None

  let server_stash_session ss =
    "server,t=CRAM-MD5;" ^ 
      Marshal.to_string (ss.sstate, ss.schallenge, ss.suser) []

  let ss_re = 
    Netstring_str.regexp "server,t=CRAM-MD5;"

  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_crammd5_sasl.server_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let (state,chal,user) = Marshal.from_string data 0 in
           { sstate = state;
             suser = user;
             schallenge = chal;
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
    ""

  type client_session =
      { cstate : Netsys_sasl_types.client_state;
        cresp : string;
        cuser : string;
        cauthz : string;
        cpasswd : string;
      }

  let create_client_session ~user ~authz ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_crammd5_sasl.create_client_session:"
        [ "mutual"; "secure" ]
        params in
    let req_mutual =
      try List.assoc "mutual" params = "true" with Not_found -> false in
    (* Ignore "secure" *)
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_crammd5_sasl.create_client_session: no password \
                  found in credentials" in
    { cstate = if req_mutual then `Auth_error no_mutual else `Wait;
      cresp = "";
      cuser = user;
      cauthz = authz;
      cpasswd = pw;
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_crammd5_sasl.client_configure_channel_binding: \
                not supported"
    else
      cs

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_crammd5_sasl.client_restart: unfinished auth";
    { cs with cstate = `Wait }

  let client_process_challenge cs msg =
    if cs.cstate <> `Wait then
      { cs with cstate = `Auth_error "protocol error" }
    else
      { cs with
        cresp = compute_response cs.cuser cs.cpasswd msg;
        cstate = `Emit;
      }

  let client_emit_response cs =
    if cs.cstate <> `Emit then
      failwith "Netmech_crammd5_sasl.client_emit_response: bad state";
    ( { cs with cstate = `OK },
      cs.cresp
    )

  let client_stash_session cs =
    "client,t=CRAM-MD5;" ^ 
      Marshal.to_string cs []

  let cs_re = 
    Netstring_str.regexp "client,t=CRAM-MD5;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_crammd5_sasl.client_resume_session"
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
    ""
end
