(* $Id$ *)

(* TODO: add saslprep to at least the server, so far we have it *)

let next_challenge = ref None  (* testing *)

let override_challenge s =
  next_challenge := Some s

module CRAM_MD5 : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "CRAM-MD5"
  let client_first = `No
  let server_sends_final_data = false
  let supports_authz = false

  type credentials =
      (string * string * (string * string) list) list

  let init_credentials l =
    (l:credentials)

  type server_session = 
      { mutable sstate : Netsys_sasl_types.server_state;
        schallenge : string;
        mutable suser : string option;
        lookup : string -> string -> credentials option;
      }

  let server_state ss = ss.sstate

  let create_server_session ~lookup ~params () =
    let _params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_crammd5_sasl.create_server_session:"
        []
        params in
    let r = String.create 16 in
    Netsys_rng.fill_random r;
    let c1 = Netencoding.to_hex ~lc:true r in
    let c =
      match !next_challenge with
        | None -> c1
        | Some c -> c in
    next_challenge := None;
    { sstate = `Emit;
      schallenge = "<" ^ c ^ ">";
      suser = None;
      lookup
    }

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
    with _ -> raise Not_found

  let server_process_response ss msg =
    try
      if ss.sstate <> `Wait then raise Not_found;
      let n = String.length msg in
      let k1 = String.rindex msg ' ' in
      let user = String.sub msg 0 k1 in
      let resp = String.sub msg (k1+1) (n-k1-1) in
      let expected_password =
        match ss.lookup user "" with
          | None ->
               raise Not_found
          | Some creds ->
               Netsys_sasl_util.extract_password creds in
      let expected_msg =
        compute_response user expected_password ss.schallenge in
      if msg <> expected_msg then raise Not_found;
      verify_utf8 user;
      verify_utf8 expected_password;
      ss.sstate <- `OK;
      ss.suser <- Some user;
    with
      | Not_found ->
           ss.sstate <- `Auth_error

  let server_process_response_restart ss msg set_stale =
    failwith "Netmech_crammd5_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    let data = ss.schallenge in
    ss.sstate <- `Wait;
    data

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

  let server_user ss =
    match ss.suser with
      | None -> raise Not_found
      | Some name -> name

  let server_authz ss =
    ""

  type client_session =
      { mutable cstate : Netsys_sasl_types.client_state;
        mutable cresp : string;
        cuser : string;
        cauthz : string;
        cpasswd : string;
      }

  let create_client_session ~user ~authz ~creds ~params () =
    let _params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_crammd5_sasl.create_client_session:"
        []
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_crammd5_sasl.create_client_session: no password \
                  found in credentials" in
    { cstate = `Wait;
      cresp = "";
      cuser = user;
      cauthz = authz;
      cpasswd = pw;
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_crammd5_sasl.client_configure_channel_binding: \
                not supported"

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_crammd5_sasl.client_restart: unfinished auth";
    cs.cstate <- `Wait

  let client_process_challenge cs msg =
    if cs.cstate <> `Wait then
      cs.cstate <- `Auth_error
    else (
      cs.cresp <- compute_response cs.cuser cs.cpasswd msg;
      cs.cstate <- `Emit;
    )

  let client_emit_response cs =
    if cs.cstate <> `Emit then
      failwith "Netmech_crammd5_sasl.client_emit_response: bad state";
    cs.cstate <- `OK;
    cs.cresp

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

  let client_user_name cs =
    cs.cuser

  let client_authz_name cs =
    ""
end
