(* $Id$ *)

open Printf

module type PROFILE = 
  sig
    val hash_function : Netsys_digests.iana_hash_fn
    val iteration_count_limit : int
    val announce_channel_binding : bool
  end

module SHA1 = struct
  let hash_function = `SHA_1
  let iteration_count_limit = 100000
  let announce_channel_binding = false
end

module SHA1_PLUS = struct
  let hash_function = `SHA_1
  let iteration_count_limit = 100000
  let announce_channel_binding = true
end

module SHA256 = struct
  let hash_function = `SHA_256
  let iteration_count_limit = 100000
  let announce_channel_binding = false
end

module SHA256_PLUS = struct
  let hash_function = `SHA_256
  let iteration_count_limit = 100000
  let announce_channel_binding = true
end

module SCRAM(P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM = struct

  let profile =
    let open Netmech_scram in
    { ptype = `SASL;
      hash_function = P.hash_function;
      return_unknown_user = false;
        (* The SASL API does not allow to indicate unknown users anyway *)
      iteration_count_limit = P.iteration_count_limit;
    }

  let default_iteration_count = 4096

  let basic_mname =
    Netmech_scram.mechanism_name profile

  let mechanism_name =
    if P.announce_channel_binding then
      basic_mname ^ "-PLUS"
    else
      basic_mname

  let client_first = `Required
  let server_sends_final_data = true
  let supports_authz = true

  let available() =
    try ignore(Netsys_digests.iana_find P.hash_function);
        true
    with Not_found -> false


  type credentials =
      (string * string * (string * string) list) list


  let init_credentials l =
    (l:credentials)

  let extract_password = Netsys_sasl_util.extract_password

  let colon_re = Netstring_str.regexp ":"

  let colon_split = Netstring_str.split colon_re

  let extract_credentials ~fallback_i (c:credentials) =
    try
      let (_, value, params) =
        List.find
          (function
            | (n, _, _) -> 
                n = "authPassword-" ^ basic_mname
          )
          c in
      let info = List.assoc "info" params in
      let (st_key, srv_key) =
        match colon_split value with
          | [ st_key; srv_key ] ->
               ( try
                   Netencoding.Base64.decode st_key,
                   Netencoding.Base64.decode srv_key
                 with Invalid_argument _ -> raise Not_found
               )
          | _ -> raise Not_found in
      let (i, salt) =
        match colon_split info with
          | [ istr; salt ] ->
               ( try
                   int_of_string istr,
                   Netencoding.Base64.decode salt
                 with Invalid_argument _ | Failure _ -> raise Not_found
               )
          | _ -> raise Not_found in
      `Stored_creds(st_key,srv_key,salt,i)
    with
      | Not_found ->
           let pw = extract_password c in
           let salt = Netmech_scram.create_salt() in
           let i = fallback_i in
           let h = profile.Netmech_scram.hash_function in
           let (st_key, srv_key) = Netmech_scram.stored_key h pw salt i in
           `Stored_creds(st_key,srv_key,salt,i)

  type server_session =
      { ss : Netmech_scram.server_session;
        ss_fallback_i : int;
        ss_cb : (string * string) list;
        mutable ss_cb_ok : bool option;
      }

  let check_channel_binding ss =
    match ss.ss_cb_ok with
      | None ->
          let flag =
           match Netmech_scram.server_channel_binding ss.ss with
              | `None
              | `SASL_none_but_advertise ->
                  not (P.announce_channel_binding)
              | `SASL_require(ty,data) ->
                  P.announce_channel_binding && (
                    try
                      let exp_data = List.assoc ty ss.ss_cb in
                      data = exp_data
                    with
                      | Not_found -> false
                  )
              | `GSSAPI _ ->
                  assert false in
          ss.ss_cb_ok <- Some flag;
          flag
      | Some flag ->
          flag


  let server_state ss =
    if Netmech_scram.server_emit_flag ss.ss then
      `Emit
    else if Netmech_scram.server_recv_flag ss.ss then
      `Wait
    else if Netmech_scram.server_finish_flag ss.ss then (
      if check_channel_binding ss then
        `OK
      else
        `Auth_error "bad channel binding"
    )
    else if Netmech_scram.server_error_flag ss.ss then
      `Auth_error "SCRAM error"
    else
      assert false

  let scram_auth fallback_i lookup =
    (fun user authz ->
       match lookup user authz with
         | None ->
              raise Not_found
         | Some creds ->
              extract_credentials ~fallback_i creds  (* or Not_found *)
    )

  let server_known_params = [ "i"; "nonce"; "mutual"; "secure" ]

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_scram_sasl.create_server_session:"
        server_known_params
        params in
    let fallback_i =
      try int_of_string (List.assoc "i" params)
      with Not_found -> default_iteration_count in
    let ss =
      Netmech_scram.create_server_session2
        ?nonce:(try Some(List.assoc "nonce" params) with Not_found -> None)
        profile
        (scram_auth fallback_i lookup) in
    { ss;
      ss_fallback_i = fallback_i;
      ss_cb = [];
      ss_cb_ok = None;
    }

  let server_configure_channel_binding ss cb_list =
    { ss with ss_cb = cb_list }


  let server_process_response ss msg =
    { ss with ss = Netmech_scram.server_recv_message ss.ss msg }

  let server_process_response_restart ss msg set_stale =
    failwith "Netmech_scram_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    let s, msg = Netmech_scram.server_emit_message ss.ss in
    { ss with ss = s }, msg

  let server_channel_binding ss =
    Netmech_scram.server_channel_binding ss.ss
                                      
  let server_stash_session ss =
    sprintf "server,t=SCRAM,%s"
      (Marshal.to_string (Netmech_scram.server_export ss.ss,
                          ss.ss_fallback_i, ss.ss_cb, ss.ss_cb_ok) [])

    
  let ss_re = Netstring_str.regexp "server,t=SCRAM,"
  
  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_scram_sasl.server_resume_session"
      | Some m ->
          let p = Netstring_str.match_end m in
          let data = String.sub s p (String.length s - p) in
          let (scram_data, ss_fallback_i, ss_cb, ss_cb_ok) =
            Marshal.from_string data 0 in 
          let auth = scram_auth ss_fallback_i lookup in
          let ss = Netmech_scram.server_import_any2 scram_data auth in
          { ss; ss_fallback_i; ss_cb; ss_cb_ok }

  let server_session_id ss =
    None
      
  let server_prop ss key =
    Netmech_scram.server_prop ss.ss key

  let server_gssapi_props ss =
    raise Not_found

  let server_user_name ss =
    match Netmech_scram.server_user_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  let server_authz_name ss =
    match Netmech_scram.server_authz_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  type client_session = Netmech_scram.client_session

  let client_state cs =
    if Netmech_scram.client_emit_flag cs then
      `Emit
    else if Netmech_scram.client_recv_flag cs then
      `Wait
    else if Netmech_scram.client_finish_flag cs then
      `OK
    else
      match Netmech_scram.client_error_flag cs with
        | Some error ->
            `Auth_error (Netmech_scram.error_of_exn error)
        | None ->
            assert false
      
  let client_known_params = [ "nonce"; "mutual"; "secure" ]

  let create_client_session ~user ~authz ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_scram_sasl.create_client_session:"
        client_known_params
        params in
    let pw =
      try extract_password creds
      with Not_found ->
        failwith "Netmech_scram_sasl.create_client_session: no password \
                  found in credentials" in
    Netmech_scram.create_client_session2
      ?nonce:(try Some(List.assoc "nonce" params) with Not_found -> None)
      profile
      user
      authz
      pw

  let client_configure_channel_binding cs cb =
    Netmech_scram.client_configure_channel_binding cs cb
      
  let client_channel_binding cs =
    Netmech_scram.client_channel_binding cs

  let client_restart cs =
    if client_state cs <> `OK then
      failwith "Netmech_scram_sasl.client_restart: unfinished auth";
    let user = Netmech_scram.client_user_name cs in
    let authz = Netmech_scram.client_authz_name cs in
    let pw = Netmech_scram.client_password cs in
    Netmech_scram.create_client_session2
      profile
      user
      authz
      pw

  let client_process_challenge cs msg =
    Netmech_scram.client_recv_message cs msg
                                      
  let client_emit_response cs =
    Netmech_scram.client_emit_message cs
                                      
  let client_stash_session cs =
    "client,t=SCRAM;" ^ 
      Netmech_scram.client_export cs
      
  let cs_re = Netstring_str.regexp "client,t=SCRAM;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_scram_sasl.client_resume_session"
      | Some m ->
           let data_pos = Netstring_str.match_end m in
           let data = String.sub s data_pos (String.length s - data_pos) in
           Netmech_scram.client_import data
      
  let client_session_id cs =
    None
      
  let client_prop cs key =
    Netmech_scram.client_prop cs key

  let client_gssapi_props cs =
    raise Not_found

  let client_user_name cs =
    Netmech_scram.client_user_name cs

  let client_authz_name cs =
    Netmech_scram.client_authz_name cs
end


module SCRAM_SHA1 = SCRAM(SHA1)
module SCRAM_SHA1_PLUS = SCRAM(SHA1_PLUS)
module SCRAM_SHA256 = SCRAM(SHA256)
module SCRAM_SHA256_PLUS = SCRAM(SHA256_PLUS)


(*
#use "topfind";;
#require "netclient,nettls-gnutls";;
Netpop.Debug.enable := true;;
let addr =
    `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "office1", 110),
            Uq_client.default_connect_options);;
let client = new Netpop.connect addr 60.0;;

module S = Netmech_scram_sasl.SCRAM_SHA1;;

let password = "xxx";;

Netpop.authenticate
  ~sasl_mechs:[ (module S)
              ]
  ~user:"gerd"
  ~creds:[ "password", password, [] ]
  ~sasl_params:[]
  client;;


 *)
