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

  let mechanism_name =
    let n = Netmech_scram.mechanism_name profile in
    if P.announce_channel_binding then
      n ^ "-PLUS"
    else
      n

  let client_first = `Required
  let server_sends_final_data = true
  let supports_authz = true

  let available() =
    try ignore(Netsys_digests.iana_find profile.hash_function); true
    with Not_found -> false


  type credentials =
      (string * string * (string * string) list) list


  let init_credentials l =
    (l:credentials)

  let extract_password = Netsys_sasl_util.extract_password

  let extract_salted_password ~fallback_i (c:credentials) =
    try
      let (_, value, params) =
        List.find
          (function
            | ("SCRAM-salted-password", _, _) -> true
            | _ -> false
          )
          c in
      let salt = List.assoc "salt" params in
      let i = 
        try int_of_string (List.assoc "i" params)
        with _ -> raise Not_found in
      (value, salt, i)
    with
      | Not_found ->
           let pw = extract_password c in
           let salt = Netmech_scram.create_salt() in
           let i = fallback_i in
           let h = profile.Netmech_scram.hash_function in
           let value = Netmech_scram.salt_password h pw salt i in
           (value, salt, i)

  type server_session =
      { ss : Netmech_scram.server_session;
        ss_fallback_i : int;
      }

  let server_state ss =
    if Netmech_scram.server_emit_flag ss.ss then
      `Emit
    else if Netmech_scram.server_recv_flag ss.ss then
      `Wait
    else if Netmech_scram.server_finish_flag ss.ss then
      `OK
    else if Netmech_scram.server_error_flag ss.ss then
      `Auth_error
    else
      assert false

  let scram_auth fallback_i lookup =
    (fun user authz ->
       match lookup user authz with
         | None ->
              raise Not_found
         | Some creds ->
              extract_salted_password ~fallback_i creds  (* or Not_found *)
    )

  let server_known_params = [ "i" ]

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
        profile
        (scram_auth fallback_i lookup) in
    { ss;
      ss_fallback_i = fallback_i
    }

  let server_process_response ss msg =
    Netmech_scram.server_recv_message ss.ss msg

  let server_process_response_restart ss msg set_stale =
    failwith "Netmech_scram_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    Netmech_scram.server_emit_message ss.ss

  let server_channel_binding ss =
    Netmech_scram.server_channel_binding ss.ss
                                      
  let server_stash_session ss =
    sprintf "server,t=SCRAM,i=%d;" ss.ss_fallback_i ^ 
      Netmech_scram.server_export ss.ss
    
  let ss_re = Netstring_str.regexp "server,t=SCRAM,i=\\([^,;]*\\);"
  
  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_scram_sasl.server_resume_session"
      | Some m ->
           let ss_fallback_i =
             try
               int_of_string (Netstring_str.matched_group m 1 s)
             with _ -> 
               failwith "Netmech_scram_sasl.server_resume_session" in
           let data_pos = Netstring_str.match_end m in
           let data = String.sub s data_pos (String.length s - data_pos) in
           let auth = scram_auth ss_fallback_i lookup in
           let ss = Netmech_scram.server_import_any2 data auth in
           { ss;
             ss_fallback_i;
           }

  let server_session_id ss =
    (* FIXME: nonce could be used *)
    None
      
  let server_prop ss key =
    (* FIXME: export parameters *)
    raise Not_found

  let server_user_name ss =
    match Netmech_scram.server_user_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  let server_authz_name ss =
    match Netmech_scram.server_authz_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  type client_session =
      { mutable cs : Netmech_scram.client_session;
      }

  let client_state cs =
    if Netmech_scram.client_emit_flag cs.cs then
      `Emit
    else if Netmech_scram.client_recv_flag cs.cs then
      `Wait
    else if Netmech_scram.client_finish_flag cs.cs then
      `OK
    else if Netmech_scram.client_error_flag cs.cs then
      `Auth_error
    else
      assert false
      
  let client_known_params = []

  let create_client_session ~user ~authz ~creds ~params () =
    let _params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_scram_sasl.create_client_session:"
        client_known_params
        params in
    let pw =
      try extract_password creds
      with Not_found ->
        failwith "Netmech_scram_sasl.create_client_session: no password \
                  found in credentials" in
    let cs =
      Netmech_scram.create_client_session2
        profile
        user
        authz
        pw in
    { cs }

  let client_configure_channel_binding cs cb =
    Netmech_scram.client_configure_channel_binding cs.cs cb
      
  let client_channel_binding cs =
    Netmech_scram.client_channel_binding cs.cs

  let client_restart cs =
    if client_state cs <> `OK then
      failwith "Netmech_scram_sasl.client_restart: unfinished auth";
    let user = Netmech_scram.client_user_name cs.cs in
    let authz = Netmech_scram.client_authz_name cs.cs in
    let pw = Netmech_scram.client_password cs.cs in
    let new_cs =
      Netmech_scram.create_client_session2
        profile
        user
        authz
        pw in
    cs.cs <- new_cs
      
  let client_process_challenge cs msg =
    Netmech_scram.client_recv_message cs.cs msg
                                      
  let client_emit_response cs =
    Netmech_scram.client_emit_message cs.cs
                                      
  let client_stash_session cs =
    "client,t=SCRAM;" ^ 
      Netmech_scram.client_export cs.cs
      
  let cs_re = Netstring_str.regexp "client,t=SCRAM;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_scram_sasl.client_resume_session"
      | Some m ->
           let data_pos = Netstring_str.match_end m in
           let data = String.sub s data_pos (String.length s - data_pos) in
           { cs = Netmech_scram.client_import data }
      
  let client_session_id cs =
    (* FIXME: use nonce *)
    None
      
  let client_prop cs key =
    (* FIXME *)
    raise Not_found

  let client_user_name cs =
    Netmech_scram.client_user_name cs.cs

  let client_authz_name cs =
    Netmech_scram.client_authz_name cs.cs
end


module SCRAM_SHA1 = SCRAM(SHA1)
module SCRAM_SHA1_PLUS = SCRAM(SHA1_PLUS)
