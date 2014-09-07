(* $Id$ *)

open Printf

module type PROFILE = 
  sig
    val hash_function : Netsys_digests.iana_hash_fn
    val return_unknown_user : bool
    val iteration_count_limit : int
  end

module SHA1_permissive = struct
  let hash_function = `SHA_1
  let return_unknown_user = true
  let iteration_count_limit = 100000
end

module SHA1_restrictive = struct
  let hash_function = `SHA_1
  let return_unknown_user = false
  let iteration_count_limit = 100000
end

module SCRAM(P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM = struct

  let profile =
    let open Netmech_scram in
    { ptype = `SASL;
      hash_function = P.hash_function;
      return_unknown_user = P.return_unknown_user;
      iteration_count_limit = P.iteration_count_limit;
    }

  let default_iteration_count = 4096

  let mechanism_name =
    Netmech_scram.mechanism_name profile

  let client_first = `Required
  let server_sends_final_data = true
  let supports_authz = true
  let plus_channel_binding = false
       (* this describes the non-PLUS variant *)

  type credentials =
      (string * string * (string * string) list) list


  let init_credentials l =
    (l:credentials)

  let extract_password (c:credentials) =
    let (_, value, _) =
      List.find
        (function
          | ("password", _, _) -> true
          | _ -> false
        )
        c in
    value

  let extract_salted_password ~fallback_i (c:credentials) =
    try
      let (_, value, params) =
        List.find
          (function
            | ("salted-password", _, _) -> true
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
           let value = Netmech_scram.salt_password profile pw salt i in
           (value, salt, i)

  type server_session =
      { ss : Netmech_scram.server_session;
        ss_fallback_i : int;
      }

  type server_state =
    [ `Wait | `Emit | `OK | `Auth_error | `Restart of string ]
      
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
    List.iter
      (fun (name,_,critical) ->
         if critical && not(List.mem name server_known_params) then
           failwith ("Netmech_scram_sasl.create_server_session: Cannot \
                      process critical parameter: " ^ name)
      )
      params;
    let params = List.map (fun (n,v,_) -> (n,v)) params in
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

  let server_process_response_restart ss msg =
    failwith "Netmech_scram_sasl.server_process_response_restart: \
              not available"
             
  let server_emit_challenge ss =
    Netmech_scram.server_emit_message ss.ss

  let server_channel_binding ss =
    Netmech_scram.server_channel_binding ss.ss
                                      
  let server_stash_session ss =
    sprintf "t=SCRAM,i=%d;" ss.ss_fallback_i ^ 
      Netmech_scram.server_export ss.ss
    
  let ss_re = Netstring_str.regexp "t=SCRAM,i=\\([^,;]*\\);"
  
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

  let server_user ss =
    match Netmech_scram.server_user_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  let server_authz ss =
    match Netmech_scram.server_authz_name ss.ss with
      | None -> raise Not_found
      | Some name -> name
      
  type client_session =
      { mutable cs : Netmech_scram.client_session;
      }

  type client_state =
    [ `Wait | `Emit | `OK | `Auth_error | `Stale ]


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
    List.iter
      (fun (name,_,critical) ->
         if critical && not(List.mem name client_known_params) then
           failwith ("Netmech_scram_sasl.create_client_session: Cannot \
                      process critical parameter: " ^ name)
      )
      params;
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
    Netmech_scram.client_export cs.cs
      
  let client_resume_session s =
    { cs = Netmech_scram.client_import s }
      
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
