(* $Id$ *)

module type PROFILE = 
  sig
    val hash_function : Netsys_digest.iana_hash_fn
    val return_unknown_user : bool
    val iteration_count_limit : int
  end

module SHA1 = struct
  let hash_function = `SHA_1
  let return_unknown_user = true
  let iteration_count_limit = 100000
end

module SCRAM(P:PROFILE) = struct
  let profile =
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
      (string * string * (string * string)) list


  let init_credentials l =
    (l:credentials)

  let extract_password (c:credentials) =
    let (_, value, _) =
      List.find
        (function
          | ("password", _, _) -> true
          | _ -> false
        )
        c

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

  type server_state =
    [ `Wait | `Emit | `OK | `Auth_error | `Restart of string ]
      
  type server_session =
      { ss : Netmech_scram.server_session;
        ss_fallback_i : int;
      }

  let server_state ss =
    XXX

  let create_server_session ~lookup ~params () =
    let fallback_i =
      try int_of_string (List.assoc "i" params)
      with Not_found -> default_iteration_count in
    let ss =
      Netmech_scram.create_server_session
        profile
        (fun user authz ->
           match lookup user authz with
             | None ->
                  raise Not_found
             | Some creds ->
                  extract_salted_password ~fallback_i creds
        ) in
    

    let server_process_response ss msg =
      Netmech_scram.server_recv_message ss.ss msg

    let server_process_response_restart ss msg =
      failwith "Netmech_scram_sasl.server_process_response_restart: \
                not available"

    let server_emit_challenge ss =
      Netmech_scram.server_emit_message ss.ss

    let server_stash_session ss =
      XXX

    let server_resume_session ~lookup s =
      XX

    let server_session_id ss =
      XXX

    let server_prop ss key =
      XXX

    let server_user ss =
      XXX

    let server_authz ss =
      XXX

    type client_state =
           [ `Wait | `Emit | `OK | `Auth_error | `Stale ]


    type client_ssession =
        { cs : Netmech_scram.client_session;
        }

    let client_state cs =
      XXX

    let create_client_session ~user ~authz ~creds ~params () =
      XXX

    let client_restart cs =
      XXX

    let client_process_challenge cs msg =
      Netmech_scram.client_recv_message cs.cs msg

    let client_emit_response cs =
      Netmech_scram.client_emit_message cs.cs

    let client_stash_session cs =
      XX

    let client_resume_session s =
      XXX

    let client_session_id cs =
      XXX

    let client_prop cs key =
      XXX
end
