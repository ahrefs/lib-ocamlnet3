open Printf

module type PROFILE =
  sig
    val mutual : bool
    val hash_function : Netsys_digests.iana_hash_fn
  end

module Make_digest(P:PROFILE) : Nethttp.HTTP_MECHANISM =
  struct
    let profile =
      { Netmech_scram.ptype = `SASL;
        hash_function = P.hash_function;
        return_unknown_user = false;
        iteration_count_limit = 65536;
      }

    let hash_available iana_name =
      iana_name = `MD5 ||
        ( try ignore(Netsys_digests.iana_find iana_name); true
          with Not_found -> false
        )

    let mechanism_name = "SCRAM"
    let available() = hash_available P.hash_function
    let restart_supported = false (* TODO *)

  type credentials =
      (string * string * (string * string) list) list

  type client_session =
    { mutable sid : string option;
      mutable data : Netmech_scram.client_session;
      mutable realm_accepted : string option;
      mutable realm_actual : string option;
      mutable realm_tosend : string option;
      mutable error : bool;
    }

  let init_credentials l =
    (l:credentials)

  let client_state cs =
    if Netmech_scram.client_finish_flag cs.data then
      `OK
    else if cs.error || Netmech_scram.client_error_flag cs.data then
      `Auth_error "SCRAM protocol error"
    else if cs.realm_actual = None then
      `Wait
    else if Netmech_scram.client_emit_flag cs.data then
      `Emit
    else if Netmech_scram.client_recv_flag cs.data then
      `Wait
    else
      assert false

  let create_client_session ~user ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_scram_http.create_client_session:"
        [ "realm" ]
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_scram_http.create_client_session: no password \
                  found in credentials" in
    { sid = None;
      data = Netmech_scram.create_client_session profile user pw;
      realm_accepted = (try Some(List.assoc "realm" params)
                        with Not_found -> None);
      realm_actual = None;
      realm_tosend = None;
      error = false
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_scram_http.client_configure_channel_binding: \
                not supported"

  let client_channel_binding cs = `None

  let client_restart ~params cs =
    failwith "Netmech_scram_http.client_restart: not supported"

  let decode_params l =  (* params are always already decoded *)
    List.map
      (function
        | (n, `Q _) -> assert false
        | (n, `V v) -> (n,v)
      )
      l

  let client_match ~params (ch_name, ch_params) =
    try
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_scram_http.create_client_session:"
          [ "realm" ]
          params in
      let ch_params = decode_params ch_params in

      if String.lowercase ch_name <> Netmech_scram.mechanism_name profile
      then raise Not_found;
      
      let ch_realm = List.assoc "realm" ch_params in
      let ac_realm_opt =
        try Some(List.assoc "realm" params)
        with Not_found -> None in
      ( match ac_realm_opt with
          | None -> ()
          | Some ac_realm -> if ac_realm <> ch_realm then raise Not_found
      );
      `Accept(ch_realm, None)
    with
      | Not_found
      | Failure _ -> `Reject

  let client_process_challenge cs method_name uri hdr challenge =
    try
      let (_, ch_params) = challenge in
      let ch_params = decode_params ch_params in
      if cs.realm_actual = None then   (* initial challenge *)
        let realm = List.assoc "realm" ch_params in
        cs.realm_actual <- Some realm;
        cs.realm_tosend <- Some realm;
      else
        let sid_opt =
          try Some(List.assoc "sid" ch_params)
          with Not_found -> None in
        let data_b64 =
          List.assoc "data" ch_params in
        let data =
          try Netencoding.Base64.decode data_b64
          with Failure _ -> raise Not_found in
        ( match sid_opt, cs.sid with
            | None, None -> ()
            | Some sid, None -> cs.sid <- Some sid
            | Some sid1, Some sid2 -> if sid1 <> sid2 then raise Not_found
            | None, Some _ -> raise Not_found
        );
        Netmech_scram.client_recv_message cs.data data
    with
      | Not_found ->
          cs.error <- true
                        

  let client_emit_response cs method_name uri hdr =
    let data = Netmech_scram.client_emit_message cs.data in
    let data_b64 = Netencoding.Base64.encode data in
    let data_l = [ "data", `V data_b64 ] in
    let realm_l =
      match cs.realm_tosend with
        | Some r ->
            cs.realm_tosend <- None;
            ["realm", `V r]
        | None ->
            [] in
    let sid_l =
      match cs.sid with
        | Some sid -> ["sid", `V sid]
        | None -> [] in
    ( (Netmech_scram.mechanism_name profile,
       (realm_l @ sid_l @ data_l)
      ),
      []
    )

  let client_user_name cs =
    Netmech_scram.client_user_name cs.data

  let client_stash_session cs =
    assert false   (* TODO *)

  let client_resume_session s =
    assert false   (* TODO *)

  let client_session_id cs =
    cs.sid

  let client_domain cs =
    (* CHECK *)
    [ "/" ]

  let client_prop cs name =
    Netmech_scram.client_prop cs.data name

  let client_gssapi_props cs =
    raise Not_found
end
