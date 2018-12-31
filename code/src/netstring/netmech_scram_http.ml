(* RFC 7804 *)

open Printf

module type PROFILE =
  sig
    val mutual : bool
    val hash_function : Netsys_digests.iana_hash_fn
    val test_nonce : string option
  end

module Make_SCRAM(P:PROFILE) : Nethttp.HTTP_CLIENT_MECHANISM =
  struct
    let profile =
      { Netmech_scram.ptype = `SASL;
        hash_function = P.hash_function;
        return_unknown_user = false;
        iteration_count_limit = 100000;
      }

    let hash_available iana_name =
      iana_name = `MD5 ||
        ( try ignore(Netsys_digests.iana_find iana_name); true
          with Not_found -> false
        )

    let mechanism_name = Netmech_scram.mechanism_name profile
    let available() = hash_available P.hash_function
    let restart_supported = false (* TODO *)

    type credentials =
      (string * string * (string * string) list) list

    type client_session =
      { sid : string option;
        data : Netmech_scram.client_session;
        initflag : bool;
        realm_accepted : string option;
        realm_actual : string option;
        realm_tosend : string option;
        error : bool;
      }

    let init_credentials l =
      (l:credentials)

    let client_state cs =
      if cs.error then
        `Auth_error "SCRAM protocol error"
      else if not P.mutual && Netmech_scram.client_semifinish_flag cs.data then
        `OK
      else if Netmech_scram.client_finish_flag cs.data then
        `OK
      else 
        match Netmech_scram.client_error_flag cs.data with
          | Some error ->
              `Auth_error (Netmech_scram.error_of_exn error)
          | None ->
              if cs.realm_actual = None then
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
      let data =
        Netmech_scram.create_client_session
          ?nonce:P.test_nonce
          profile user pw in
      { sid = None;
        data;
        initflag = true;
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
      else
        cs

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

    let base64_decode s =
      let s1 = Netencoding.Base64.decode s in
      let l1 = String.length s1 in
      if s1 <> "" && s1.[l1-1] = '\n' then
        String.sub s1 0 (l1-1)
      else
        s1

    let client_match ~params (ch_name, ch_params) =
      let params =
        Netsys_sasl_util.preprocess_params
          "Netmech_scram_http.client_match:"
          [ "realm" ]
          params in
      let ac_realm_opt =
        try Some(List.assoc "realm" params)
        with Not_found -> None in
      let realm_name =
        match ac_realm_opt with
          | None -> "_default_"
          | Some r -> r in
      try
        let ch_params = decode_params ch_params in

        if STRING_LOWERCASE ch_name <> STRING_LOWERCASE (Netmech_scram.mechanism_name profile)
        then raise Not_found;

        match List.assoc "sid" ch_params with
          | _ ->
              `Accept(realm_name, None)
          | exception Not_found ->
              let ch_realm_opt =
                try Some(List.assoc "realm" ch_params)
                with Not_found -> None in
              ( match ac_realm_opt, ch_realm_opt with
                  | Some ac_realm, Some ch_realm ->
                      if ac_realm <> ch_realm then raise Not_found
                  | _ -> ()
              );
              `Accept(realm_name, None)
      with
        | Not_found
        | Failure _ -> `Reject

    let client_process_authinfo cs hdr =
      (* There must be an Authentication-Info header *)
      try
        let info = hdr # field "authentication-info" in
        let info_params = Nethttp.Header.parse_quoted_parameters info in
        let sid_opt =
          try Some(List.assoc "sid" info_params)
          with Not_found -> None in
        let data_b64 =
          List.assoc "data" info_params in
        let data =
          try base64_decode data_b64
          with Failure _ -> raise Not_found in
        ( match sid_opt, cs.sid with
            | None, None -> ()
            | Some sid, None -> ()
            | Some sid1, Some sid2 -> if sid1 <> sid2 then raise Not_found
            | None, Some _ -> raise Not_found
        );
        { cs with
          data = Netmech_scram.client_recv_message cs.data data;
          sid = sid_opt
        }
      with
        | Not_found ->
            { cs with error = true }

    let client_process_challenge cs method_name uri hdr challenge =
      if Netmech_scram.client_semifinish_flag cs.data then
        client_process_authinfo cs hdr
      else
        try
          let (_, ch_params) = challenge in
          let ch_params = decode_params ch_params in
          if cs.initflag then   (* initial challenge *)
            let realm = 
              try Some(List.assoc "realm" ch_params)
              with Not_found -> None in
            { cs with
              initflag = false;
              realm_actual = realm;
              realm_tosend = realm;
            }
          else
            let sid_opt =
              try Some(List.assoc "sid" ch_params)
              with Not_found -> None in
            let data_b64 =
              List.assoc "data" ch_params in
            let data =
              try base64_decode data_b64
              with Failure _ -> raise Not_found in
            ( match sid_opt, cs.sid with
                | None, None -> ()
                | Some sid, None -> ()
                | Some sid1, Some sid2 -> if sid1 <> sid2 then raise Not_found
                | None, Some _ -> raise Not_found
            );
            { cs with
              data = Netmech_scram.client_recv_message cs.data data;
              sid = sid_opt
            }
        with
          | Not_found ->
              { cs with error = true }


    let client_emit_response cs method_name uri hdr =
      let ds, data = Netmech_scram.client_emit_message cs.data in
      let data_b64 = Netencoding.Base64.encode data in
      let data_l = [ "data", `V data_b64 ] in
      let realm_l =
        match cs.realm_tosend with
          | Some r ->
              ["realm", `V r]
          | None ->
              [] in
      let sid_l =
        match cs.sid with
          | Some sid -> ["sid", `V sid]
          | None -> [] in
      let cs =
        { cs with
          data = ds;
          realm_tosend = None
        } in
      ( cs,
        (Netmech_scram.mechanism_name profile,
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


module SHA_256 : PROFILE =
  struct
    let mutual=false
    let hash_function = `SHA_256
    let test_nonce=None
  end


module SHA_256_mutual : PROFILE =
  struct
    let mutual=true
    let hash_function = `SHA_256
    let test_nonce=None
  end
    

(*

#use "topfind";;
#require "netstring,nettls-gnutls";;

module P =
  struct
    let mutual = true
    let hash_function = `SHA_256
    let test_nonce = Some "rOprNGfwEbeRWgbNEkqO"
  end;;
module M = Netmech_scram_http.Make_SCRAM(P);;

Netmech_scram.Debug.enable := true;;

let creds = M.init_credentials [ "password", "pencil", [] ];;
let s = M.create_client_session ~user:"user" ~creds ~params:["realm", "testrealm@example.com", true ] ();;
let empty_hdr = new Netmime.basic_mime_header [];;
let s = M.client_process_challenge s "GET" "/resource" empty_hdr
          ("SCRAM-SHA-256", ["realm", `V "testrealm@example.com"]);;
let s, msg1, new_hdr = M.client_emit_response s "GET" "/resource" empty_hdr;;
let s = M.client_process_challenge s "GET" "/resource" empty_hdr
          ("SCRAM-SHA-256",
            ["realm", `V "testrealm@example.com";
             "sid", `V "AAAABBBBCCCCDDDD";
             "data", `V "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRixzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTYK";
            ]
          );;
let s, msg2, new_hdr = M.client_emit_response s "GET" "/resource" empty_hdr;;
let s = M.client_process_challenge s "GET" "/resource" empty_hdr
          ("SCRAM-SHA-256",
            ["realm", `V "testrealm@example.com";
             "sid", `V "AAAABBBBCCCCDDDD";
             "data", `V "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQo="
            ]
          );;

 *)
