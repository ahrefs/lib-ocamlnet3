(* $Id$ *)

open Netmech_digest
open Printf

module type PROFILE =
  sig
    val mutual : bool
    val hash_functions : Netsys_digests.iana_hash_fn list
  end

module Make_digest(P:PROFILE) : Nethttp.HTTP_CLIENT_MECHANISM = struct

  let profile =
    { ptype = `HTTP;
      hash_functions = List.filter hash_available P.hash_functions;
      mutual = P.mutual
    }

  let mechanism_name = "Digest"
  let available() = profile.hash_functions <> []
  let restart_supported = true

  type credentials =
      (string * string * (string * string) list) list

  type client_session = Netmech_digest.client_session

  let format_kv l =
    List.map (fun (k,v) -> k ^ "=" ^ v) l

  let init_credentials l =
    (l:credentials)

  let client_state cs = cs.cstate

  let create_client_session ~user ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digest_http.create_client_session:"
        [ "realm"; "cnonce"; ]
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_digest_http.create_client_session: no password \
                  found in credentials" in
    { cstate = `Wait;
      cresp = None;
      cprofile = profile;
      cdigest_uri = "";
      cmethod = "";
      crealm = (try Some(List.assoc "realm" params)
                with Not_found -> None);
      cuser = user;
      cauthz = "";
      cpasswd = pw;
      cnonce = (try List.assoc "cnonce" params
                with Not_found -> create_nonce());
    }


  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_digest_http.client_configure_channel_binding: \
                not supported"
    else
      cs

  let client_restart ~params cs =
    if cs.cstate <> `OK then
      failwith "Netmech_digest_http.client_restart: unfinished auth";
    client_restart_i cs

  let decode_params l =
    List.map
      (function
        | (n, `Q _) -> assert false
        | (n, `V v) -> (n,v)
      )
      l

                     
  let client_process_challenge cs method_name uri hdr challenge =
    match cs.cresp with
      | None ->
          let (_, msg_params) = challenge in
          let msg_params = decode_params msg_params in
          let cs = client_process_initial_challenge_kv cs msg_params in
          ( match cs.cresp with
              | None -> cs
              | Some rp ->
                  let rp' = 
                    { rp with
                      r_digest_uri = uri;
                      r_method = method_name
                    } in
                  { cs with cresp = Some rp' }
          )
      | Some rp ->
          (* There must be an Authorization-Info header *)
          ( try
              let info = hdr # field "authentication-info" in
              let info_params = Nethttp.Header.parse_quoted_parameters info in
              client_process_final_challenge_kv cs info_params
                (* NB. This function ignores cnonce and nc. They are actually
                   not needed for verification.
                 *)
            with
              | Not_found
              | Failure _ ->
                  { cs with
                    cstate = `Auth_error "bad Authentication-info header" }
          )


  let client_emit_response cs method_name uri hdr =
    if cs.cstate <> `Emit && cs.cstate <> `Stale then
      failwith "Netmech_digest_http.client_emit_response: bad state";
    let cs = client_modify ~mod_method:method_name ~mod_uri:uri cs in
    let cs, l1 = client_emit_response_kv ~quote:true cs in
    let l2 =
      List.map
        (fun (n,v) -> (n, `Q v))
        l1 in
    (cs, ("Digest", l2), [])
    
  let client_user_name cs =
    cs.cuser

  let client_stash_session cs =
    client_stash_session_i cs

  let client_resume_session s =
    client_resume_session_i s
    
  let client_session_id cs =
    None

  let client_prop cs key =
    client_prop_i cs key

  let client_gssapi_props cs =
    raise Not_found

  let client_channel_binding cs = `None
      
  let client_domain cs =
    match cs.cresp with
      | None -> []
      | Some r ->
          let d = r.r_domain in
          if d <> [] then
            d
          else
            [ "/" ]  (* whole server *)
       (* NB. the uri's are passed through Nethttp_client.normalize_domain,
          so server-relative paths can be interpreted
        *)


  let client_match ~params (ch_name, ch_params) =
    try
      if STRING_LOWERCASE ch_name <> "digest" then raise Not_found;
      let cs = 
        create_client_session
          ~user:"user" ~creds:["password","",[]] ~params () in
      let hdr = new Netmime.basic_mime_header [] in
      let cs = 
        client_process_challenge cs "DUMMY" "dummy" hdr (ch_name, ch_params) in
      if cs.cstate = `Emit then
        match cs.cresp with
          | Some rp ->
              `Accept(rp.r_realm, None)
          | None ->
              `Reject
      else
        `Reject
    with
      | Not_found
      | Failure _ ->
          `Reject
end


module Digest =
  Make_digest(
      struct 
        let mutual = false
        let hash_functions = [ `SHA_256; `MD5 ]
      end
    )

module Digest_mutual =
  Make_digest(
      struct 
        let mutual = true
        let hash_functions = [ `SHA_256; `MD5 ]
      end
    )
