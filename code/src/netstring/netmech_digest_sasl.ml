(* $Id$ *)

(* Unit tests: tests/netstring/bench/test_netmech.ml *)

open Netmech_digest
open Printf

(* For parsing the messages, we just reuse the Nethttp
   function for the www-authenticate HTTP header.
 *)

let parse_message =
  Nethttp.Header.parse_quoted_parameters


module DIGEST_MD5 : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "DIGEST-MD5"
  let client_first = `No
  let server_sends_final_data = true
  let supports_authz = true
  let available() = true

  let profile =
    { ptype = `SASL;
      hash_functions = [ `MD5 ];
      mutual = true;
    }

  type credentials =
      (string * string * (string * string) list) list

  type client_session = Netmech_digest.client_session
  type server_session = Netmech_digest.server_session

  let init_credentials l =
    (l:credentials)

  let server_state ss = ss.sstate

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_server_session:"
        [ "realm"; "nonce"; "mutual"; "secure" ]
        params in
    let srealm =
      try Some(List.assoc "realm" params)
      with Not_found -> None in
    let nonce =
      try List.assoc "nonce" params
      with Not_found -> create_nonce() in
    (* NB. "mutual" is enabled anyway, so no check here *)
    { sstate = `Emit;
      srealm;
      snonce = nonce;
      sresponse = None;
      snextnc = 1;
      sstale = false;
      sprofile = profile;
      sutf8 = true;
      snosess = false;
      lookup
    }

  let server_configure_channel_binding ss cb_list =
    failwith "Netmech_digest_sasl.server_configure_channel_binding: \
              not supported"

  let format_kv l =
    String.concat "," (List.map (fun (k,v) -> k ^ "=" ^ v) l)


  let server_emit_challenge ss =
    if ss.sstate <> `Emit then
      failwith "Netmech_digestmd5_sasl.server_emit_challenge: bad state";
    match ss.sresponse with
      | None ->
          let ss, l = server_emit_initial_challenge_kv ~quote:true ss in
          (ss, format_kv l)
      | Some _ ->
          let ss, l = server_emit_final_challenge_kv ~quote:true ss in
          (ss, format_kv l)


  let server_process_response ss msg =
    try
      let msg_params = parse_message msg in
      server_process_response_kv ss msg_params "AUTHENTICATE"
    with
      | Failure _ ->  (* from parse_message *)
           { ss with sstate = `Auth_error "parse error" }

  let server_process_response_restart ss msg set_stale =
    if ss.sstate <> `OK then
      failwith "Netmech_digestmd5_sasl.server_process_response_restart: \
                bad state";
    try
      let msg_params = parse_message msg in
      server_process_response_restart_kv ss msg_params set_stale "AUTHENTICATE"
    with
      | Failure _  -> (* from parse_message *)
           ( { ss with sstate = `Auth_error "parse error" },
             false
           )

             
  let server_channel_binding ss =
    `None

  let server_stash_session ss =
    server_stash_session_i ss

  let server_resume_session ~lookup s =
    server_resume_session_i ~lookup s

  let server_session_id ss =
    Some ss.snonce

  let server_prop ss key =
    server_prop_i ss key

  let server_gssapi_props ss =
    raise Not_found

  let server_user_name ss =
    match ss.sresponse with
      | None -> raise Not_found
      | Some(rp,_,_) -> to_utf8 rp.r_utf8 rp.r_user

  let server_authz_name ss =
    match ss.sresponse with
      | None -> raise Not_found
      | Some(rp,_,_) ->
          match rp.r_authz with
            | None -> raise Not_found
            | Some authz -> authz


  let create_client_session ~user ~authz ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_client_session:"
        [ "digest-uri"; "realm"; "cnonce"; "mutual"; "secure" ]
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_digestmd5_sasl.create_client_session: no password \
                  found in credentials" in
    (* NB. mutual auth is enabled anyway *)
    { cstate = `Wait;
      cresp = None;
      cprofile = profile;
      cmethod = "AUTHENTICATE";
      cdigest_uri = (try List.assoc "digest-uri" params
                     with Not_found -> "generic/generic");
      crealm = (try Some(List.assoc "realm" params)
                with Not_found -> None);
      cuser = user;
      cauthz = authz;
      cpasswd = pw;
      cnonce = (try List.assoc "cnonce" params
                with Not_found -> create_nonce());
    }

  let client_configure_channel_binding cs cb =
    if cb <> `None then
      failwith "Netmech_digestmd5_sasl.client_configure_channel_binding: \
                not supported"
    else
      cs

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_digestmd5_sasl.client_restart: unfinished auth";
    client_restart_i cs


  let client_process_challenge cs msg =
    (* This can either be the initial challenge or the final server message *)
    try
      let msg_params = parse_message msg in
      if List.exists (fun (k,_) -> STRING_LOWERCASE k = "rspauth") msg_params
      then
        client_process_final_challenge_kv cs msg_params
      else
        client_process_initial_challenge_kv cs msg_params
    with
      | Failure _ ->  (* from parse_message *)
          { cs with cstate = `Auth_error "parse error" }


  let client_emit_response cs =
    if cs.cstate <> `Emit && cs.cstate <> `Stale then
      failwith "Netmech_digestmd5_sasl.client_emit_response: bad state";
    let cs, l = client_emit_response_kv ~quote:true cs in
    (cs, format_kv l)

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

  let client_user_name cs =
    cs.cuser

  let client_authz_name cs =
    cs.cauthz
end


(*
#use "topfind";;
#require "netstring";;       
open Netmech_digest_sasl.DIGEST_MD5;;
let creds = init_credentials ["password", "secret", []];;
let lookup _ _ = Some creds;;
let s = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; "nonce", "OA6MG9tEQGm2hh",false] ();;
let s, s1 = server_emit_challenge s;;
let c = create_client_session ~user:"chris" ~authz:"" ~creds ~params:["digest-uri", "imap/elwood.innosoft.com", false; "cnonce", "OA6MHXh6VqTrRk", false ] ();;
let c = client_process_challenge c s1;;
let c, c1 = client_emit_response c;;
(* response=d388dad90d4bbd760a152321f2143af7 *)
let s = server_process_response s c1;;
let s, s2 = server_emit_challenge s;;
assert(server_state s = `OK);;
assert(s2 = "rspauth=\"ea40f60335c427b5527b84dbabcdfffd\"");;
let c = client_process_challenge c s2;;
assert(client_state c = `OK);;

let crestart = c;;

(* Reauth, short path: *)
let c = client_restart crestart;;
let c, c2 = client_emit_response c;;
(* nc=2 *)
let stoo = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; ] ();;
let stoo = server_process_response stoo c2;;
assert(server_state stoo = `Restart "OA6MG9tEQGm2hh");;
(* Now the server looks into the cache, and finds s under this ID *)
let s, _ = server_process_response_restart s c2 false;;
assert(server_state s = `Emit);;
let s, s3 = server_emit_challenge s;;
assert(s3 = "rspauth=\"73dd7feae8e84a22b0ad1f92666954d0\"");;
assert(server_state s = `OK);;
let c = client_process_challenge c s3;;
assert(client_state c = `OK);;

(* Reauth, long path: *)
let c = client_restart crestart;;
let c, c2 = client_emit_response c;;
(* nc=2 *)
let stoo = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; ] ();;
let stoo = server_process_response stoo c2;;
assert(server_state stoo = `Restart "OA6MG9tEQGm2hh");;
let s, _ = server_process_response_restart s c2 true;;   (* stale *)
let s, s4 = server_emit_challenge s;;
(* s4: new nonce, stale=true *)
let c = client_process_challenge c s4;;
assert(client_state c = `Stale);;
let c, c3 = client_emit_response c;;
(* c3: new cnonce *)
let s = server_process_response s c3;;
let s, s5 = server_emit_challenge s;;
assert(server_state s = `OK);;
let c = client_process_challenge c s5;;
assert(client_state c = `OK);;
 *)
