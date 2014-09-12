(* $Id$ *)

open Printf

(* For parsing the messages, we just reuse the Nethttp
   function for the www-authenticate HTTP header.
 *)

let parse_message s =
  let u = "dummy " ^ s in
  let mh = new Netmime.basic_mime_header ["WWW-Authenticate", u ] in
  match Nethttp.Header.get_www_authenticate mh with
    | [] -> []
    | [_, params] -> params
    | _ -> assert false 

(* Quotes strings: *)

let qstring =
  Nethttp.qstring_of_value

module StrMap = Map.Make(String)
module StrSet = Set.Make(String)

module DIGEST_MD5 : Netsys_sasl_types.SASL_MECHANISM = struct
  let mechanism_name = "DIGEST-MD5"
  let client_first = `No
  let server_sends_final_data = true
  let supports_authz = true

  type credentials =
      (string * string * (string * string) list) list

  let init_credentials l =
    (l:credentials)

  type response_params =
      { r_user : string;           (* UTF-8 or ISO-8859-1 *)
        r_authz : string option;
        r_realm : string;          (* UTF-8 or ISO-8859-1 *)
        r_nonce : string;
        r_cnonce : string;
        r_nc : int;
        r_digest_uri : string;
        r_utf8 : bool;
      }

  type server_session = 
      { mutable sstate : Netsys_sasl_types.server_state;
        mutable sresponse : (response_params * string * string) option;
        mutable snextnc : int;
        mutable sstale : bool;
        mutable snonce : string;
        srealm : string option;
        lookup : string -> string -> credentials option;
      }

  let h = Digest.string

  let hex s =
    Netencoding.to_hex ~lc:true s

  let compute_response (p:response_params) password a2_prefix =
    (* a2_prefix: either "AUTHENTICATE:" or ":" *)
    let nc = sprintf "%08x" p.r_nc in
(*
eprintf "compute_response user=%s authz=%s realm=%s password=%s nonce=%s cnonce=%s digest-uri=%s nc=%s a2_prefix=%s\n"
        p.r_user (match p.r_authz with None -> "n/a" | Some a -> a)
        p.r_realm password p.r_nonce p.r_cnonce p.r_digest_uri nc a2_prefix;
 *)
    (* Note that RFC-2617 has an error here (it would calculate
       a1_a = hex (h ...)), and this made it into the standard. So
       DIGEST-MD5 as SASL is incompatible with Digest Authentication for HTTP.
     *)
    let a1_a =
      h (p.r_user ^ ":" ^ p.r_realm ^ ":" ^ password) in
    let a1_b =
      a1_a ^ ":" ^ p.r_nonce ^ ":" ^ p.r_cnonce in
    let a1 =
      match p.r_authz with
        | None -> a1_b
        | Some authz -> a1_b ^ ":" ^ authz in
    let a2 = a2_prefix ^ p.r_digest_uri in
    hex
      (h
         ((hex (h a1)) ^ ":" ^ 
            p.r_nonce ^ ":" ^ 
              nc ^ ":" ^ 
                p.r_cnonce ^ ":" ^ 
                  "auth:" ^ 
                    (hex (h a2))))
      

  let server_state ss = ss.sstate

  let create_nonce() =
    let nonce_data = String.create 16 in
    Netsys_rng.fill_random nonce_data;
    Netencoding.to_hex nonce_data

  let create_server_session ~lookup ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_server_session:"
        [ "realm"; "nonce" ]
        params in
    let srealm =
      try Some(List.assoc "realm" params)
      with Not_found -> None in
    let nonce =
      try List.assoc "nonce" params
      with Not_found -> create_nonce() in
    { sstate = `Emit;
      srealm;
      snonce = nonce;
      sresponse = None;
      snextnc = 1;
      sstale = false;
      lookup
    }

  let verify_utf8 s =
    try
      Netconversion.verify `Enc_utf8 s
    with _ -> raise Not_found

  let to_utf8 is_utf8 s =
    (* Convert from client encoding to UTF-8 *)
    if is_utf8 then (
      verify_utf8 s;
      s
    )
    else
      (* it is ISO-8859-1 *)
      Netconversion.convert
        ~in_enc:`Enc_iso88591
        ~out_enc:`Enc_utf8
        s

  let to_client is_utf8 s =
    (* Convert from UTF-8 to client encoding *)
    if is_utf8 then (
      verify_utf8 s;
      s   (* client uses utf-8, too *)
    )
    else
      try
        Netconversion.convert
          ~in_enc:`Enc_utf8
          ~out_enc:`Enc_iso88591
          s
      with
        | Netconversion.Malformed_code -> raise Not_found

  let server_emit_challenge ss =
    if ss.sstate <> `Emit then
      failwith "Netmech_digestmd5_sasl.server_emit_challenge: bad state";
    match ss.sresponse with
      | None ->
           (* initial challenge *)
           let l =
             ( match ss.srealm with
                 | None -> []
                 | Some realm -> [ "realm=" ^ qstring realm ]
             ) @
             [ "nonce=" ^ qstring ss.snonce;
               "qpop=auth"
             ] @
             ( if ss.sstale then [ "stale=true" ] else [] ) @
             [ "charset=utf-8";
               "algorithm=md5-sess";
             ] in
           ss.sstate <- `Wait;
           ss.sstale <- false;
           String.concat "," l
      | Some(_,_,srv_resp) ->
           (* second message *)
           ss.sstate <- `OK;
           "rspauth=" ^ srv_resp

  let to_strmap l =
    (* will raise Not_found if a key appears twice *)
    fst
      (List.fold_left
         (fun (m,s) (name,value) ->
            if StrSet.mem name s then raise Not_found;
            (StrMap.add name value m, StrSet.add name s)
         )
         (StrMap.empty, StrSet.empty)
         l
      )

  let nc_re =
    let hex = "[0-9a-f]" in
    Netstring_str.regexp (hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ hex ^ "$")

  let get_nc s =
    match Netstring_str.string_match nc_re s 0 with
      | None ->
           raise Not_found
      | Some _ ->
           ( try int_of_string ("0x" ^ s)
             with Failure _ -> raise Not_found
           )

  let decode_response msg =
    let m = to_strmap (parse_message msg) in
    let user = StrMap.find "username" m in
    let realm = try StrMap.find "realm" m with Not_found -> "" in
    let nonce = StrMap.find "nonce" m in
    let cnonce = StrMap.find "cnonce" m in
    let nc_str = StrMap.find "nc" m in
    let nc = get_nc nc_str in
    let qop = try StrMap.find "qop" m with Not_found -> "auth" in
    if qop <> "auth" then raise Not_found;
    let digest_uri = StrMap.find "digest-uri" m in
    let response = StrMap.find "response" m in
    let utf8 =
      if StrMap.mem "charset" m then (
        let v = StrMap.find "charset" m in
        if v <> "utf-8" then raise Not_found;
        true
      )
      else
        false in
    let authz0 =
      try Some(StrMap.find "authzid" m) with Not_found -> None in
    let authz =
      if authz0 = Some "" then None else authz0 in
    let r =
      { r_user = user;
        r_authz = authz;
        r_realm = realm;
        r_nonce = nonce;
        r_cnonce = cnonce;
        r_nc = nc;
        r_digest_uri = digest_uri;
        r_utf8 = utf8
      } in
    (r, response)

  let validate_response ss r response =
    let realm_utf8 = to_utf8 r.r_utf8 r.r_realm in
    ( match ss.srealm with
        | None -> ()
        | Some expected_realm ->
            if expected_realm <> realm_utf8 then raise Not_found
    );
    let user_utf8 = to_utf8 r.r_utf8 r.r_user in
    let authz =
      match r.r_authz with
        | None -> ""
        | Some authz -> verify_utf8 authz; authz in
    let password_utf8 =
      match ss.lookup user_utf8 authz with
        | None ->
             raise Not_found
        | Some creds ->
             Netsys_sasl_util.extract_password creds in
    let password = to_client r.r_utf8 password_utf8 in
    let expected_response = compute_response r password "AUTHENTICATE:" in
    if response <> expected_response then raise Not_found;
    password

  exception Restart of string

  let server_process_response ss msg =
    try
      let (r, response) = decode_response msg in
      if r.r_nc > 1 then raise(Restart r.r_nonce);
      if ss.sstate <> `Wait then raise Not_found;
      let password = validate_response ss r response in
      (* success: *)
      let srv_response = compute_response r password ":" in
      ss.snextnc <- r.r_nc + 1;
      ss.sresponse <- Some(r, response, srv_response);
      ss.sstate <- `Emit;
    with
      | Nethttp.Bad_header_field _  (* from parse_message *)
      | Not_found ->
           ss.sstate <- `Auth_error
      | Restart id ->
           ss.sstate <- `Restart id

  let server_process_response_restart ss msg set_stale =
    if ss.sstate <> `OK then
      failwith "Netmech_digestmd5_sasl.server_process_response_restart: \
                bad state";
    try
      let old_r =
        match ss.sresponse with
          | None -> assert false
          | Some (r, _, _) -> r in
      let (new_r, response) = decode_response msg in
      if old_r.r_user <> new_r.r_user
         || old_r.r_authz <> new_r.r_authz
         || old_r.r_realm <> new_r.r_realm
         || old_r.r_nonce <> new_r.r_nonce
         || old_r.r_cnonce <> new_r.r_cnonce
         || old_r.r_nc + 1 <> new_r.r_nc
         || old_r.r_digest_uri <> new_r.r_digest_uri
         || old_r.r_utf8 <> new_r.r_utf8 then raise Not_found;
      let password = validate_response ss new_r response in
      (* success *)
      if set_stale then (
        ss.sstale <- true;
        raise Not_found
      ) else (
        let srv_response = compute_response new_r password ":" in
        ss.snextnc <- new_r.r_nc + 1;
        ss.sresponse <- Some(new_r, response, srv_response);
        ss.sstate <- `Emit;
        true
      )
    with
      | Not_found ->
           ss.snonce <- create_nonce();
           ss.snextnc <- 1;
           ss.sresponse <- None;
           ss.sstate <- `Emit;
           false

             
  let server_channel_binding ss =
    `None

  let server_stash_session ss =
    let tuple =
      (ss.sstate, ss.sresponse, ss.snextnc, ss.sstale, ss.srealm, ss.snonce) in
    "server,t=DIGEST-MD5;" ^ 
      Marshal.to_string tuple []

  let ss_re = 
    Netstring_str.regexp "server,t=DIGEST-MD5;"

  let server_resume_session ~lookup s =
    match Netstring_str.string_match ss_re s 0 with
      | None ->
           failwith "Netmech_digestmd5_sasl.server_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let (sstate, sresponse, snextnc, sstale, srealm, snonce) =
             Marshal.from_string data 0 in
           { sstate;
             sresponse;
             snextnc;
             sstale;
             srealm;
             snonce;
             lookup
           }

  let server_session_id ss =
    Some ss.snonce

  let server_prop ss key =
    match key with
      | "nonce" -> ss.snonce
      | _ ->
          ( match ss.sresponse with
              | None -> raise Not_found
              | Some(rp,_,_) ->
                  match key with
                    | "digest-uri" ->  rp.r_digest_uri
                    | "cnonce" -> rp.r_cnonce
                    | "nc" -> string_of_int rp.r_nc
                    | "realm" ->
                        (* may be in ISO-8859-1 *)
                        to_utf8 rp.r_utf8 rp.r_realm
                    | _ -> raise Not_found
          )

  let server_user ss =
    match ss.sresponse with
      | None -> raise Not_found
      | Some(rp,_,_) -> to_utf8 rp.r_utf8 rp.r_user

  let server_authz ss =
    match ss.sresponse with
      | None -> raise Not_found
      | Some(rp,_,_) ->
          match rp.r_authz with
            | None -> raise Not_found
            | Some authz -> authz


  type client_session =
      { mutable cstate : Netsys_sasl_types.client_state;
        mutable cresp : response_params option;
        cdigest_uri : string;
        crealm : string option;
        cuser : string;
        cauthz : string;
        cpasswd : string;
        mutable cnonce : string;
      }

  let create_client_session ~user ~authz ~creds ~params () =
    let params = 
      Netsys_sasl_util.preprocess_params
        "Netmech_digestmd5_sasl.create_client_session:"
        [ "digest-uri"; "realm"; "cnonce" ]
        params in
    let pw =
      try Netsys_sasl_util.extract_password creds
      with Not_found ->
        failwith "Netmech_digestmd5_sasl.create_client_session: no password \
                  found in credentials" in
    { cstate = `Wait;
      cresp = None;
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

  let client_state cs = cs.cstate

  let client_channel_binding cs =
    `None

  let client_restart cs =
    if cs.cstate <> `OK then
      failwith "Netmech_digestmd5_sasl.client_restart: unfinished auth";
    match cs.cresp with
      | None -> assert false
      | Some rp ->
          let rp_next = { rp with r_nc = rp.r_nc+1 } in
          cs.cresp <- Some rp_next;
          cs.cstate <- `Emit


  let client_process_challenge cs msg =
    (* This can either be the initial challenge or the final server message *)
    try
      if cs.cstate <> `Wait then raise Not_found;
      let m = to_strmap (parse_message msg) in
      if StrMap.mem "rspauth" m then (
        (* final server message *)
        match cs.cresp with
          | None -> raise Not_found
          | Some rp ->
              let resp = compute_response rp cs.cpasswd ":" in
              if resp <> StrMap.find "rspauth" m then raise Not_found;
              cs.cstate <- `OK;
      )
      else (
        (* initial challenge *)
        let realm =
          try StrMap.find "realm" m
          with Not_found ->
            match cs.crealm with
              | Some r -> r
              | None -> "" in
        let nonce = StrMap.find "nonce" m in
        let qop = try StrMap.find "qop" m with Not_found -> "auth" in
        let stale = 
          try StrMap.find "stale" m = "true" with Not_found -> false in
        if stale && cs.cresp = None then raise Not_found;
        let utf8 =
          try StrMap.find "charset" m = "utf-8" with Not_found -> false in
        if not utf8 then raise Not_found;
        (* If this is an initial challenge after we tried to resume the
           old session, we need a new conce *)
        let cnonce =
          match cs.cresp with
            | None -> cs.cnonce
            | Some _ -> create_nonce() in
        cs.cnonce <- cnonce;
        let rp =
          { r_user = cs.cuser;
            r_authz = if cs.cauthz="" then None else Some cs.cauthz;
            r_realm = realm;
            r_nonce = nonce;
            r_cnonce = cnonce;
            r_nc = 1;
            r_digest_uri = cs.cdigest_uri;
            r_utf8 = true
          } in
        cs.cresp <- Some rp;
        cs.cstate <- if stale then `Stale else `Emit;
      )
    with Not_found ->
         cs.cstate <- `Auth_error


  let client_emit_response cs =
    if cs.cstate <> `Emit && cs.cstate <> `Stale then
      failwith "Netmech_digestmd5_sasl.client_emit_response: bad state";
    match cs.cresp with
      | None ->
          assert false
      | Some rp ->
          let resp = compute_response rp cs.cpasswd "AUTHENTICATE:" in
          let l =
            [ "username=" ^ qstring rp.r_user;
              "realm=" ^ qstring rp.r_realm;
              "nonce=" ^ qstring rp.r_nonce;
              "cnonce=" ^ qstring rp.r_cnonce;
              "nc=" ^ sprintf "%08x" rp.r_nc;
              "qop=auth";
              "digest-uri=" ^ qstring rp.r_digest_uri;
              "response=" ^ resp;
              "charset=utf-8";
            ] @
              ( match rp.r_authz with
                  | None -> []
                  | Some authz -> [ "authzid=" ^ qstring authz ] 
              ) in
          let out = String.concat "," l in
          cs.cstate <- `Wait;
          out


  let client_stash_session cs =
    "client,t=DIGEST-MD5;" ^ 
      Marshal.to_string cs []

  let cs_re = 
    Netstring_str.regexp "client,t=DIGEST-MD5;"

  let client_resume_session s =
    match Netstring_str.string_match cs_re s 0 with
      | None ->
           failwith "Netmech_digestmd5_sasl.client_resume_session"
      | Some m ->
           let p = Netstring_str.match_end m in
           let data = String.sub s p (String.length s - p) in
           let cs = Marshal.from_string data 0 in
           (cs : client_session)
    
  let client_session_id cs =
    None
      
  let client_prop cs key =
    match key with
      | "cnonce" -> cs.cnonce
      | "digest-uri" -> cs.cdigest_uri
      | _ ->
          (match cs.cresp with
             | None -> raise Not_found
             | Some rp ->
                 match key with
                   | "realm" -> rp.r_realm
                   | "nonce" -> rp.r_nonce
                   | "nc" -> string_of_int rp.r_nc
                   | _ -> raise Not_found
          )

  let client_user_name cs =
    cs.cuser

  let client_authz_name cs =
    cs.cauthz
end


(*
#use "topfind";;
#require "netstring";;       
open Netmech_digestmd5_sasl.DIGEST_MD5;;
let creds = init_credentials ["password", "secret", []];;
let lookup _ _ = Some creds;;
let s = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; "nonce", "OA6MG9tEQGm2hh",false] ();;
let s1 = server_emit_challenge s;;
let c = create_client_session ~user:"chris" ~authz:"" ~creds ~params:["digest-uri", "imap/elwood.innosoft.com", false; "cnonce", "OA6MHXh6VqTrRk", false ] ();;
client_process_challenge c s1;;
let c1 = client_emit_response c;;
(* response=d388dad90d4bbd760a152321f2143af7 *)
server_process_response s c1;;
let s2 = server_emit_challenge s;;
assert(server_state s = `OK);;
assert(s2 = "rspauth=ea40f60335c427b5527b84dbabcdfffd");;
client_process_challenge c s2;;
assert(client_state c = `OK);;

(* Reauth, short path: *)
client_restart c;;
let c2 = client_emit_response c;;
(* nc=2 *)
let stoo = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; ] ();;
server_process_response stoo c2;;
assert(server_state stoo = `Restart "OA6MG9tEQGm2hh");;
(* Now the server looks into the cache, and finds s under this ID *)
server_process_response_restart s c2 false;;
assert(server_state s = `Emit);;
let s3 = server_emit_challenge s;;
assert(s3 = "rspauth=73dd7feae8e84a22b0ad1f92666954d0");;
assert(server_state s = `OK);;
client_process_challenge c s3;;
assert(client_state c = `OK);;

(* Reauth, long path: *)
client_restart c;;
let c2 = client_emit_response c;;
(* nc=2 *)
let stoo = create_server_session ~lookup ~params:["realm", "elwood.innosoft.com", false; ] ();;
server_process_response stoo c2;;
assert(server_state stoo = `Restart "OA6MG9tEQGm2hh");;
server_process_response_restart s c2 true;;   (* stale *)
let s4 = server_emit_challenge s;;
(* s4: new nonce, stale=true *)
client_process_challenge c s4;;
assert(client_state c = `Stale);
let c3 = client_emit_response c;;
(* c3: new cnonce *)
server_process_response s c3;;
let s5 = server_emit_challenge s;;
assert(server_state s = `OK);;
client_process_challenge c s5;;
assert(client_state c = `OK);;
 *)
