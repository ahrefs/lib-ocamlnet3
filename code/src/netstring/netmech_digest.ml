(* $Id$ *)

(* The core of digest authentication *)

open Printf

module StrMap = Map.Make(String)
module StrSet = Set.Make(String)

type ptype = [ `SASL | `HTTP ]

type profile =
    { ptype : ptype;
      hash_functions : Netsys_digests.iana_hash_fn list;
        (* The server will only use the first one. The client will accept
           any of these *)
      mutual : bool;
        (* Only for clients: whether it is required that the server includes
           (for HTTP) or includes the right rspauth header. *)
    }

type response_params =
    { r_ptype : ptype;
      r_hash : Netsys_digests.iana_hash_fn;
      r_no_sess : bool;          (* simple scheme w/o -sess. Only HTTP *)
      r_rfc2069 : bool;
      r_user : string;           (* UTF-8 or ISO-8859-1 *)
      r_authz : string option;
      r_realm : string;          (* UTF-8 or ISO-8859-1 *)
      r_nonce : string;
      r_cnonce : string;
      r_nc : int;
      r_method : string;
      r_digest_uri : string;
      r_utf8 : bool;              (* for HTTP: always false *)
      r_opaque : string option;   (* only HTTP *)
      r_domain : string list;     (* only HTTP *)
    }

type credentials =
    (string * string * (string * string) list) list

type server_session = 
    { mutable sstate : Netsys_sasl_types.server_state;
      mutable sresponse : (response_params * string * string) option;
      mutable snextnc : int;
      mutable sstale : bool;
      mutable snonce : string;
      srealm : string option;
      sprofile : profile;
      sutf8 : bool;
      lookup : string -> string -> credentials option;
    }

let create_nonce() =
  let nonce_data = String.create 16 in
  Netsys_rng.fill_random nonce_data;
  Netencoding.to_hex nonce_data
                     
let hash iana_name =
  if iana_name = `MD5 then
    Digest.string
  else
    Netsys_digests.digest_string (Netsys_digests.iana_find iana_name)

let hash_available iana_name =
  iana_name = `MD5 ||
    ( try ignore(Netsys_digests.iana_find iana_name); true
      with Not_found -> false
    )

(* Quotes strings: *)

let qstring =
  Nethttp.qstring_of_value

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
  let h = hash p.r_hash in
  let a1 =
    if p.r_no_sess then
      p.r_user ^ ":" ^ p.r_realm ^ ":" ^ password
    else
      let a1_a =
        h (p.r_user ^ ":" ^ p.r_realm ^ ":" ^ password) in
      let a1_a =
        match p.r_ptype with
          | `HTTP -> hex a1_a   (* see comment above *)
          | `SASL -> a1_a in
      let a1_b =
        a1_a ^ ":" ^ p.r_nonce ^ ":" ^ p.r_cnonce in
      match p.r_authz with
        | None -> a1_b
        | Some authz -> a1_b ^ ":" ^ authz in
  let a2 = a2_prefix ^ p.r_digest_uri in
  let auth_body =
    if p.r_rfc2069 then  (* RFC 2069 mode *)
      [ hex (h a1); p.r_nonce; hex (h a2) ]
    else
      [ hex (h a1); p.r_nonce; nc; p.r_cnonce; "auth"; hex (h a2) ] in
  hex (h (String.concat ":" auth_body))

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

let space_re = Netstring_str.regexp "[ \t]+"

let space_split = Netstring_str.split space_re


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

let server_emit_initial_challenge_kv ?(quote=false) ss =
  (* for HTTP: "domain" is not returned *)
  let q s = if quote then qstring s else s in
  let h = List.hd ss.sprofile.hash_functions in
  let h_name = List.assoc h Netsys_digests.iana_rev_alist in
  let l =
    ( match ss.srealm with
        | None -> []
        | Some realm -> [ "realm", q realm ]
    ) @
      [ "nonce", q ss.snonce;
        "qpop", "auth"
      ] @
        ( if ss.sstale then [ "stale", "true" ] else [] ) @
        ( if ss.sutf8 then [ "charset", "utf-8" ] else [] ) @
          [ "algorithm", String.uppercase h_name ^ "-sess" ] in
  ss.sstate <- `Wait;
  ss.sstale <- false;
  l

let server_emit_final_challenge_kv ss =
  match ss.sresponse with
    | None -> assert false
    | Some(_,_,srv_resp) ->
        ss.sstate <- `OK;
        [ "rspauth", srv_resp ]

let iana_sess_alist =
  List.map
    (fun (name,code) -> (name ^ "-sess", code))
    Netsys_digests.iana_alist

let decode_response ptype msg_params method_name =
  let m = to_strmap msg_params in
  let user = StrMap.find "username" m in
  let realm = try StrMap.find "realm" m with Not_found -> "" in
  let nonce = StrMap.find "nonce" m in
  let cnonce = StrMap.find "cnonce" m in
  let nc_str = StrMap.find "nc" m in
  let nc = get_nc nc_str in
  let qop, rfc2069 = 
    try (StrMap.find "qop" m, false) with Not_found -> ("auth", true) in
  if qop <> "auth" then raise Not_found;
  let digest_uri_name =
    match ptype with
      | `HTTP -> "uri"
      | `SASL -> "digest-uri" in
  let digest_uri = StrMap.find digest_uri_name m in
  let response = StrMap.find "response" m in
  let utf8 =
    if StrMap.mem "charset" m then (
      let v = StrMap.find "charset" m in
      if v <> "utf-8" then raise Not_found;
      true
    )
    else
      false in
  let opaque =
    try Some(StrMap.find "opaque" m) with Not_found -> None in
  let authz0 =
    try Some(StrMap.find "authzid" m) with Not_found -> None in
  let authz =
    if authz0 = Some "" then None else authz0 in
  let alg_lc =
    try StrMap.find "algorithm" m with Not_found -> "" in
  let hash, no_sess =
    try (List.assoc alg_lc Netsys_digests.iana_alist, true)
    with Not_found ->
      try (List.assoc alg_lc iana_sess_alist, false)
      with Not_found ->
           match ptype with
             | `SASL -> (`MD5, false)
             | `HTTP -> raise Not_found in
  let r =
    { r_ptype = ptype;
      r_hash = hash;
      r_no_sess = no_sess;
      r_user = user;
      r_authz = authz;
      r_realm = realm;
      r_nonce = nonce;
      r_cnonce = cnonce;
      r_nc = nc;
      r_method = method_name;
      r_digest_uri = digest_uri;
      r_utf8 = utf8;
      r_rfc2069 = ptype=`HTTP && rfc2069;
      r_opaque = opaque;
      r_domain = [];   (* not repeated in response *)
    } in
  (r, response)


let validate_response ss r response =
  let realm_utf8 = to_utf8 r.r_utf8 r.r_realm in
  ( match ss.srealm with
      | None -> ()
      | Some expected_realm ->
          if expected_realm <> realm_utf8 then raise Not_found
  );
  if r.r_hash <> List.hd ss.sprofile.hash_functions then raise Not_found;
  if r.r_no_sess then raise Not_found;  (* not supported *)
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
  let expected_response = compute_response r password (r.r_method ^ ":") in
  if response <> expected_response then raise Not_found;
  password

exception Restart of string

let server_process_response_kv ss msg_params method_name =
  try
    let (r, response) =
      decode_response ss.sprofile.ptype msg_params method_name in
    if r.r_nc > 1 then raise(Restart r.r_nonce);
    if ss.sstate <> `Wait then raise Not_found;
    let password = validate_response ss r response in
    (* success: *)
    let srv_response = compute_response r password ":" in
    ss.snextnc <- r.r_nc + 1;
    ss.sresponse <- Some(r, response, srv_response);
    ss.sstate <- `Emit;
  with
    | Not_found ->
         ss.sstate <- `Auth_error
    | Restart id ->
         ss.sstate <- `Restart id


let server_process_response_restart_kv ss msg_params set_stale method_name =
  try
    let old_r =
      match ss.sresponse with
        | None -> assert false
        | Some (r, _, _) -> r in
    let (new_r, response) =
      decode_response ss.sprofile.ptype msg_params method_name in
    if old_r.r_hash <> new_r.r_hash
       || old_r.r_no_sess <> new_r.r_no_sess
       || old_r.r_user <> new_r.r_user
       || old_r.r_authz <> new_r.r_authz
       || old_r.r_realm <> new_r.r_realm
       || old_r.r_nonce <> new_r.r_nonce
       || old_r.r_cnonce <> new_r.r_cnonce
       || old_r.r_nc + 1 <> new_r.r_nc
       (* || old_r.r_digest_uri <> new_r.r_digest_uri *) (* CHECK *)
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


let server_stash_session_i ss =
  let tuple =
    (ss.sprofile, ss.sstate, ss.sresponse, ss.snextnc, ss.sstale, ss.srealm,
     ss.snonce, ss.sutf8) in
  "server,t=DIGEST;" ^ 
    Marshal.to_string tuple []

let ss_re = 
  Netstring_str.regexp "server,t=DIGEST;"

let server_resume_session_i ~lookup s =
  match Netstring_str.string_match ss_re s 0 with
    | None ->
         failwith "Netmech_digest.server_resume_session"
    | Some m ->
         let p = Netstring_str.match_end m in
         let data = String.sub s p (String.length s - p) in
         let (sprofile,sstate, sresponse, snextnc, sstale, srealm, snonce,
              sutf8) =
           Marshal.from_string data 0 in
         { sprofile;
           sstate;
           sresponse;
           snextnc;
           sstale;
           srealm;
           snonce;
           sutf8;
           lookup
         }

let server_prop_i ss key =
  match key with
    | "nonce" -> ss.snonce
    | _ ->
        ( match ss.sresponse with
            | None -> raise Not_found
            | Some(rp,_,_) ->
                match key with
                  | "digest-uri" | "uri" ->  rp.r_digest_uri
                  | "cnonce" -> rp.r_cnonce
                  | "nc" -> string_of_int rp.r_nc
                  | "realm" ->
                      (* may be in ISO-8859-1 *)
                      to_utf8 rp.r_utf8 rp.r_realm
                  | _ -> raise Not_found
        )

type client_session =
    { mutable cstate : Netsys_sasl_types.client_state;
      mutable cresp : response_params option;
      cdigest_uri : string;
      cmethod : string;
      cprofile : profile;
      crealm : string option;
      cuser : string;
      cauthz : string;
      cpasswd : string;
      mutable cnonce : string;
    }


let client_restart_i cs =
  match cs.cresp with
    | None -> assert false
    | Some rp ->
        let rp_next = { rp with r_nc = rp.r_nc+1 } in
        cs.cresp <- Some rp_next;
        cs.cstate <- `Emit

let client_process_final_challenge_kv cs msg_params =
  try
    if cs.cstate <> `Wait then raise Not_found;
    if cs.cprofile.mutual then (
      let m = to_strmap msg_params in
      let rspauth = StrMap.find "rspauth" m in
      match cs.cresp with
        | None -> raise Not_found
        | Some rp ->
            let resp = compute_response rp cs.cpasswd ":" in
            if resp <> rspauth then raise Not_found;
            cs.cstate <- `OK;
    ) else
      cs.cstate <- `OK
  with Not_found ->
       cs.cstate <- `Auth_error


let client_process_initial_challenge_kv cs msg_params =
  try
    if cs.cstate <> `Wait then raise Not_found;
    let m = to_strmap msg_params in
    let realm =
      try StrMap.find "realm" m
      with Not_found ->
        match cs.crealm with
          | Some r -> r
          | None -> "" in
    let nonce = StrMap.find "nonce" m in
    let qop, rfc2069 = 
      try (StrMap.find "qop" m, false) with Not_found -> ("auth", true) in
    let stale = 
      try StrMap.find "stale" m = "true" with Not_found -> false in
    if stale && cs.cresp = None then raise Not_found;
    let utf8 =
      try StrMap.find "charset" m = "utf-8" with Not_found -> false in
    if cs.cprofile.ptype = `SASL && not utf8 then raise Not_found;
    let opaque =
      try Some(StrMap.find "opaque" m) with Not_found -> None in
    let domain =
      try space_split (StrMap.find "domain" m) with Not_found -> [] in
    let alg_lc = String.lowercase(StrMap.find "algorithm" m) in
    let hash, no_sess =
      try (List.assoc alg_lc Netsys_digests.iana_alist, true)
      with Not_found ->
        (List.assoc alg_lc iana_sess_alist, false) in
    if cs.cprofile.ptype = `SASL && no_sess then raise Not_found;
    if not (List.mem hash cs.cprofile.hash_functions) then raise Not_found;
    (* If this is an initial challenge after we tried to resume the
       old session, we need a new conce *)
    let cnonce =
      match cs.cresp with
        | None -> cs.cnonce
        | Some _ -> create_nonce() in
    cs.cnonce <- cnonce;
    let rp =
      { r_ptype = cs.cprofile.ptype;
        r_hash = hash;
        r_no_sess = no_sess;
        r_user = cs.cuser;
        r_authz = if cs.cauthz="" then None else Some cs.cauthz;
        r_realm = realm;
        r_nonce = nonce;
        r_cnonce = cnonce;
        r_nc = 1;
        r_method = cs.cmethod;
        r_digest_uri = cs.cdigest_uri;
        r_utf8 = utf8;
        r_rfc2069 = cs.cprofile.ptype=`HTTP && rfc2069;
        r_opaque = opaque;
        r_domain = domain;
      } in
    cs.cresp <- Some rp;
    cs.cstate <- if stale then `Stale else `Emit;
  with Not_found ->
       cs.cstate <- `Auth_error

let client_emit_response_kv ?(quote=false) cs =
  (* SASL: method_name="AUTHENTICATE" *)
  let q s = if quote then qstring s else s in
  match cs.cresp with
    | None ->
        assert false
    | Some rp ->
        let resp = compute_response rp cs.cpasswd (rp.r_method ^ ":") in
        let digest_uri_name =
          match cs.cprofile.ptype with
            | `SASL -> "digest-uri"
            | `HTTP -> "uri" in
        let l =
          [ "username", q rp.r_user;
            "realm", q rp.r_realm;
            "nonce", q rp.r_nonce;
            "cnonce", q rp.r_cnonce;
            "nc", sprintf "%08x" rp.r_nc;
            "qop", "auth";
            digest_uri_name, q rp.r_digest_uri;
            "response", resp;
          ] @
            ( if rp.r_utf8 then [ "charset", "utf-8" ] else [] ) @
              ( match rp.r_authz with
                  | None -> []
                  | Some authz -> [ "authzid", q authz ] 
              ) @
                ( match rp.r_opaque with
                    | None -> []
                    | Some s -> [ "opaque", q s ]
                ) @
                  ( if rp.r_ptype = `SASL && rp.r_hash = `MD5 then
                      []
                    else
                      let alg = 
                        String.uppercase
                          (List.assoc 
                             rp.r_hash Netsys_digests.iana_rev_alist) in
                      let suffix =
                        if rp.r_no_sess then "" else "-sess" in
                      [ "algorithm", alg ^ suffix ]
                  ) in
        cs.cstate <- (if cs.cprofile.mutual then `Wait else `OK);
        l

let client_stash_session_i cs =
  "client,t=DIGEST;" ^ 
    Marshal.to_string cs []

let cs_re = 
  Netstring_str.regexp "client,t=DIGEST;"

let client_resume_session_i s =
  match Netstring_str.string_match cs_re s 0 with
    | None ->
         failwith "Netmech_digest.client_resume_session"
    | Some m ->
         let p = Netstring_str.match_end m in
         let data = String.sub s p (String.length s - p) in
         let cs = Marshal.from_string data 0 in
         (cs : client_session)

let client_prop_i cs key =
  match key with
    | "cnonce" -> cs.cnonce
    | "digest-uri" | "uri" -> cs.cdigest_uri
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
