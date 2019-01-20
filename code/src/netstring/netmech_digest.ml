(* $Id$ *)

(* Unit tests: tests/netstring/bench/test_netmech.ml (SASL only) *)


(* The core of digest authentication *)

(* What is implemented in the client (when H is the name of the hash function):

   - HTTP: RFC-2069 mode
   - HTTP: RFC-2617 mode: qop="auth", both H and H-sess
   - HTTP: charset is iso-8859-1
   - HTTP: user name hashing
   - SASL mode: qop="auth", H-sess, charset=utf-8

   What is implemented in the server:

   - HTTP: RFC-2069 mode
   - HTTP: RFC-2617 mode: qop="auth", both H and H-sess
     (selected by ss.snosess)
   - HTTP: NO user name hashing
   - HTTP: charset can be iso-8859-1 or utf-8
   - SASL mode: qop="auth", H-sess, charset=utf-8

   So far: H=MD5. We are prepared for other hash functions, though.
 *)

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
      r_utf8 : bool;
      r_opaque : string option;   (* only HTTP *)
      r_domain : string list;     (* only HTTP *)
      r_userhash : bool;          (* only HTTP *)
    }

type credentials =
    (string * string * (string * string) list) list

type server_session = 
    { sstate : Netsys_sasl_types.server_state;
      sresponse : (response_params * string * string) option;
      snextnc : int;
      sstale : bool;
      snonce : string;
      srealm : string option;   (* always UTF-8 *)
      sprofile : profile;
      sutf8 : bool;             (* whether to use UTF-8 on the wire *)
      snosess : bool;
      lookup : string -> string -> credentials option;
    }

let create_nonce() =
  let nonce_data = Bytes.create 16 in
  Netsys_rng.fill_random nonce_data;
  Netencoding.to_hex (Bytes.to_string nonce_data)
                     
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

let verify_utf8 s =
  try
    Netconversion.verify `Enc_utf8 s
  with _ -> failwith "UTF-8 mismatch"

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
      | Netconversion.Malformed_code -> 
          failwith "cannot convert to ISO-8859-1"

let create_hashed_creds hash_fn user password realm =
  let h_name = List.assoc hash_fn Netsys_digests.iana_rev_alist in
  let h = hash hash_fn in
  [ "digest",
    h (user ^ ":" ^ realm ^ ":" ^ password) |> Netencoding.Base64.encode,
    [ "realm", realm;
      "algo", h_name
    ]
  ]

let extract_h_pw (p:response_params) (creds:Netsys_sasl.credentials) =
  let h_name = List.assoc p.r_hash Netsys_digests.iana_rev_alist in
  try
    let _, h_a1, _ =
      List.find
        (fun (t, _, params) ->
          t = "digest" &&
            List.mem_assoc "realm" params &&
              List.assoc "realm" params = p.r_realm &&
                List.mem_assoc "algo" params &&
                  List.assoc "algo" params = h_name
        )
        creds in
    Netencoding.Base64.decode h_a1
  with
    | Not_found ->
        let pw_utf8 = Netsys_sasl_util.extract_password creds in
        let pw = to_client p.r_utf8 pw_utf8 in
        let h = hash p.r_hash in
        h (p.r_user ^ ":" ^ p.r_realm ^ ":" ^ pw)

let compute_response (p:response_params) creds a2_prefix =
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
  let h_pw = extract_h_pw p creds in
  let h_a1 =
    if p.r_no_sess then
      h_pw
    else
      let a1_a =
        match p.r_ptype with
          | `HTTP -> hex h_pw   (* see comment above *)
          | `SASL -> h_pw in
      let a1_b =
        a1_a ^ ":" ^ p.r_nonce ^ ":" ^ p.r_cnonce in
      let a1 =
        match p.r_authz with
          | None -> a1_b
          | Some authz -> a1_b ^ ":" ^ authz in
      h a1 in
  let a2 = a2_prefix ^ p.r_digest_uri in
  let auth_body =
    if p.r_rfc2069 then  (* RFC 2069 mode *)
      [ hex h_a1; p.r_nonce; hex (h a2) ]
    else
      [ hex h_a1; p.r_nonce; nc; p.r_cnonce; "auth"; hex (h a2) ] in
  hex (h (String.concat ":" auth_body))

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
        failwith "cannot parse nc"
    | Some _ ->
         ( try int_of_string ("0x" ^ s)
           with Failure _ -> failwith "cannot convert nc from hex"
         )

let server_emit_initial_challenge_kv ?(quote=false) ss =
  (* for HTTP: "domain" is not returned *)
  let q s = if quote then qstring s else s in
  let h = List.hd ss.sprofile.hash_functions in
  let h_name = List.assoc h Netsys_digests.iana_rev_alist in
  let l =
    ( match ss.srealm with
        | None -> []
        | Some realm -> [ "realm", q (to_utf8 ss.sutf8 realm) ]
    ) @
      [ "nonce", q ss.snonce;
        "qop", "auth"
      ] @
        ( if ss.sstale then [ "stale", "true" ] else [] ) @
        ( if ss.sutf8 then [ "charset", "utf-8" ] else [] ) @
          [ "algorithm", STRING_UPPERCASE h_name ^
                           (if ss.snosess then "" else "-sess") ] in
  ( { ss with
      sstate = `Wait;
      sstale = false;
    },
    l
  )

let server_emit_final_challenge_kv ?(quote=false) ss =
  let q s = if quote then qstring s else s in
  match ss.sresponse with
    | None -> assert false
    | Some(rp,_,srv_resp) ->
        if rp.r_rfc2069 then
          ( { ss with sstate = `OK; }, [] )
        else
          ( { ss with sstate = `OK; },
            [ "rspauth", q srv_resp ] @
              ( match ss.sprofile.ptype with
                  | `SASL -> []
                  | `HTTP ->
                      [ "qop", "auth";
                        "cnonce", q rp.r_cnonce;
                        "nc", sprintf "%08x" rp.r_nc
                      ]
              )
          )


let iana_sess_alist =
  List.map
    (fun (name,code) -> (name ^ "-sess", code))
    Netsys_digests.iana_alist

let decode_response ptype msg_params method_name =
  let m = to_strmap msg_params in
  let user = StrMap.find "username" m in
  let realm = try StrMap.find "realm" m with Not_found -> "" in
  let nonce = StrMap.find "nonce" m in
  let qop, rfc2069 =
    try
      let qop = StrMap.find "qop" m in
      if qop <> "auth" then failwith "bad qop";
      qop, false
    with Not_found -> "auth", true in
  if rfc2069 && ptype<>`HTTP then raise Not_found;
  let cnonce, nc =
    if rfc2069 then
      "", 1
    else
      let cnonce = try StrMap.find "cnonce" m
                   with Not_found -> failwith "missing cnonce" in
      let nc_str = try StrMap.find "nc" m
                   with Not_found -> failwith "missing nc" in
      let nc = get_nc nc_str in
      cnonce, nc in
  let digest_uri_name =
    match ptype with
      | `HTTP -> "uri"
      | `SASL -> "digest-uri" in
  let digest_uri = try StrMap.find digest_uri_name m
                   with Not_found -> failwith ("missing " ^ digest_uri_name) in
  let response = try StrMap.find "response" m
                 with Not_found -> failwith "missing response" in
  let utf8 =
    if StrMap.mem "charset" m then (
      let v = StrMap.find "charset" m in
      if v <> "utf-8" then failwith "bad charset";
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
  let userhash =
    try StrMap.find "userhash" m = "true" with Not_found -> false in
  let alg_lc =
    try StrMap.find "algorithm" m |> STRING_LOWERCASE with Not_found -> "" in
  let hash, no_sess =
    if rfc2069 then
      `MD5, true
    else
      try (List.assoc alg_lc Netsys_digests.iana_alist, true)
      with Not_found ->
           try (List.assoc alg_lc iana_sess_alist, false)
           with Not_found ->
                match ptype with
                  | `SASL -> (`MD5, false)
                  | `HTTP -> failwith "cannot determine algorithem" in
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
      r_rfc2069 = rfc2069;
      r_opaque = opaque;
      r_domain = [];   (* not repeated in response *)
      r_userhash = userhash;
    } in
  (r, response)


let validate_response ss r response =
  let realm_utf8 = to_utf8 r.r_utf8 r.r_realm in
  ( match ss.srealm with
      | None -> ()
      | Some expected_realm ->
          if expected_realm <> realm_utf8 then failwith "bad realm";
  );
  if r.r_hash <> List.hd ss.sprofile.hash_functions then
    failwith "unexpected hash function";
  if r.r_no_sess <> ss.snosess then
    failwith "parameter mismatch";
  if r.r_userhash then 
    failwith "user name hashing not supported"; 
    (* not supported on server side *)
  let user_utf8 = to_utf8 r.r_utf8 r.r_user in
  let authz =
    match r.r_authz with
      | None -> ""
      | Some authz -> verify_utf8 authz; authz in
  let creds =
    match ss.lookup user_utf8 authz with
      | None ->
          failwith "bad user"
      | Some creds ->
          creds in
  let expected_response = compute_response r creds (r.r_method ^ ":") in
  if response <> expected_response then failwith "bad password";
  creds

exception Restart of string

let server_process_response_kv ss msg_params method_name =
  try
    let (r, response) =
      decode_response ss.sprofile.ptype msg_params method_name in
    if r.r_nc > 1 then raise(Restart r.r_nonce);
    if ss.sstate <> `Wait then raise Not_found;
    let creds = validate_response ss r response in
    (* success: *)
    let srv_response = compute_response r creds ":" in
    { ss with
      snextnc = r.r_nc + 1;
      sresponse = Some(r, response, srv_response);
      sstate = `Emit;
    }
  with
    | Failure msg ->
         { ss with sstate = `Auth_error msg }
    | Not_found ->
         { ss with sstate = `Auth_error "unspecified" }
    | Restart id ->
         { ss with sstate = `Restart id }


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
    let creds = validate_response ss new_r response in
    (* success *)
    if set_stale then raise Exit;
    let srv_response = compute_response new_r creds ":" in
    ( { ss with
        snextnc = new_r.r_nc + 1;
        sresponse = Some(new_r, response, srv_response);
        sstate = `Emit;
      },
      true
    )
  with
    | Failure _ ->  (* from validate_response *)
         ( { ss with
             snonce = create_nonce();
             snextnc = 1;
             sresponse = None;
             sstate = `Emit;
           },
           false
         )

    | Not_found ->
         ( { ss with
             snonce = create_nonce();
             snextnc = 1;
             sresponse = None;
             sstate = `Emit;
           },
           false
         )
    | Exit ->
         ( { ss with
             snonce = create_nonce();
             snextnc = 1;
             sresponse = None;
             sstate = `Emit;
             sstale = true
           },
           false
         )



let server_stash_session_i ss =
  let tuple =
    (ss.sprofile, ss.sstate, ss.sresponse, ss.snextnc, ss.sstale, ss.srealm,
     ss.snonce, ss.sutf8, ss.snosess) in
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
              sutf8, snosess) =
           Marshal.from_string data 0 in
         { sprofile;
           sstate;
           sresponse;
           snextnc;
           sstale;
           srealm;
           snonce;
           sutf8;
           snosess;
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
    { cstate : Netsys_sasl_types.client_state;
      cresp : response_params option;
      cdigest_uri : string;
      cmethod : string;
      cprofile : profile;
      crealm : string option;   (* always UTF-8 *)
      cuser : string;           (* always UTF-8 *)
      cauthz : string;          (* always UTF-8 *)
      cpasswd : string;         (* always UTF-8 *)
      cnonce : string;
    }


let client_restart_i cs =
  match cs.cresp with
    | None -> assert false
    | Some rp ->
        let rp_next = { rp with r_nc = rp.r_nc+1 } in
        { cs with
          cresp = Some rp_next;
          cstate = `Emit
        }

let client_process_final_challenge_kv cs msg_params =
  try
    if cs.cstate <> `Wait then raise Not_found;
    if cs.cprofile.mutual then (
      let m = to_strmap msg_params in
      let rspauth = StrMap.find "rspauth" m in
      match cs.cresp with
        | None -> raise Not_found
        | Some rp ->
            let creds = [ "password", cs.cpasswd, [] ] in
            let resp = compute_response rp creds ":" in
            if resp <> rspauth then raise Not_found;
            { cs with cstate = `OK }
    ) else
      { cs with cstate = `OK }
  with
    | Failure msg ->
       { cs with cstate = `Auth_error msg }
    | Not_found ->
       { cs with cstate = `Auth_error "cannot authenticate server" }


let client_process_initial_challenge_kv cs msg_params =
  try
    if cs.cstate <> `Wait then raise Not_found;
    let m = to_strmap msg_params in
    let utf8 =
      try StrMap.find "charset" m = "utf-8" with Not_found -> false in
    (* UTF-8: we encode our message in UTF-8 when the server sets the utf-8
       attribute
     *)
    let realm =
      try StrMap.find "realm" m
      with Not_found ->
        match cs.crealm with
          | Some r -> to_client utf8 r
          | None -> "" in
    let nonce = StrMap.find "nonce" m in
    let qop_s, rfc2069 = 
      try (StrMap.find "qop" m, false) with Not_found -> ("auth", true) in
    let qop_l = space_split qop_s in
    if not (List.mem "auth" qop_l) then failwith "bad qop";
    let stale = 
      try StrMap.find "stale" m = "true" with Not_found -> false in
    if stale && cs.cresp = None then raise Not_found;
    if cs.cprofile.ptype = `SASL && not utf8 then failwith "missing utf-8";
    let opaque =
      try Some(StrMap.find "opaque" m) with Not_found -> None in
    let domain =
      try space_split (StrMap.find "domain" m) with Not_found -> [] in
    let alg_lc = 
      try STRING_LOWERCASE (StrMap.find "algorithm" m)
      with Not_found when cs.cprofile.ptype = `HTTP -> "md5" in
    let hash, no_sess =
      try (List.assoc alg_lc Netsys_digests.iana_alist, true)
      with Not_found ->
        (List.assoc alg_lc iana_sess_alist, false) in
    let userhash =
      try StrMap.find "userhash" m = "true" with Not_found -> false in
    if cs.cprofile.ptype = `SASL && no_sess then raise Not_found;
    if not (List.mem hash cs.cprofile.hash_functions) then
      failwith "unsupported hash function";
    (* If this is an initial challenge after we tried to resume the
       old session, we need a new conce *)
    let cnonce =
      match cs.cresp with
        | None -> cs.cnonce
        | Some _ -> create_nonce() in
    let rp =
      { r_ptype = cs.cprofile.ptype;
        r_hash = hash;
        r_no_sess = no_sess;
        r_user = to_client utf8 cs.cuser;
        r_authz = if cs.cauthz="" then None else Some(to_client utf8 cs.cauthz);
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
        r_userhash = userhash;
      } in
    { cs with 
      cresp = Some rp;
      cstate = if stale then `Stale else `Emit;
      cnonce = cnonce;
    }
  with 
    | Failure msg ->
        { cs with cstate = `Auth_error msg }
    | Not_found ->
        { cs with cstate = `Auth_error "unspecified" }

let client_modify ?mod_method ?mod_uri cs =
  match cs.cresp with
    | None ->
        invalid_arg "Netmech_digest.client_modify"
    | Some rp ->
        let rp1 =
          { rp with
            r_method = (match mod_method with
                          | None -> rp.r_method
                          | Some m -> m
                       );
            r_digest_uri = (match mod_uri with
                              | None -> rp.r_digest_uri
                              | Some u -> u
                           )
          } in
        { cs with cresp = Some rp1 }


let client_emit_response_kv ?(quote=false) cs =
  (* SASL: method_name="AUTHENTICATE" *)
  let q s = if quote then qstring s else s in
  match cs.cresp with
    | None ->
        assert false
    | Some rp ->
        let creds = [ "password", cs.cpasswd, [] ] in
        let resp = compute_response rp creds (rp.r_method ^ ":") in
        let digest_uri_name =
          match cs.cprofile.ptype with
            | `SASL -> "digest-uri"
            | `HTTP -> "uri" in
        let username =
          if rp.r_userhash then
            let h = hash rp.r_hash in
            h (rp.r_user ^ ":" ^ rp.r_realm)
          else
            rp.r_user in
        let l =
          [ "username", q username;
            "realm", q rp.r_realm;
            "nonce", q rp.r_nonce;
            digest_uri_name, q rp.r_digest_uri;
            "response", q resp;
          ] @
            ( if rp.r_rfc2069 then
                []
              else
                [ "cnonce", q rp.r_cnonce;
                  "nc", sprintf "%08x" rp.r_nc;
                  "qop", "auth";
                ]
            ) @
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
                          STRING_UPPERCASE
                            (List.assoc 
                               rp.r_hash Netsys_digests.iana_rev_alist) in
                        let suffix =
                          if rp.r_no_sess then "" else "-sess" in
                        [ "algorithm", alg ^ suffix ]
                    ) in
        ( { cs with cstate = (if cs.cprofile.mutual then `Wait else `OK) },
          l
        )

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
