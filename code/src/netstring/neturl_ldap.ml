open Neturl
open Printf

let make_ldap_url ?(encoded=false) ?host ?addr ?port ?socksymbol
                  ?dn ?attributes ?scope ?filter ?extensions () =
  let enc = Netencoding.Url.encode ~plus:false in
  let path =
    if dn=None && attributes=None && scope=None &&
         filter=None && extensions=None
    then
      []
    else
      match dn with
        | None -> [ ""; "" ]
        | Some s -> [ ""; s ] in
  let q4 =
    match extensions with
      | None -> ""
      | Some l ->
          "?" ^ 
            String.concat
              ","
                (List.map
                   (fun (crit,name,valopt) ->
                      sprintf "%s%s%s"
                              (if crit then "!" else "")
                              (enc name)
                              (match valopt with
                                 | None -> ""
                                 | Some v -> "=" ^ enc v
                              )
                   )
                   l
                ) in
  let q3 =
      match filter with
        | None ->
            if q4 = "" then "" else "?" ^ q4
        | Some s ->
            "?" ^ enc s ^ q4 in
  let q2 =
    match scope with
      | None ->
          if q3 = "" then "" else "?" ^ q3
      | Some `Base ->
          "?base" ^ q3
      | Some `Sub ->
          "?sub" ^ q3
      | Some `One ->
          "?one" ^ q3 in
  let q1 =
    match attributes with
      | None ->
          if q2 = "" then "" else q2
      | Some l ->
          String.concat "," (List.map enc l) ^ q2 in
  let query =
    if q1 = "" then
      None
    else
      Some q1 in
  let u1 =
    make_url
      ~encoded ~scheme:"ldap" ?host ?addr ?port ?socksymbol ~path
      Neturl.ldap_url_syntax in
  modify_url
    ~encoded:true
    ?query
    u1


let nth_query_part q n =
  let l = String.length q in
  let rec extract start n k =
    if n=0 then
      if k >= l || q.[k] = '?' then
        String.sub q start (k-start)
      else
        extract start n (k+1)
    else
      if k >= l then
        raise Not_found
      else
        if q.[k] = '?' then
          extract (k+1) (n-1) (k+1)
        else
          extract start n (k+1)
  in
  assert(n>=0);
  extract 0 n 0

      
let ldap_url_dn ?(encoded=false) u =
  match url_path ~encoded u with
    | [ ""; dn ] -> dn
    | [] -> raise Not_found
    | _ -> raise Malformed_URL


let comma_re = Netstring_str.regexp ","


let ldap_url_attributes ?(encoded=false) u =
  let query = url_query ~encoded:true u in
  let q_atts = nth_query_part query 0 in
  let atts = Netstring_str.split comma_re q_atts in
  if encoded then
    atts
  else
    List.map (Netencoding.Url.decode ~plus:false) atts


let ldap_url_scope u =
  let query = url_query ~encoded:true u in
  let q_scope = nth_query_part query 1 in
  match STRING_LOWERCASE q_scope with
    | ""
    | "base" -> `Base
    | "one" -> `One
    | "sub" -> `Sub
    | _ -> raise Malformed_URL

let ldap_url_filter ?(encoded=false) u =
  let query = url_query ~encoded:true u in
  let q_flt = nth_query_part query 2 in
  if encoded then
    q_flt
  else
    Netencoding.Url.decode ~plus:false q_flt

let ext_re = Netstring_str.regexp "!?\\([0-9a-zA-Z.%-]+\\)\\(=\\(.*\\)\\)$"

let ldap_url_extensions ?(encoded=false) u =
  let query = url_query ~encoded:true u in
  let q_exts = nth_query_part query 3 in
  let exts1 = Netstring_str.split comma_re q_exts in
  List.map
    (fun ext1 ->
       match Netstring_str.string_match ext_re ext1 0 with
         | None -> raise Malformed_URL
         | Some m ->
             let crit = ext1.[0] = '!' in
             let name1 = Netstring_str.matched_group m 1 ext1 in
             let value1 =
               try Some(Netstring_str.matched_group m 3 ext1)
               with Not_found -> None in
             let name =
               if encoded then name1 else
                 Netencoding.Url.decode ~plus:false name1 in
             let value =
               if encoded then value1 else
                 match value1 with
                   | None -> None
                   | Some s -> Some(Netencoding.Url.decode ~plus:false s) in
             (crit,name,value)
    )
    exts1


let ldap_url_provides ?(dn=false) ?(attributes=false) ?(scope=false)
                      ?(filter=false) ?(extensions=false) u =
  let query_comp_present n =
    try
      let query = url_query ~encoded:true u in
      ignore(nth_query_part query n);
      true
    with Not_found -> false in
  let dn_ok =
    not dn || Neturl.url_path u <> [] in
  let attributes_ok =
    not attributes || query_comp_present 0 in
  let scope_ok =
    not scope || query_comp_present 1 in
  let filter_ok =
    not filter || query_comp_present 2 in
  let exts_ok =
    not extensions || query_comp_present 3 in
  dn_ok && attributes_ok && scope_ok && filter_ok && exts_ok
