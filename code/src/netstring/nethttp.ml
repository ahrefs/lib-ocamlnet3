(* $Id$ 
 * ----------------------------------------------------------------------
 * Nethttp: Basic definitions for the HTTP protocol
 *)

type protocol_version = 
    int * int
type protocol_attribute =
  [ `Secure_https
  ]
type protocol =
  [ `Http of (protocol_version * protocol_attribute list)
  | `Other
  ]

let string_of_protocol =
  function
    | `Http((m,n),_) -> "HTTP/" ^ string_of_int m ^ "." ^ string_of_int n
    | `Other -> failwith "string_of_protocol"

let http_re = Netstring_pcre.regexp "HTTP/([0-9]+)\\.([0-9]+)$"

let protocol_of_string s =
  match Netstring_pcre.string_match http_re s 0 with
    | Some m ->
	( try 
	    `Http ((int_of_string (Netstring_pcre.matched_group m 1 s),
		    int_of_string (Netstring_pcre.matched_group m 2 s)), [])
	  with
	      Failure _ -> `Other  (* Probably denial-of-service attack! *)
	)
    | None ->
	`Other

type http_status = 
  (* 1xx: (informational) *)
  [ `Continue
  | `Switching_protocols 
  (* 2xx: (successful) *)
  | `Ok
  | `Created
  | `Accepted
  | `Non_authoritative
  | `No_content
  | `Reset_content
  | `Partial_content
  (* 3xx: (redirection) *)
  | `Multiple_choices
  | `Moved_permanently
  | `Found
  | `See_other
  | `Not_modified
  | `Use_proxy
  | `Temporary_redirect
  (* 4xx: (client error) *)
  | `Bad_request
  | `Unauthorized
  | `Payment_required
  | `Forbidden
  | `Not_found
  | `Method_not_allowed
  | `Not_acceptable
  | `Proxy_auth_required
  | `Request_timeout
  | `Conflict
  | `Gone
  | `Length_required
  | `Precondition_failed
  | `Request_entity_too_large
  | `Request_uri_too_long
  | `Unsupported_media_type
  | `Requested_range_not_satisfiable
  | `Expectation_failed
  (* 5xx: (server error) *)
  | `Internal_server_error
  | `Not_implemented
  | `Bad_gateway
  | `Service_unavailable
  | `Gateway_timeout
  | `Http_version_not_supported 
  ]

let int_of_http_status =
  function
      (* 1xx: (informational) *)
    | `Continue -> 100
    | `Switching_protocols -> 101
      (* 2xx: (successful) *)
    | `Ok -> 200
    | `Created -> 201
    | `Accepted -> 202
    | `Non_authoritative -> 203
    | `No_content -> 204
    | `Reset_content -> 205
    | `Partial_content -> 206
      (* 3xx: (redirection) *)
    | `Multiple_choices -> 300
    | `Moved_permanently -> 301
    | `Found -> 302
    | `See_other -> 303
    | `Not_modified -> 304
    | `Use_proxy -> 305
    | `Temporary_redirect -> 307
      (* 4xx: (client error) *)
    | `Bad_request -> 400
    | `Unauthorized -> 401
    | `Payment_required -> 402
    | `Forbidden -> 403
    | `Not_found -> 404
    | `Method_not_allowed -> 405
    | `Not_acceptable -> 406
    | `Proxy_auth_required -> 407
    | `Request_timeout -> 408
    | `Conflict -> 409
    | `Gone -> 410
    | `Length_required -> 411
    | `Precondition_failed -> 412
    | `Request_entity_too_large -> 413
    | `Request_uri_too_long -> 414
    | `Unsupported_media_type -> 415
    | `Requested_range_not_satisfiable -> 416
    | `Expectation_failed -> 417
      (* 5xx: (server error) *)
    | `Internal_server_error -> 500
    | `Not_implemented -> 501
    | `Bad_gateway -> 502
    | `Service_unavailable -> 503
    | `Gateway_timeout -> 504
    | `Http_version_not_supported -> 505


let string_of_http_status =
  function
      (* 1xx: (informational) *)
    | `Continue -> "Continue"
    | `Switching_protocols -> "Switching Protocols"
      (* 2xx: (successful) *)
    | `Ok -> "OK"
    | `Created -> "Created"
    | `Accepted -> "Accepted"
    | `Non_authoritative -> "Non-authoritative Information"
    | `No_content -> "No Content"
    | `Reset_content -> "Reset Content"
    | `Partial_content -> "Partial Content"
      (* 3xx: (redirection) *)
    | `Multiple_choices -> "Multiple Choices"
    | `Moved_permanently -> "Moved Permanently"
    | `Found -> "Found"
    | `See_other -> "See Other"
    | `Not_modified -> "Not Modified"
    | `Use_proxy -> "Use Proxy"
    | `Temporary_redirect -> "Temporary Redirect"
      (* 4xx: (client error) *)
    | `Bad_request -> "Bad Request"
    | `Unauthorized -> "Unauthorized"
    | `Payment_required -> "Payment Required"
    | `Forbidden -> "Forbidden"
    | `Not_found -> "Not Found"
    | `Method_not_allowed -> "Method Not Allowed"
    | `Not_acceptable -> "Not Acceptable"
    | `Proxy_auth_required -> "Proxy Authorization Required"
    | `Request_timeout -> "Request Timeout"
    | `Conflict -> "Conflict"
    | `Gone -> "Gone"
    | `Length_required -> "Length Required"
    | `Precondition_failed -> "Precondition Failed"
    | `Request_entity_too_large -> "Request Entity Too Large"
    | `Request_uri_too_long -> "Request URI Too Long"
    | `Unsupported_media_type -> "Unsupported Media Type"
    | `Requested_range_not_satisfiable -> "Request Range Not Satisfiable"
    | `Expectation_failed -> "Expectation Failed"
      (* 5xx: (server error) *)
    | `Internal_server_error -> "Internal Server Error"
    | `Not_implemented -> "Not Implemented"
    | `Bad_gateway -> "Bad Gateway"
    | `Service_unavailable -> "Service Unavailable"
    | `Gateway_timeout -> "Gateway Timeout"
    | `Http_version_not_supported -> "HTTP Version Not Supported"


let http_status_of_int =
  function
      (* 1xx: (informational) *)
    | 100 -> `Continue
    | 101 -> `Switching_protocols
      (* 2xx: (successful) *)
    | 200 -> `Ok
    | 201 -> `Created
    | 202 -> `Accepted
    | 203 -> `Non_authoritative
    | 204 -> `No_content
    | 205 -> `Reset_content
    | 206 -> `Partial_content
      (* 3xx: (redirection) *)
    | 300 -> `Multiple_choices
    | 301 -> `Moved_permanently
    | 302 -> `Found
    | 303 -> `See_other
    | 304 -> `Not_modified
    | 305 -> `Use_proxy
    | 307 -> `Temporary_redirect
      (* 4xx: (client error) *)
    | 400 -> `Bad_request
    | 401 -> `Unauthorized
    | 402 -> `Payment_required
    | 403 -> `Forbidden
    | 404 -> `Not_found
    | 405 -> `Method_not_allowed
    | 406 -> `Not_acceptable
    | 407 -> `Proxy_auth_required
    | 408 -> `Request_timeout
    | 409 -> `Conflict
    | 410 -> `Gone
    | 411 -> `Length_required
    | 412 -> `Precondition_failed
    | 413 -> `Request_entity_too_large
    | 414 -> `Request_uri_too_long
    | 415 -> `Unsupported_media_type
    | 416 -> `Requested_range_not_satisfiable
    | 417 -> `Expectation_failed
      (* 5xx: (server error) *)
    | 500 -> `Internal_server_error
    | 501 -> `Not_implemented
    | 502 -> `Bad_gateway
    | 503 -> `Service_unavailable
    | 504 -> `Gateway_timeout
    | 505 -> `Http_version_not_supported
    | _ -> raise Not_found

type http_method = string * string
  (** Method name, URI *)

type cache_control_token =
    [ `No_store
    | `Max_age of int
    | `Max_stale of int option
    | `Min_fresh of int
    | `No_transform
    | `Only_if_cached
    | `Public
    | `Private of string list
    | `No_cache of string list
    | `Must_revalidate
    | `Proxy_revalidate
    | `S_maxage of int
    | `Extension of string * string option
    ]

type etag =
    [ `Weak of string
    | `Strong of string
    ]

let weak_validator_match e1 e2 =
  match (e1,e2) with
    | (`Strong s1, `Strong s2) -> s1 = s2
    | (`Strong s1, `Weak w2) -> s1 = w2
    | (`Weak w1, `Strong s2) -> w1 = s2
    | (`Weak w1, `Weak w2) -> w1 = w2

let strong_validator_match e1 e2 =
  match (e1,e2) with
    | (`Strong s1, `Strong s2) -> s1 = s2
    | _ -> false
  
exception Bad_header_field of string

class type http_header = Netmime.mime_header
class type http_header_ro = Netmime.mime_header_ro
class type http_trailer = Netmime.mime_header
class type http_trailer_ro = Netmime.mime_header_ro


type cookie =
    { cookie_name : string;
      cookie_value : string;
      cookie_expires : float option;
      cookie_domain : string option;
      cookie_path : string option;
      cookie_secure : bool;
    }


let status_re =
  Netstring_pcre.regexp "^([0-9]+)([ \t]+(.*))?$"

let status_of_cgi_header hdr =
  let (code, phrase) =
    try
      let status = hdr # field "Status" in
      ( match Netstring_pcre.string_match status_re status 0 with
	  | Some m ->
	      (int_of_string (Netstring_pcre.matched_group m 1 status),
	       (try Netstring_pcre.matched_group m 3 status with Not_found -> "")
	      )
	  | None ->
	      failwith "Bad Status response header field"
		(* Don't know what to do *)
      )
    with
	Not_found ->
	  (* Maybe there is a [Location] header: *)
	  ( try
	      let location = hdr # field "Location" in
	      (302, "Found")
	    with
		Not_found ->
		  (* Default: 200 OK *)
		  (200, "OK")
	  )
  in
  (* Repair [phrase] if empty: *)
  let phrase =
    if phrase = "" then 
      ( try string_of_http_status (http_status_of_int code)
	with Not_found -> "Unknown"
      )
    else
      phrase in
  (code, phrase)
;;


let query_re =
  Netstring_pcre.regexp "^([^?]*)\\?(.*)$"

let decode_query req_uri =
  match Netstring_pcre.string_match query_re req_uri 0 with
    | Some m ->
	(Netstring_pcre.matched_group m 1 req_uri,
	 Netstring_pcre.matched_group m 2 req_uri)
    | None ->
	(req_uri, "")

let host_re =
  Netstring_pcre.regexp "([^: \t]+)(:([0-9]+))?$"

let split_host_port s =
  match Netstring_pcre.string_match host_re s 0 with
    | Some m ->
	let host_name = Netstring_pcre.matched_group m 1 s in
	let host_port =
	  try Some(int_of_string(Netstring_pcre.matched_group m 3 s))
	  with
	    | Not_found -> None
	in
	(host_name, host_port)
    | None ->
	failwith "Invalid hostname"

let uripath_encode s =
  let l = Neturl.split_path s in
  let l' = List.map (Netencoding.Url.encode ~plus:false) l in
  Neturl.join_path l'

let uripath_decode s =
  let l = Neturl.split_path s in
  let l' = 
    List.map
      (fun u -> 
	 let u' = Netencoding.Url.decode ~plus:false u in
	 if String.contains u' '/' then
	   failwith "Nethttp.uripath_decode";
	 u')
      l in
  Neturl.join_path l'


module Header = struct
  open Netmime
  open Mimestring

  (* As scanner we use the scanner for mail header fields from Mimestring. It
   * is very configurable.
   *)

  let std_special_chars =
        [ ','; ';'; '=' ]
	  (* CHECK: Maybe we should add more characters, e.g. '@'. They are not
	   * used in HTTP, and including them here would cause that field values
	   * containing them are rejected. Maybe we want that.
	   *)

  let scan_value ?(specials = std_special_chars) s = 
    let scanner = create_mime_scanner ~specials ~scan_options:[] s in
    Stream.from
      (fun _ ->
	 Some (snd (scan_token scanner)))
	
  (* ---- Parser combinators for stream parsers: ---- *)
 
  let rec parse_comma_separated_list subparser stream =
    (* The [subparser] is required to return its value when it finds a
     * comma (i.e. [Special ','], or when it finds [End]. These tokens
     * must not be swallowed.
     *)
    match stream with parser
      | [< expr = subparser; rest = parse_comma_separated_rest subparser >] ->
	  expr :: rest
      | [< >] ->
	  []

  and parse_comma_separated_rest subparser stream =
    match stream with parser
      | [< '(Special ','); _ = parse_commas; list = parse_comma_separated_list subparser >] ->
	  list
      | [< 'End >] ->
	  []

  and parse_commas stream =
    match stream with parser
      | [< '(Special ','); _ = parse_commas >] ->
	  ()
      | [< >] ->
	  ()

  let merge_lists mh fieldparser fieldname =
    let fields = mh # multiple_field fieldname in
    if fields = [] then raise Not_found;
    List.flatten (List.map fieldparser fields)

  let parse_field mh fn_name f_parse fieldname =
    try
      let field = mh # field fieldname in
      f_parse (scan_value field)
    with
      | Stream.Failure
      | Stream.Error _ ->
	  raise (Bad_header_field fn_name)

  let parse_comma_separated_field ?specials mh fn_name f_parse fieldname =
    let fieldparser field =
      try
	parse_comma_separated_list f_parse (scan_value ?specials field)
      with
	| Stream.Failure
	| Stream.Error _ ->
	    raise (Bad_header_field fn_name) in
    merge_lists mh fieldparser fieldname

  (* ----- Common parsers/printer: ---- *)
	      
  let parse_token_list mh fn_name fieldname =
    let parse_token stream =
      match stream with parser 
	| [< '(Atom tok) >] -> tok
    in
    parse_comma_separated_field mh fn_name parse_token fieldname

  let parse_token_or_qstring stream =
    match stream with parser
      | [< '(Atom tok) >] -> tok
      | [< '(QString v) >] -> v

  let rec parse_params stream =
    match stream with parser
      | [< '(Special ';'); 
	   '(Atom name); '(Special '='); v = parse_token_or_qstring;
	   rest = parse_params
	>]->
	  (name,v) :: rest
      | [< >] ->
	  []

  let parse_extended_token_list mh fn_name fieldname =
    (* token [ '=' (token|qstring) ( ';' token '=' (token|qstring) ) * ] *)
    let rec parse_extended_token stream =
      match stream with parser
	| [< '(Atom tok); extension = parse_equation >] ->
	    ( match extension with
		  Some (eq_val, params) ->
		    (tok, Some eq_val, params)
		| None ->
		    (tok, None, [])
	    )
    and parse_equation stream =
      match stream with parser
	| [< '(Special '='); v = parse_token_or_qstring; params = parse_params >] ->
	    Some (v, params)
	| [< >] ->
	    None
    in
    parse_comma_separated_field mh fn_name parse_extended_token fieldname

  let qstring_indicator_re = 
    Netstring_pcre.regexp "[\\\\\"()<>@,;:/[\\]?={} \\x00-\\x1f\\x7f]"

  let qstring_re = Netstring_pcre.regexp "[\\\\\\\"]"
		     (* = backslash, double quotes *)

  let qstring_of_value s =
    (* Returns a qstring *)
      "\"" ^ Netstring_pcre.global_replace qstring_re "\\\\\\0" s ^ "\""
	(* Escape qstring_re with a backslash *)

  let string_of_value s =
    (* Returns a token or a qstring, depending on the value of [s] *)
    try 
      ignore(Netstring_pcre.search_forward qstring_indicator_re s 0);
      qstring_of_value s
    with
	Not_found -> s

  let string_of_params l =
    if l = [] then
      ""
    else
      ";" ^ 
      String.concat
	";"
	(List.map
	   (fun (n,s) -> 
	      n ^ "=" ^ string_of_value s)
	   l)

  let string_of_extended_token fn_name =
    function
      | (tok, None, []) ->
	  tok
      | (tok, None, _) ->
	  invalid_arg fn_name
      | (tok, Some eq_val, params) ->
	  tok ^ "=" ^ eq_val ^ string_of_params params

  let parse_parameterized_token_list mh fn_name fieldname =
    (* token ( ';' token '=' (token|qstring) ) * *)
    let rec parse_parameterized_token stream =
      match stream with parser
	| [< '(Atom tok); params = parse_params >] ->
	    (tok, params)
    in
    parse_comma_separated_field mh fn_name parse_parameterized_token fieldname

  let string_of_parameterized_token (tok, params) =
    tok ^ string_of_params params

  let q_split ( l : (string * (string * string) list) list )  
              : (string * (string * string) list * (string * string) list) list
              =
    (* Find the "q" param, and split [params] at that position *)
    let rec split params =
      match params with
	| [] -> ([], [])
	| ("q", q) :: rest -> ([], params)
	| other :: rest -> 
	    let before, after = split rest in
	    (other :: before), after
    in
    List.map
      (fun (tok, params) ->
	 let before, after = split params in
	 (tok, before, after))
      l

  let q_merge fn_name (tok, params, q_params) =
    if List.mem_assoc "q" params then invalid_arg fn_name;
    ( match q_params with
	| ( "q", _ ) :: _
	| [] ->
	    (tok, (params @ q_params))
	| _ ->
	    invalid_arg fn_name
    )


  let date_of_string fn_name s =
    try
      Netdate.parse_epoch s
    with
	Invalid_argument _ -> 
	  raise(Bad_header_field fn_name)

  let string_of_date f =
    Netdate.format ~fmt:"%a, %d %b %Y %H:%M:%S GMT" (Netdate.create ~zone:0 f)

  let sort_by_q ?(default=1.0) toks_with_params =
    (* Sorts [toks_with_params] such that the highest [q] values come first.
     * Tokens with a [q] value of 0 are removed. Tokens without [q] value
     * are assumed to have the [default] value. This is also done with 
     * unparseable [q] values.
     *)
    List.map
      snd
      (List.stable_sort
	 (fun (q1, tok_param1) (q2, tok_param2) ->
	    Pervasives.compare q2 q1)
	 (List.filter
	    (fun (q, tok_param) ->
	       q > 0.0)
	    (List.map
	       (fun (tok, params) ->
		  try 
		    let q_str = List.assoc "q" params in
		    (float_of_string q_str, (tok, params))
		  with
		    | Not_found -> (default, (tok, params))
		    | Failure _ -> (default, (tok, params))
	       )
	       toks_with_params)))

  let sort_by_q' ?default tok_with_params_and_qparams =
    List.map 
      (fun ((tok, tok_params), q_params) -> (tok, tok_params, q_params))
      (sort_by_q
	 ?default
	 (List.map
	    (fun (tok, tok_params, q_params) -> ((tok, tok_params), q_params))
	    tok_with_params_and_qparams))

  (* ---- The field accessors: ---- *)

  let get_accept mh =
    q_split
      (parse_parameterized_token_list mh "Nethttp.get_accept" "Accept")

  let set_accept mh av =
    let s =
      String.concat ","
      (List.map
	 (fun triple -> 
	    string_of_parameterized_token (q_merge "Nethttp.set_accept" triple))
	 av) in
    mh # update_field "Accept" s

  let best_media_type mh supp =
    let supp' =
      (* All of [supp] not mentioned in the [Accept] field *)
      let toks = try get_accept mh with Not_found -> [] in
      List.filter (fun supp_type -> 
		     not (List.exists (fun (t,_,_) -> t=supp_type) toks)) supp
    in
    let rec find_best toks =
      match toks with
	| (tok, params, qparams) :: toks' ->
	    ( if List.mem tok supp then
		(tok, params)
	      else
		let (main_type, sub_type) = Mimestring.split_mime_type tok in
		if sub_type = "*" then (
		  try
		    (List.find
		       (fun supp_type ->
			  (main_type = "*") || 
			  (sub_type = "*" && 
		              main_type = fst(Mimestring.split_mime_type supp_type))
		       )
		       supp',
		     params)
		  with
		      Not_found -> find_best toks'
		)
		else find_best toks'
	    )
	| [] ->
	    (* Nothing acceptable: *)
	    ("", [])
    in
    try
      let mt_list = sort_by_q' (get_accept mh) in  (* or Not_found *)
      find_best mt_list
    with
	Not_found -> ("*/*", [])

  let get_accept_charset mh =
    parse_parameterized_token_list mh
      "Nethttp.get_accept_charset" "Accept-Charset"

  let set_accept_charset mh l =
    mh # update_field
      "Accept-Charset" 
      (String.concat "," (List.map string_of_parameterized_token l))

  let best_tok_of_list toks supp = 
    let tok =
      List.find
	(fun tok -> tok = "*" || List.mem tok supp)
	toks in
    if tok = "*" then
      List.find (fun tok -> not (List.mem tok toks)) supp
    else
      tok

  let best_charset mh supp =
    try
      let toks_with_params = get_accept_charset mh in  (* or Not_found *)
      (* Special handling of ISO-8859-1: *)
      let toks_with_params' =
	if not(List.mem_assoc "*" toks_with_params) && 
	  not(List.exists
		(fun (tok,_) -> String.lowercase tok = "iso-8859-1") 
		toks_with_params) 
	then
	  toks_with_params @ [ "ISO-8859-1", ["q", "1.0"] ]
	else
	  toks_with_params in
      let toks' = List.map fst (sort_by_q toks_with_params') in
      best_tok_of_list toks' supp
    with
	Not_found -> "*"

  let get_accept_encoding mh =
    parse_parameterized_token_list mh
      "Nethttp.get_accept_encoding" "Accept-Encoding"

  let set_accept_encoding mh l =
    mh # update_field
      "Accept-Encoding" 
      (String.concat "," (List.map string_of_parameterized_token l))

  let best_encoding mh supp =
    try
      let toks_with_params = sort_by_q (get_accept_encoding mh) in
      best_tok_of_list (List.map fst toks_with_params) supp
    with
	Not_found -> "identity"

  let get_accept_language mh =
    parse_parameterized_token_list mh
      "Nethttp.get_accept_language" "Accept-Language"

  let set_accept_language mh l =
    mh # update_field
      "Accept-Language" 
      (String.concat "," (List.map string_of_parameterized_token l))

  let get_accept_ranges mh =
    parse_token_list mh "Nethttp.get_accept_ranges" "Accept-Ranges"

  let set_accept_ranges mh toks =
    mh # update_field "Accept-Ranges" (String.concat "," toks)

  let get_age mh =
    try
      float_of_string (mh # field "Age")
    with
	Failure _ -> raise(Bad_header_field "Nethttp.get_age")

  let set_age mh v =
    mh # update_field "Age" (Printf.sprintf "%0.f" v)

  let get_allow mh =
    parse_token_list mh "Nethttp.get_allow" "Allow"

  let set_allow mh toks =
    mh # update_field "Allow" (String.concat "," toks)

  let comma_split_re = Netstring_pcre.regexp "([ \t]*,)+[ \t]*"

  let comma_split =
    Netstring_pcre.split comma_split_re
      
  let parse_opt_eq_token stream =
    match stream with parser
      | [< '(Special '='); 
	   v = (fun stream ->
		  match stream with parser
		    | [< '(Atom v) >] -> v
		    | [< '(QString v) >] -> v);
	>] -> Some v
      | [< >] -> None

  let parse_cc_directive stream =
    match stream with parser
      | [< '(Atom "no-cache"); name_opt = parse_opt_eq_token >] ->
	  ( match name_opt with
	      | None -> `No_cache []
	      | Some names -> `No_cache(comma_split names)
	  )
      | [< '(Atom "no-store") >] -> 
	  `No_store
      | [< '(Atom "max-age"); '(Special '='); '(Atom seconds) >] ->
	  `Max_age(int_of_string seconds)
      | [< '(Atom "max-stale"); delta_opt = parse_opt_eq_token >] ->
	  ( match delta_opt with
	      | None -> `Max_stale None
	      | Some seconds -> `Max_stale(Some(int_of_string seconds))
	  )
      | [< '(Atom "min-fresh"); '(Special '='); '(Atom seconds) >] ->
	  `Min_fresh(int_of_string seconds)
      | [< '(Atom "no-transform") >] -> 
	  `No_transform
      | [< '(Atom "only-if-cached") >] -> 
	  `Only_if_cached
      | [< '(Atom "public") >] -> 
	  `Public
      | [< '(Atom "private"); name_opt = parse_opt_eq_token >] ->
	  ( match name_opt with
	      | None -> `Private []
	      | Some names -> `Private(comma_split names)
	  )
      | [< '(Atom "must-revalidate") >] -> 
	  `Must_revalidate
      | [< '(Atom "proxy-revalidate") >] -> 
	  `Proxy_revalidate
      | [< '(Atom "s-maxage"); '(Special '='); '(Atom seconds)>] ->
	  `S_maxage(int_of_string seconds)
      | [< '(Atom extension); val_opt = parse_opt_eq_token >] ->
	  `Extension(extension, val_opt)

  let get_cache_control mh =
    parse_comma_separated_field
      mh "Nethttp.get_cache_control" parse_cc_directive "Cache-Control"

  let set_cache_control mh l =
    let s = 
      String.concat ","
	(List.map
	   (function
	      | `No_store -> "no-store"
	      | `Max_age n -> "max-age=" ^ string_of_int n
	      | `Max_stale None -> "max-stale"
	      | `Max_stale(Some n) -> "max-stale=" ^ string_of_int n
	      | `Min_fresh n -> "min-fresh=" ^ string_of_int n
	      | `No_transform -> "no-transform"
	      | `Only_if_cached -> "only-if-cached"
	      | `Public -> "public"
	      | `Private names -> "private=\"" ^ String.concat "," names ^ "\""
	      | `No_cache [] -> "no-cache"
	      | `No_cache names -> "no-cache=\"" ^ String.concat "," names ^ "\""
	      | `Must_revalidate -> "must-revalidate"
	      | `Proxy_revalidate -> "proxy-revalidate"
	      | `S_maxage n -> "s-maxage=" ^ string_of_int n
	      | `Extension(tok,None) -> tok
	      | `Extension(tok, Some param) -> tok ^ "=" ^ string_of_value param
	   )
	   l) in
    mh # update_field "Cache-Control" s

  let get_connection mh =
    parse_token_list mh "Nethttp.get_connection" "Connection"

  let set_connection mh toks =
    mh # update_field "Connection" (String.concat "," toks)

  let get_content_encoding mh =
    parse_token_list mh "Nethttp.get_content_encoding" "Content-Encoding"

  let set_content_encoding mh toks =
    mh # update_field "Content-Encoding" (String.concat "," toks)

  let get_content_language mh =
    parse_token_list mh "Nethttp.get_content_language" "Content-Language"

  let set_content_language mh toks =
    mh # update_field "Content-Language" (String.concat "," toks)

  let get_content_length mh =
    try
      Int64.of_string (mh # field "Content-Length")
    with
	Failure _ -> raise (Bad_header_field "Nethttp.get_content_length")

  let set_content_length mh n =
    mh # update_field "Content-Length" (Int64.to_string n)

  let get_content_location mh =
    mh # field "Content-Location"

  let set_content_location mh s =
    mh # update_field "Content-Location" s

  let get_content_md5 mh =
    mh # field "Content-MD5"

  let set_content_md5 mh s =
    mh # update_field "Content-MD5" s

  let parse_byte_range_resp_spec stream =
    match stream with parser
      | [< '(Special '*') >] -> 
	  None
      | [< '(Atom first); '(Special '-'); '(Atom last) >] -> 
	  Some(Int64.of_string first, Int64.of_string last)

  let parse_byte_range_resp_length stream =
    match stream with parser
      | [< '(Special '*') >] -> 
	  None
      | [< '(Atom length) >] ->
	  Some(Int64.of_string length)

  let parse_content_range_spec stream =
    match stream with parser
      | [< '(Atom "bytes"); 
	  br=parse_byte_range_resp_spec; 
	  '(Special '/');
	  l=parse_byte_range_resp_length;
	  'End
         >] ->
	  `Bytes(br,l)

  let get_content_range mh =
    let s = mh # field "Content-Range" in
    let stream = scan_value ~specials:[ ','; ';'; '='; '*'; '-'; '/' ] s in
    try
      parse_content_range_spec stream 
    with
      | Stream.Failure
      | Stream.Error _
      | Failure _ ->
	  raise (Bad_header_field "Nethttp.get_content_range")

  let set_content_range mh (`Bytes(range_opt,length_opt)) =
    let s = 
      ( match range_opt with
	  | Some (first,last) -> Int64.to_string first ^ "-" ^ Int64.to_string last
	  | None -> "*"
      ) ^ "/" ^ 
      ( match length_opt with
	  | Some length -> Int64.to_string length
	  | None -> "*"
      ) in
    mh # update_field "Content-Range" s

  let get_content_type mh =
    try
      List.hd
	(parse_parameterized_token_list mh
	   "Nethttp.get_content_type" "Content-Type")
    with
	Failure _ -> raise(Bad_header_field "Nethttp.get_content_type")

  let set_content_type mh (tok,params) =
    mh # update_field
      "Content-Type" 
      (string_of_parameterized_token (tok,params))

  let get_date mh =
    date_of_string "Nethttp.get_date" (mh # field "Date")

  let set_date mh d =
    mh # update_field "Date" (string_of_date d)

  let parse_etag_token stream =
    match stream with parser
      | [< '(Atom "W"); '(Special '/'); '(QString e) >] ->
	  `Weak e
      | [< '(QString e) >] ->
	  `Strong e

  let parse_etag stream =
    match stream with parser
      | [< etag=parse_etag_token; 'End >] -> etag

  let get_etag mh =
    let s = mh # field "ETag" in
    let stream = scan_value ~specials:[ ','; ';'; '='; '/' ] s in
    try parse_etag stream
    with
      | Stream.Failure
      | Stream.Error _
      | Failure _ ->
	  raise (Bad_header_field "Nethttp.get_etag")

  let string_of_etag =
    function
      | `Weak s -> "W/" ^ qstring_of_value s
      | `Strong s -> qstring_of_value s
	  
  let set_etag mh etag =
    mh # update_field "ETag" (string_of_etag etag)

  let get_expect mh =
    parse_extended_token_list mh "Nethttp.get_expect" "Expect"

  let set_expect mh expectation =
    mh # update_field "Expect" 
      (String.concat "," 
	 (List.map (string_of_extended_token "Nethttp.set_expect") expectation))

  let get_expires mh =
    date_of_string "Nethttp.get_expires" (mh # field "Expires")

  let set_expires mh d =
    mh # update_field "Expires" (string_of_date d)

  let get_from mh =
    mh # field "From"

  let set_from mh v =
    mh # update_field "From" v

  let get_host mh =
    let s = mh # field "Host" in
    try
      split_host_port s
    with
      | Failure _ -> raise(Bad_header_field "Nethttp.get_host")

  let set_host mh (host,port_opt) =
    let s = 
      host ^ 
      ( match port_opt with Some p -> ":" ^ string_of_int p | None -> "") in
    mh # update_field "Host" s

  let parse_etag_or_star_tok stream =
    match stream with parser
      | [< '(Special '*') >] -> None
      | [< etag=parse_etag_token >] -> Some etag

  let get_etag_list mh fn_name fieldname =
    let specials = [ ','; ';'; '='; '/'; '*' ] in
    let l =
      parse_comma_separated_field
	~specials mh fn_name parse_etag_or_star_tok fieldname in
    if List.mem None l then
      None
    else
      Some(List.map (function Some e -> e | None -> assert false) l)

  let set_etag_list mh fieldname l_opt =
    let v =
      match l_opt with
	| None -> "*"
	| Some l ->
	    String.concat "," (List.map string_of_etag l) in
    mh # update_field fieldname v

  let get_if_match mh =
    get_etag_list mh "Nethttp.get_if_match" "If-Match"

  let set_if_match mh =
    set_etag_list mh "If-Match"

  let get_if_modified_since mh =
    date_of_string "Nethttp.get_if_modified_since" (mh # field "If-Modified-Since")

  let set_if_modified_since mh d =
    mh # update_field "If-Modified-Since" (string_of_date d)

  let get_if_none_match mh =
    get_etag_list mh "Nethttp.get_if_none_match" "If-None-Match"

  let set_if_none_match mh =
    set_etag_list mh "If-None-Match"

  let get_if_range mh =
    let s = mh # field "If-Range" in
    let stream = scan_value ~specials:[ ','; ';'; '='; '/' ] s in
    try `Etag (parse_etag stream)
    with
      | Stream.Failure
      | Stream.Error _
      | Failure _ ->
	  `Date (date_of_string "Nethttp.get_if_range" s)
  
  let set_if_range mh v =
    let s =
      match v with
	| `Etag e -> string_of_etag e
	| `Date d -> string_of_date d in
    mh # update_field "If-Range" s

  let get_if_unmodified_since mh =
    date_of_string "Nethttp.get_if_unmodified_since" 
      (mh # field "If-Unmodified-Since")

  let set_if_unmodified_since mh d =
    mh # update_field "If-Unmodified-Since" (string_of_date d)

  let get_last_modified mh =
    date_of_string "Nethttp.get_last_modified" (mh # field "Last-Modified")

  let set_last_modified mh d =
    mh # update_field "Last-Modified" (string_of_date d)

  let get_location mh =
    mh # field "Location"

  let set_location mh s =
    mh # update_field "Location" s

  let get_max_forwards mh =
    try
      int_of_string (mh # field "Max-Forwards")
    with
	Failure _ -> raise(Bad_header_field "Nethttp.get_max_forwards")

  let set_max_forwards mh n =
    mh # update_field "Max-Forwards" (string_of_int n)

  let parse_pragma_directive stream =
    match stream with parser
      | [< '(Atom tok); param_opt = parse_opt_eq_token >] -> (tok, param_opt)

  let get_pragma mh =
    parse_comma_separated_field
      mh "Nethttp.get_pragma" parse_pragma_directive "Pragma"

  let set_pragma mh l =
    let s =
      String.concat ","
	(List.map 
	   (function
	      | (tok, None) -> tok
	      | (tok, Some param) -> tok ^ "=" ^ string_of_value param)
	   l) in
    mh # update_field "Pragma" s

  let parse_opt_last_pos stream =
    match stream with parser
      | [< '(Atom last) >] -> Some(Int64.of_string last)
      | [< >] -> None

  let rec parse_byte_range_spec stream =
    match stream with parser
      | [< '(Atom first); '(Special '-'); last=parse_opt_last_pos; 
	   r=parse_byte_range_spec_rest
	>] ->
	  (Some (Int64.of_string first), last) :: r
      | [< '(Special '-'); '(Atom suffix_length);
	   r=parse_byte_range_spec_rest
	>] ->
	  (None, Some(Int64.of_string suffix_length)) :: r
      | [< >] ->
	  []

  and parse_byte_range_spec_rest stream =
    match stream with parser
      | [< '(Special ','); _=parse_commas; r=parse_byte_range_spec >] -> r
      | [< >] -> []

  let parse_ranges_specifier stream =
    match stream with parser
      | [< '(Atom "bytes"); 
	  '(Special '=');
	  r=parse_byte_range_spec; 
	  'End
         >] ->
	  `Bytes r

  let get_range mh =
    let s = mh # field "Range" in
    let stream = scan_value ~specials:[ ','; ';'; '='; '*'; '-'; '/' ] s in
    try
      parse_ranges_specifier stream
    with
      | Stream.Failure
      | Stream.Error _
      | Failure _ ->
	  raise (Bad_header_field "Nethttp.get_range")

  let set_range mh (`Bytes l) =
    let s =
      "bytes=" ^ 
      String.concat ","
	(List.map
	   (function
	      | (Some first, Some last) ->
		  Int64.to_string first ^ "-" ^ Int64.to_string last
	      | (Some first, None) ->
		  Int64.to_string first ^ "-"
	      | (None, Some last) ->
		  "-" ^ Int64.to_string last
	      | (None, None) ->
		  invalid_arg "Nethttp.set_range")
	   l) in
    mh # update_field "Range" s
	
  let get_referer mh =
    mh # field "Referer"

  let get_referrer = get_referer

  let set_referer mh s =
    mh # update_field "Referer" s

  let set_referrer = set_referer

  let get_retry_after mh =
    let s = mh # field "Retry-After" in
    try
      `Seconds(int_of_string s)
    with
	Failure _ -> `Date(date_of_string "Nethttp.get_retry_after" s)

  let set_retry_after mh v =
    let s =
      match v with
	| `Seconds n -> string_of_int n 
	| `Date d -> string_of_date d in
    mh # update_field "Retry-After" s

  let get_server mh =
    mh # field "Server"

  let set_server mh name =
    mh # update_field "Server" name

  let get_te mh =
    q_split
      (parse_parameterized_token_list mh "Nethttp.get_te" "TE")

  let set_te mh te =
    let s =
      String.concat ","
      (List.map
	 (fun triple -> 
	    string_of_parameterized_token (q_merge "Nethttp.set_te" triple))
	 te) in
    mh # update_field "TE" s

  let get_trailer mh =
    parse_token_list mh "Nethttp.get_trailer" "Trailer"

  let set_trailer mh fields =
    mh # update_field "Trailer" (String.concat "," fields)

  let get_transfer_encoding mh =
    parse_parameterized_token_list mh "Nethttp.get_transfer_encoding" "Transfer-Encoding"

  let set_transfer_encoding mh te =
    let s =
      String.concat ","
      (List.map string_of_parameterized_token te) in
    mh # update_field "Transfer-Encoding" s

  let get_upgrade mh =
    parse_token_list mh "Nethttp.get_upgrade" "Upgrade"

  let set_upgrade mh fields =
    mh # update_field "Upgrade" (String.concat "," fields)

  let get_user_agent mh =
    mh # field "User-Agent"

  let set_user_agent mh s =
    mh # update_field "User-Agent" s

  let get_vary mh =
    let l = parse_token_list mh "Nethttp.get_vary" "Vary" in
    if List.mem "*" l then
      `Star
    else
      `Fields l

  let set_vary mh v =
    let s =
      match v with
	| `Star -> "*"
	| `Fields l -> String.concat "," l in
    mh # update_field "Vary" s


  (* --- Authentication --- *)

  let parse_challenges mh fn_name fieldname =
    let rec parse_auth_params stream =
      match stream with parser
	| [< '(Atom ap_name); '(Special '='); ap_val = parse_token_or_qstring;
             rest = parse_auth_param_rest
	  >] ->
	    (ap_name, ap_val) :: rest

    and parse_auth_param_rest stream =
      match Stream.npeek 3 stream with
	| [ (Special ','); (Atom _); (Special '=') ] ->
	    ( match stream with parser
		| [< '(Special ',');
		     '(Atom ap_name); '(Special '='); 
		     ap_val = parse_token_or_qstring;
		     rest = parse_auth_param_rest
		  >] ->
		    (ap_name, ap_val) :: rest
		| [< >] ->    (* should not happen... *)
		    []
	    )
	| _ ->
	    []

    and parse_challenge stream =
      match stream with parser
	| [< '(Atom auth_scheme); auth_params = parse_auth_params >] ->
	    (auth_scheme, auth_params)
    in
    parse_comma_separated_field mh fn_name parse_challenge fieldname
      
  let mk_challenges fields =
    String.concat "," 
      (List.map
	 (fun (auth_name, auth_params) ->
	    auth_name ^ " " ^ 
	      (String.concat ","
		 (List.map
		    (fun (p_name, p_val) ->
		       p_name ^ "=" ^ string_of_value p_val)
		    auth_params))
	 )
	 fields)

  let get_www_authenticate mh =
    parse_challenges mh "Nethttp.get_www_authenticate" "WWW-Authenticate"

  let set_www_authenticate mh fields =
    mh # update_field "WWW-Authenticate" (mk_challenges fields)

  let get_proxy_authenticate mh =
    parse_challenges mh "Nethttp.get_proxy_authenticate" "Proxy-Authenticate"

  let set_proxy_authenticate mh fields =
    mh # update_field "Proxy-Authenticate" (mk_challenges fields)

  let ws_re = Netstring_pcre.regexp "[ \t\r\n]+";;

  let parse_credentials mh fn_name fieldname =
    let rec parse_creds stream =
      match stream with parser
	| [< '(Atom auth_name);
	     params = parse_auth_params
	  >] ->
	    (auth_name, params)
	     
    and parse_auth_params stream =
      match stream with parser
	| [< '(Atom ap_name); '(Special '='); ap_val = parse_token_or_qstring;
             rest = parse_auth_param_rest
	  >] ->
	    (ap_name, ap_val) :: rest

    and parse_auth_param_rest stream =
      match stream with parser
	| [< '(Special ',');
	     '(Atom ap_name); '(Special '='); 
	     ap_val = parse_token_or_qstring;
	     rest = parse_auth_param_rest
	  >] ->
	    (ap_name, ap_val) :: rest
	| [< >] ->
	    []
    in

    (* Basic authentication is a special case! *)
    let v = mh # field fieldname in  (* or Not_found *)
    match Netstring_pcre.split ws_re v with
      | [ name; creds ] when String.lowercase name = "basic" ->
	  ("basic", ["credentials", creds])
      | _ ->
	  parse_field mh fn_name parse_creds fieldname

  let mk_credentials (auth_name, auth_params) =
    if String.lowercase auth_name = "basic" then (
      let creds = 
	try List.assoc "credentials" auth_params 
	with Not_found -> 
	  failwith "Nethttp.mk_credentials: basic credentials not found" in
      "Basic " ^ creds
    )
    else
      auth_name ^ " " ^ 
	(String.concat ","
	   (List.map
	      (fun (p_name, p_val) ->
		 p_name ^ "=" ^ string_of_value p_val)
	      auth_params))

  let get_authorization mh =
    parse_credentials mh "Nethttp.get_authorization" "authorization"

  let set_authorization mh v =
    mh # update_field "Authorization" (mk_credentials v)

  let get_proxy_authorization mh = 
    parse_credentials mh "Nethttp.get_proxy_authorization" "proxy-authorization"

  let set_proxy_authorization mh v = 
    mh # update_field "Proxy-Authorization" (mk_credentials v)




  (* --- Cookies --- *)

  exception No_equation of string

  let split_name_is_value s =
    (* Recognizes a string "name=value" and returns the pair (name,value).
     * If the string has the wrong format, the function will raise
     * No_equation, and the argument of the exception is the unparseable
     * string.
     *)
    try
      let p = String.index s '=' in
      (String.sub s 0 p, String.sub s (p+1) (String.length s - p - 1))
    with
	Not_found ->
          raise(No_equation s)

  let spaces_at_beginning_re = Pcre.regexp "^\\s+";;
  let spaces_at_end_re = Pcre.regexp "\\s+$";;

  let strip_spaces s =
    (* Remove leading and trailing spaces: *)
    Pcre.qreplace ~rex:spaces_at_end_re
      (Pcre.qreplace ~rex:spaces_at_beginning_re s)

  let split_cookies_re = Pcre.regexp "[ \t\r\n]*;[ \t\r\n]*" ;;

  let get_cookie mh =
    let cstrings = mh # multiple_field "Cookie" in
    (* Remove leading and trailing spaces: *)
    let cstrings' = List.map strip_spaces cstrings in
    let partss = List.map
                   (fun cstring ->
                      Pcre.split
                        ~max:(-1)
                        ~rex:split_cookies_re
                        cstring
                   )
                   cstrings' in
    let parts = List.flatten partss in

    List.map
      (fun part ->
         let n,v =
           try split_name_is_value part
           with No_equation _ -> (part, "")
                (* Because it is reported that MSIE returns just "n" instead
                 * of "n=" when the value v is empty
                 *)
         in
         let n_dec = Netencoding.Url.decode n in
         let v_dec = Netencoding.Url.decode v in
         (n_dec, v_dec)
      )
      parts

  let set_cookie mh l =
    let s =
      String.concat ";"
	(List.map
	   (fun (n,v) -> 
	      Netencoding.Url.encode n ^ "=" ^ Netencoding.Url.encode v)
	   l) in
    mh # update_field "Cookie" s

  let set_set_cookie mh l =
    let cookie_fields =
      List.map
	(fun c ->
	   let enc_name  = Netencoding.Url.encode ~plus:false c.cookie_name in
	   let enc_value = Netencoding.Url.encode ~plus:false c.cookie_value in
	   enc_name ^ "=" ^ enc_value ^ 
	   ( match c.cookie_expires with
		 None -> ""
	       | Some t -> 
		   ";EXPIRES=" ^ Netdate.mk_usenet_date t
	   ) ^ 
	   (match c.cookie_domain with
		None -> ""
	      | Some d ->
		  ";DOMAIN=" ^ d
	   ) ^
	   (match c.cookie_path with
		None -> ""
	      | Some p ->
		  ";PATH=" ^ p 
	   ) ^
	   if c.cookie_secure then ";SECURE" else ""
	)
	l
    in
    mh # update_multiple_field "Set-cookie" cookie_fields


end
