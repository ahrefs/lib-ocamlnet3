(* $Id$ *)

open Netplex_types
open Genlex
open Printf

exception Config_error of string

class address = object end

type ext_config_tree =
    [ `Section of address * string * ext_config_tree list
	(* (relative_name, contents) *)
    | `Parameter of address * string * param_value
	(* (relative_name, contents) *)
    ]


let is_win32 =
  match Sys.os_type with
    | "Win32" -> true
    | _ -> false;;


let mk_absolute dir path =
  if Netsys.is_absolute path then
    path
  else
    Filename.concat dir path


let parse_config_file filename =
  let rec parse_tree stream =
    match Stream.peek stream with
      | Some (Ident id) ->
          ignore(Stream.next stream);
          let v = parse_rhs stream in
	  ( match v with
	      | `Section tl -> `Section(id, tl)
	      | `Parameter p -> `Parameter(id, p)
	  )
      | _ -> raise Stream.Failure

  and parse_tree_list stream =
    let t_opt =
      try Some(parse_tree stream)
      with Stream.Failure -> None in
    match t_opt with
      | Some t ->
          let r = semi_parse_tree_list stream in
          t :: r
      | None ->
          []

  and semi_parse_tree_list stream =
    match Stream.peek stream with
      | Some (Kwd ";") ->
          ignore(Stream.next stream);
          parse_tree_list stream
      | _ ->
          []

  and parse_tree_semi stream =
    let t = parse_tree stream in
    ignore(semi_list stream);
    t

  and semi_list stream =
    match Stream.peek stream with
      | Some (Kwd ";") ->
          ignore(Stream.next stream);
          ignore(semi_list stream);
      | _ ->
          ()

  and parse_rhs stream =
    match Stream.peek stream with
      | Some (Kwd "=") ->
          ignore(Stream.next stream);
          let v = parse_param_value stream in
          `Parameter v
      | Some (Kwd "{") ->
          ignore(Stream.next stream);
          let tl = parse_tree_list stream in
          let tok = Stream.next stream in
          if tok <> Kwd "}" then raise Stream.Failure;
          `Section tl
      | _ ->
          raise Stream.Failure

  and parse_param_value stream =
    match Stream.peek stream with
      | Some (Int n) -> ignore(Stream.next stream); `Int n
      | Some (Float f) -> ignore(Stream.next stream); `Float f
      | Some (String s) -> ignore(Stream.next stream); `String s
      | Some (Ident "false") -> ignore(Stream.next stream); `Bool false
      | Some (Ident "true") -> ignore(Stream.next stream); `Bool true
      | _ ->
          raise Stream.Failure
  in

  let line = ref 1 in
  let ch = open_in filename in
  try
    let s1 = Stream.of_channel ch in
    let s2 =
      Stream.from
	(fun _ ->
	   match Stream.peek s1 with
	     | None -> None
	     | Some '\n' ->
		 ignore(Stream.next s1);
		 incr line;
		 Some '\n'
	     | (Some _) as p ->
		 ignore(Stream.next s1);
		 p
	) in
    let lexer = Genlex.make_lexer [ "{"; "}"; "="; ";" ] s2 in
    try
      let tree =
	parse_tree_semi lexer in
      Stream.empty lexer;
      close_in ch;
      tree
    with
      | Stream.Failure ->
	  raise(Config_error(filename ^ ", line " ^ string_of_int !line ^ 
			       ": Syntax error"))
      | Stream.Error _ ->
	  raise(Config_error(filename ^ ", line " ^ string_of_int !line ^ 
			       ": Syntax error"))
  with
    | error ->
	close_in ch;
	raise error
;;


let rec ext_config_tree (tree : config_tree) : ext_config_tree =
  match tree with
    | `Section(name, tl) ->
	`Section(new address, name, List.map ext_config_tree tl)
    | `Parameter(name, v) ->
	`Parameter(new address, name, v)


let rec iter_config_tree f prefix cnt (tree : ext_config_tree) =
  match tree with
    | `Section(addr, name, tl) ->
	let n =
	  try 
	    Hashtbl.find cnt name
	  with
	    | Not_found ->
		Hashtbl.add cnt name 0;
		0 in
	Hashtbl.replace cnt name (n+1);
	let fullname = 
	  if prefix <> "" then 
	    prefix ^ "." ^ name ^ "[" ^ string_of_int n ^ "]"
	  else 
	    name in
	f addr fullname tree;
	List.iter (iter_config_tree f fullname (Hashtbl.create 10)) tl
    | `Parameter(addr, name, v) ->
	let fullname = if prefix <> "" then prefix ^ "." ^ name else name in
	if Hashtbl.mem cnt name then
	  raise(Config_error("Parameter defined twice: " ^ fullname));
	Hashtbl.add cnt name 0;
	f addr fullname tree;
;;	


class repr_config_file filename0 simple_tree : Netplex_types.config_file =
  let tree = ext_config_tree simple_tree in
  let filename =
    mk_absolute (Unix.getcwd()) filename0 in
object(self)
  val addresses = Hashtbl.create 100

  initializer (
    try
      iter_config_tree
	(fun addr fullname subtree ->
	   Hashtbl.add addresses addr (fullname,subtree)
	)
	""
	(Hashtbl.create 10)
	tree
    with
      | Config_error msg -> 
	  raise(Config_error (filename ^ ": " ^ msg))
  )

  method filename = filename
  method tree = simple_tree

  method root_addr =
    match tree with
      | `Section(a,_,_) -> a
      | `Parameter(a,_,_) -> a

  method root_name =
    match tree with
      | `Section(_,n,_) -> n
      | `Parameter(_,n,_) -> n

  method resolve_section addr name =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#resolve_section" in
    match subtree with
      | `Section(_,_,tl) ->
	  List.map
	    (function
	       | `Section(addr,_,_) -> addr
	       | _ -> assert false
	    )
	    (List.filter
	       (function
		  | `Section(_,n,_) -> n = name
		  | _ -> false)
	       tl
	    )
      | `Parameter _ ->
	  []

  method restrict_subsections addr names =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#restrict_subsections" in
    match subtree with
      | `Section(_,_,tl) ->
	  List.iter
	    (function
	       | `Section(a,n,_) ->
		   if not (List.mem n names) then
		     raise(Config_error(filename ^ ": Section " ^ 
					  self#print addr ^ 
					  " must not contain subsection '" ^ 
					  n ^ "'"))
	       | _ -> ())
	    tl
      | _ -> 
	  failwith "#restrict_subsections"

  method restrict_parameters addr names =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#restrict_parameters" in
    match subtree with
      | `Section(_,_,tl) ->
	  List.iter
	    (function
	       | `Parameter(a,n,_) ->
		   if not (List.mem n names) then
		     raise(Config_error(filename ^ ": Section " ^ 
					  self#print addr ^ 
					  " must not contain parameter '" ^ 
					  n ^ "'"))
	       | _ -> ())
	    tl
      | _ -> 
	  failwith "#restrict_parameters"


  method resolve_parameter addr name =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#resolve_parameter" in
    match subtree with
      | `Section(_,_,tl) ->
	  let vl =
	    List.map
	      (function
		 | `Parameter(addr,_,_) -> addr
		 | _ -> assert false
	      )
	      (List.filter
		 (function
		    | `Parameter(_,n,_) -> n = name
		    | _ -> false)
		 tl
	      ) in
	  ( match vl with
	      | [] -> raise Not_found
	      | [v] -> v
	      | _ ->
		  raise(Config_error(filename ^ ": Several definitions for parameter " ^ fullname ^ " found"))
	  )
      | `Parameter _ ->
	  raise Not_found

  method print addr =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#print" in
    fullname

  method string_param addr =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#string_param" in
    match subtree with
      | `Parameter(_,_,`String s) -> s
      | _ -> 
	  raise(Config_error(filename ^ ": Parameter " ^ fullname ^ 
			       " is not a string"))


  method int_param addr =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#int_param" in
    match subtree with
      | `Parameter(_,_,`Int s) -> s
      | _ ->
	  raise(Config_error(filename ^ ": Parameter " ^ fullname ^ 
			       " is not an integer"))

  method float_param addr =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#float_param" in
    match subtree with
      | `Parameter(_,_,`Float s) -> s
      | _ ->
	  raise(Config_error(filename ^ ": Parameter " ^ fullname ^ 
			       " is not a floating-point number"))

  method bool_param addr =
    let (fullname, subtree) =
      try
	Hashtbl.find addresses addr
      with
	| Not_found ->
	    failwith "#bool_param" in
    match subtree with
      | `Parameter(_,_,`Bool b) -> b
      | _ ->
	  raise(Config_error(filename ^ ": Parameter " ^ fullname ^ 
			       " is not a boolean value"))

end


let repr_config_file = new repr_config_file


let read_config_file filename =
  let tree = parse_config_file filename in
  repr_config_file filename tree


let inet4_binding =
  Netstring_str.regexp "^\\([0-9.]*\\):\\([0-9]+\\)$" ;;

let inet6_binding =
  Netstring_str.regexp "^\\[\\([0-9a-fA-F.:]*\\)\\]:\\([0-9]+\\)$" ;;

let host_binding =
  Netstring_str.regexp "^\\(.*\\):\\([0-9]+\\)$" ;;

let extract_address ptype socket_dir service_name proto_name cf addraddr =
  let typ =
    try
      cf # string_param
	(cf # resolve_parameter addraddr "type") 
    with
      | Not_found ->
	  failwith ("Missing parameter: " ^ cf#print addraddr ^ ".type") in
  let get_path() =
    try
      mk_absolute socket_dir
	(cf # string_param
	   (cf # resolve_parameter addraddr "path"))
    with
      | Not_found ->
	  failwith ("Missing parameter: " ^ cf#print addraddr ^ ".path") in
  let get_name() =
    try
      (cf # string_param
	      (cf # resolve_parameter addraddr "name"))
    with
      | Not_found ->
	  failwith ("Missing parameter: " ^ cf#print addraddr ^ ".name") in
  ( match typ with
      | "local" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "path" ];
	  let path = get_path() in
	  ( match Sys.os_type with
	      | "Win32" ->
		  [ `W32_pipe_file path ]
	      | _ ->
		  [ `Socket (Unix.ADDR_UNIX path) ]
	  )
      | "unixdomain" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "path" ];
	  let path = get_path() in
	  [ `Socket (Unix.ADDR_UNIX path) ]
      | "socket_file" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "path" ];
	  let path = get_path() in
	  [ `Socket_file path ]
      | "w32_pipe" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "path" ];
	  let path = get_path() in
	  [ `W32_pipe path ]
      | "w32_pipe_file" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "path" ];
	  let path = get_path() in
	  [ `W32_pipe_file path ]
      | "container" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type" ];
	  [ `Container(socket_dir,service_name,proto_name,`Any) ]
      | "internal" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "name" ];
          let name = get_name() in
          if ptype = `Multi_threading then (
            [ `Internal name ]
          )
          else []
      | "internet" ->
	  cf # restrict_subsections addraddr [];
	  cf # restrict_parameters addraddr [ "type"; "bind" ];
	  let bind =
	    try
	      cf # string_param
		(cf # resolve_parameter addraddr "bind") 
	    with
	      | Not_found ->
		  failwith ("Missing parameter: " ^ cf#print addraddr ^ ".bind") in
	  ( match Netstring_str.string_match inet4_binding bind 0 with
	      | Some m ->
		  ( try
		      let a = 
			Unix.inet_addr_of_string
			  (Netstring_str.matched_group m 1 bind) in
		      let p =
			int_of_string
			  (Netstring_str.matched_group m 2 bind) in
		      [ `Socket (Unix.ADDR_INET(a,p)) ]
		    with
		      | _ ->
			  failwith ("Cannot parse " ^ cf#print addraddr ^ 
				      ".bind")
		  )
	      | None ->
		  ( match Netstring_str.string_match inet6_binding bind 0 with
		      | Some m ->
			  ( try
			      let a = 
				Unix.inet_addr_of_string
				  (Netstring_str.matched_group m 1 bind) in
			      let p =
				int_of_string
				  (Netstring_str.matched_group m 2 bind) in
			      [ `Socket (Unix.ADDR_INET(a,p)) ]
			    with
			      | _ ->
				  failwith ("Cannot parse " ^ cf#print addraddr ^ 
					      ".bind")
			  )
		      | None ->
			  ( match Netstring_str.string_match host_binding bind 0 with
			      | Some m ->
				  ( try
				      let h = 
					Netstring_str.matched_group m 1 bind in
				      let p =
					int_of_string
					  (Netstring_str.matched_group m 2 bind) in
				      let entry =
					Uq_resolver.get_host_by_name h in
				      let al =
					Array.to_list
					  entry.Unix.h_addr_list in
				      List.map
					(fun a ->
					   `Socket(Unix.ADDR_INET(a,p))
					)
					al
				    with
				      | _ ->
					  failwith ("Cannot parse or resolve " ^ cf#print addraddr ^ 
						      ".bind")
				  )
			      | None ->
				  failwith ("Cannot parse " ^ cf#print addraddr ^ 
					      ".bind")
			  )
		  )
	  )

      | _ ->
	  failwith ("Bad parameter: " ^ cf#print addraddr ^ ".type")
  )
;;

let read_netplex_config_ ptype c_logger_cfg c_wrkmng_cfg c_proc_cfg cf =
  
  if cf # root_name <> "netplex" then
    failwith ("Not a netplex configuration file");

  (* - Additional subsections of the root are intentionally allowed!
  cf # restrict_subsections cf#root_addr [ "controller"; "service" ];
   *)
  cf # restrict_parameters cf#root_addr [];

  let ctrl_cfg = Netplex_controller.extract_config c_logger_cfg cf in
  let socket_dir = ctrl_cfg # socket_directory in

  let parse_owner prefix s =
    try
      let p = 
        try String.index s ':'
        with Not_found -> failwith "missing ':'" in
      let u_str = String.sub s 0 p in
      let g_str = String.sub s (p+1) (String.length s - p - 1) in
      let u =
        try int_of_string u_str
        with Failure _ ->
          try (Unix.getpwnam u_str).Unix.pw_uid
          with Not_found ->
            failwith ("unknown user: " ^ u_str) in
      let g =
        try int_of_string g_str
        with Failure _ ->
          try (Unix.getgrnam g_str).Unix.gr_gid
          with Not_found ->
            failwith ("unknown group: " ^ g_str) in
      (u,g)
    with
      | Failure msg ->
           failwith (prefix ^ msg) in

  let services =
    List.map
      (fun addr ->
	 cf # restrict_subsections addr [ "protocol"; "processor";
					  "workload_manager" ];
	 cf # restrict_parameters addr [ "name"; "user"; "group";
					 "startup_timeout"; "conn_limit";
					 "gc_when_idle"
				       ];

	 let service_name =
	   try
	     cf # string_param (cf # resolve_parameter addr "name")
	   with
	     | Not_found ->
		 failwith ("Missing parameter: " ^ cf#print addr ^ ".name") in
	 
	 let user_opt =
	   try
	     Some(cf # string_param (cf # resolve_parameter addr "user"))
	   with
	     | Not_found -> None in

	 let group_opt =
	   try
	     Some(cf # string_param (cf # resolve_parameter addr "group"))
	   with
	     | Not_found -> None in

	 let user_group_opt =
	   match (user_opt, group_opt) with
	     | Some user, Some group -> 
		 let user_ent =
		   try Unix.getpwnam user
		   with Not_found ->
		     failwith ("Unknown user: " ^ cf#print addr ^ ".user") in
		 let group_ent =
		   try Unix.getgrnam group
		   with Not_found ->
		     failwith ("Unknown group: " ^ cf#print addr ^ ".group") in
		 Some(user_ent.Unix.pw_uid, group_ent.Unix.gr_gid)
	     | Some user, None ->
		 let user_ent =
		   try Unix.getpwnam user
		   with Not_found ->
		     failwith ("Unknown user: " ^ cf#print addr ^ ".user") in
		 Some(user_ent.Unix.pw_uid, user_ent.Unix.pw_gid)
	     | None, Some _ ->
		 failwith("Missing user parameter for: " ^ cf#print addr ^
			    ".group")
	     | None, None -> None in

	 if user_group_opt <> None then (
	    if Unix.geteuid() <> 0 then
	      failwith "Cannot set user and group if not running as root";
	 );

	 let startup_timeout =
	   try
	     cf # float_param (cf # resolve_parameter addr "startup_timeout")
	   with
	     | Not_found -> 60.0 in

	 let conn_limit =
	   try
	     Some(cf # int_param (cf # resolve_parameter addr "conn_limit"))
	   with
	     | Not_found -> None in

	 let gc_when_idle =
	   try
	     cf # bool_param (cf # resolve_parameter addr "gc_when_idle")
	   with
	     | Not_found -> false in

	 let protocols =
	   List.map
	     (fun protaddr ->
		cf # restrict_subsections protaddr [ "address" ];
		cf # restrict_parameters protaddr [ "name";
						    "lstn_backlog";
						    "lstn_reuseaddr";
						    "so_keepalive";
						    "tcp_nodelay";
                                                    "local_chmod";
                                                    "local_chown";
						  ];

		let prot_name =
		  try
		    cf # string_param (cf # resolve_parameter protaddr "name")
		  with
		    | Not_found ->
			failwith ("Missing parameter: " ^ cf#print protaddr ^ ".name") in
		let lstn_backlog =
		  try
		    cf # int_param (cf # resolve_parameter protaddr "lstn_backlog") 
		  with
		    | Not_found -> 20 in
		let lstn_reuseaddr =
		  try
		    cf # bool_param (cf # resolve_parameter protaddr "lstn_reuseaddr") 
		  with
		    | Not_found -> true in
		let so_keepalive =
		  try
		    cf # bool_param (cf # resolve_parameter protaddr "so_keepalive") 
		  with
		    | Not_found -> true in
		let tcp_nodelay =
		  try
		    cf # bool_param (cf # resolve_parameter protaddr "tcp_nodelay") 
		  with
		    | Not_found -> false in
                let local_chmod =
                  try
                    Some(cf # int_param (cf # resolve_parameter protaddr "local_chmod"))
                  with
                    | Not_found -> None
                    | Config_error _ ->
                         (* so that octal numbers work *)
                         Some(int_of_string
                                (cf # string_param
                                   (cf # resolve_parameter protaddr "local_chmod"))) in
                let local_chown =
                  try
                    Some(parse_owner
                           (cf#print protaddr ^ ".local_chown: ")
                           (cf # string_param
                              (cf # resolve_parameter protaddr "local_chown")))
                  with
                    | Not_found -> None in

		let addresses =
		  List.flatten
		    (List.map
		       (extract_address
                          ptype socket_dir service_name prot_name cf)
		       (cf # resolve_section protaddr "address")) in

		( object
		    method name = prot_name
		    method addresses = Array.of_list addresses
		    method lstn_backlog = lstn_backlog
		    method lstn_reuseaddr = lstn_reuseaddr
		    method so_keepalive = so_keepalive
		    method tcp_nodelay = tcp_nodelay
                    method local_chmod = local_chmod
                    method local_chown = local_chown
		    method configure_slave_socket _ = ()
		  end
		)

	     )
	     (cf # resolve_section addr "protocol") in

	 if protocols = [] then
	   failwith ("Section " ^ cf#print addr ^ " requires a sub-section 'protocol'");

	 let sockserv_config =
	   ( object
	       method name = service_name
	       method protocols = protocols
	       method change_user_to = user_group_opt
	       method startup_timeout = startup_timeout
	       method conn_limit = conn_limit
	       method gc_when_idle = gc_when_idle
	       method controller_config = ctrl_cfg
	     end
	   ) in

	 let procaddr =
	   match cf # resolve_section addr "processor" with
	     | [] ->
		 failwith ("Missing section: " ^ cf#print addr ^ ".processor")
	     | [a] -> a
	     | _ ->
		 failwith ("Only one section allowed: " ^ cf#print addr ^ 
			     ".processor") in

	 let processor_type =
	   try
	     cf # string_param (cf # resolve_parameter procaddr "type")
	   with
	     | Not_found ->
		 failwith ("Missing parameter: " ^ cf#print procaddr ^ ".type")
	 in

	 let create_processor_config =
	   try
	     List.find
	       (fun cfg -> cfg # name = processor_type)
	       c_proc_cfg
	   with
	     | Not_found ->
		 failwith ("No such processor type: "  ^ processor_type) in

	 let wrkmngaddr =
	   match cf # resolve_section addr "workload_manager" with
	     | [] ->
		 failwith ("Missing section: " ^ cf#print addr ^
			     ".workload_manager")
	     | [a] -> a
	     | _ ->
		 failwith ("Only one section allowed: " ^ cf#print addr ^ 
			     ".workload_manager") in

	 let wrkmng_type =
	   try
	     cf # string_param (cf # resolve_parameter wrkmngaddr "type")
	   with
	     | Not_found ->
		 failwith ("Missing parameter: " ^ cf#print wrkmngaddr ^ ".type")
	 in

	 let create_wrkmng_config =
	   try
	     List.find
	       (fun cfg -> cfg # name = wrkmng_type)
	       c_wrkmng_cfg
	   with
	     | Not_found ->
		 failwith ("No such workload_manager type: "  ^ wrkmng_type) in

	 ( sockserv_config, 
	   (procaddr, create_processor_config), 
	   (wrkmngaddr, create_wrkmng_config) )
      )
      (cf # resolve_section cf#root_addr "service") in

  ( object
      method ptype = ptype
      method controller_config = ctrl_cfg 
      method services = services
    end
      : netplex_config
  )
;;


let read_netplex_config ptype c_logger_cfg c_wrkmng_cfg c_proc_cfg cf =
  try
    read_netplex_config_ ptype c_logger_cfg c_wrkmng_cfg c_proc_cfg cf
  with
    | Failure msg ->
	raise (Config_error(cf#filename ^ ": " ^ msg))


let read_pem (cf:config_file) pname addr =
  let basedir = Filename.dirname cf#filename in
  try
    `PEM_file(mk_absolute
                basedir
                (cf # string_param (cf # resolve_parameter addr pname)))
  with
    | Not_found ->
         failwith ("Bad section: " ^ cf # print addr)


let read_key (cf:config_file) addr =
  let basedir = Filename.dirname cf#filename in
  let cert =
    read_pem cf "crt_file" addr in
  let key =
    read_pem cf "key_file" addr in
  let pw_opt =
    try
      Some(cf # string_param (cf # resolve_parameter addr "password"))
    with
      | Not_found ->
           try
             let name = cf # string_param 
                               (cf # resolve_parameter addr "password_file") in
             let name = mk_absolute basedir name in
             let ch = open_in name in
             let pw = try input_line ch with End_of_file -> "" in
             close_in ch;
             Some pw
           with
             | Not_found ->
                  None in
  (cert, key, pw_opt)


let read_x509_config (cf:config_file) a_x509 =
  let trust =
    List.map
      (read_pem cf "crt_file")
      (cf # resolve_section a_x509 "trust") in
  let revoke =
    List.map
      (read_pem cf "crl_file")
      (cf # resolve_section a_x509 "revoke") in
  let keys =
    List.map
      (read_key cf)
      (cf # resolve_section a_x509 "key") in
  (trust, revoke, keys)


let read_tls_config ?verify (cf:config_file) addr tls_opt =
  let basedir = Filename.dirname cf#filename in
  match cf#resolve_section addr "tls" with
    | [] ->
         None
    | [a_tls] ->
         ( match tls_opt with
             | None ->
                  failwith ("No TLS provider available, but config section " ^ 
                              cf # print addr ^ " exists")
             | Some tls ->
                  let algorithms =
                    try Some(cf # string_param
                                    (cf # resolve_parameter a_tls "algorithms"))
                    with Not_found -> None in
                  let dh_params =
                    match cf#resolve_section a_tls "dh_params" with
                      | [] -> None
                      | [a_dh] ->
                           ( try
                               Some(`PKCS3_PEM_file
                                     (mk_absolute basedir
                                        (cf # string_param
                                           (cf # resolve_parameter
                                                a_dh "pkcs3_file"))))
                             with
                               | Not_found ->
                                    try
                                      Some(`Generate
                                            (cf # int_param
                                              (cf # resolve_parameter 
                                                      a_dh "bits")))
                                    with
                                      | Not_found ->
                                           failwith("Bad section: " ^ 
                                                      cf # print a_dh)
                           )
                      | _ ->
                           failwith ("Several sections: " ^ 
                                       cf#print a_tls ^ ".dh_params") in
(*
                  let peer_name =
                    try Some(cf # string_param
                                    (cf # resolve_parameter a_tls "peer_name"))
                    with Not_found -> None in
 *)
                  let peer_auth =
                    try
                      match cf # string_param
                                   (cf # resolve_parameter a_tls "peer_auth")
                      with
                        | "none" -> `None
                        | "optional" -> `Optional
                        | "required" -> `Required
                        | s ->
                             failwith ("Bad parameter: " ^ cf # print a_tls ^ 
                                         ".peer_auth")
                    with Not_found -> `None in
                  ( match cf # resolve_section a_tls "x509" with
                      | [] ->
                           failwith ("Missing section: " ^ cf # print a_tls ^
                                       ".x509")
                      | [a_x509] ->
                           let (trust, revoke, keys) =
                             read_x509_config cf a_x509 in
                           Some(Netsys_tls.create_x509_config
                                  ?algorithms
                                  ?dh_params
                                  ?verify
                                  ~trust
                                  ~revoke
                                  ~keys
                                  ~peer_auth
                                  tls)
                      | _ ->
                           failwith ("Several sections: " ^ cf#print a_tls ^ 
                                       ".x509")
                  )
         )
    | _ ->
         failwith ("Several sections: " ^ cf#print addr ^ ".tls")
