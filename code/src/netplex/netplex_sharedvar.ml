(* $Id$ *)

open Netplex_types

exception Sharedvar_type_mismatch of string
exception Sharedvar_no_permission of string
exception Sharedvar_not_found of string
exception Sharedvar_null

exception No_perm
exception Bad_type


let release = ref (fun () -> ())


let x_plugin =
  ( object (self)
      val mutable variables = Hashtbl.create 50
      val mutable owns = Hashtbl.create 50

      initializer (
	release :=
	  (fun () -> 
	     variables <- Hashtbl.create 1;
	     owns <- Hashtbl.create 1
	  )
      )

      method required = []

      method program =
	Netplex_ctrl_aux.program_Sharedvar'V2

      method ctrl_added _ = ()

      method ctrl_unplugged ctrl =
	List.iter
	  (fun cid ->
	     self # ctrl_container_finished ctrl cid true
	  )
	  ctrl#containers

      method ctrl_receive_call ctrl cid procname arg reply =
	match procname with
	  | "ping" ->
	      reply(Some(Netplex_ctrl_aux._of_Sharedvar'V2'ping'res ()))

	  | "create_var" ->
	      let (var_name, own_flag, ro_flag, ty, tmo) =
		Netplex_ctrl_aux._to_Sharedvar'V2'create_var'arg arg in
	      let success =
		self # create_var ctrl cid var_name own_flag ro_flag ty tmo in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'create_var'res success))

	  | "set_value" ->
	      let (var_name, var_value, ty) =
		Netplex_ctrl_aux._to_Sharedvar'V2'set_value'arg arg in
	      let code =
		self # set_value ctrl cid var_name var_value ty in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'set_value'res code))

	  | "get_value" ->
	      let (var_name, ty) =
		Netplex_ctrl_aux._to_Sharedvar'V2'get_value'arg arg in
	      let valopt =
		self # get_value ctrl var_name ty in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'get_value'res valopt))

	  | "delete_var" ->
	      let (var_name) =
		Netplex_ctrl_aux._to_Sharedvar'V2'delete_var'arg arg in
	      let success =
		self # delete_var ctrl cid var_name in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'delete_var'res success))

	  | "wait_for_value" ->
	      let (var_name, ty) =
		Netplex_ctrl_aux._to_Sharedvar'V2'wait_for_value'arg arg in
	      self # wait_for_value ctrl cid var_name ty
		(fun r -> 
		   reply
		     (Some
			(Netplex_ctrl_aux._of_Sharedvar'V2'wait_for_value'res 
			   r)))

	  | "dump" ->
	      let (var_name, levstr) =
		Netplex_ctrl_aux._to_Sharedvar'V2'dump'arg arg in
	      self # dump var_name levstr;
	      reply
		(Some(Netplex_ctrl_aux._of_Sharedvar'V2'dump'res ()))

	  | _ ->
	      failwith ("Netplex_sharedvar: unknown proc " ^ procname)

      method ctrl_container_finished ctrl cid is_last =
	if is_last then (
	  let ssn = cid#socket_service_name in
	  let vars = try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	  Hashtbl.remove owns (ctrl,ssn);
	  List.iter
	    (fun var_name ->
	       ignore(self # delete_var ctrl cid var_name)
	    )
	    vars
	)


      method private create_var ctrl cid var_name own_flag ro_flag ty tmo =
	let ssn = cid#socket_service_name in
	if Hashtbl.mem variables (ctrl,var_name) then
	  `shvar_exists
	else (
          let g_tmo = ref None in
	  Hashtbl.add 
	    variables 
	    (ctrl,var_name)
	    ("",
	     (if own_flag then Some ssn else None),
	     ro_flag,
             ty,
             tmo,
             g_tmo,
	     false,
	     Queue.create(),
	     ref 0
	    );
	  if own_flag then (
	    let ovars =
	      try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	    Hashtbl.replace owns (ctrl,ssn) (var_name :: ovars)
	  );
          self # restart_timer ctrl var_name g_tmo tmo;
	  `shvar_ok
	)

      method private restart_timer ctrl var_name g_tmo tmo =
        ( match !g_tmo with
            | None -> ()
            | Some g -> Unixqueue.clear ctrl#event_system g
        );
        if tmo >= 0.0 then (
          let g = Unixqueue.new_group ctrl#event_system in
          g_tmo := Some g;
          Unixqueue.weak_once ctrl#event_system g tmo
            (fun () -> 
               ignore(self # delete_var_force ctrl var_name)
            )
        )
        else
          g_tmo := None

      method private delete_var ctrl cid var_name =
	let ssn = cid#socket_service_name in
	try
	  let (_, owner, _, _, _, g_tmo, _, q, _) = 
	    Hashtbl.find variables (ctrl,var_name) in
	  ( match owner with
	      | None -> ()
	      | Some ssn' -> if ssn <> ssn' then raise Not_found
	  );
	  Hashtbl.remove variables (ctrl,var_name);
          ( match !g_tmo with
              | None -> ()
              | Some g -> Unixqueue.clear ctrl#event_system g
          );
	  if owner <> None then (
	    let ovars =
	       try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	    let nvars =
	      List.filter (fun n -> n <> var_name) ovars in
	    Hashtbl.replace owns (ctrl,ssn) nvars
	  );
	  Queue.iter
	    (fun f ->
	       self # schedule_callback ctrl f `shvar_notfound
	    )
	    q;
	  `shvar_ok
	with
	  | Not_found ->
	      `shvar_notfound


      method private delete_var_force ctrl var_name =
	try
	  let (_, owner, _, _, _, g_tmo, _, q, _) = 
	    Hashtbl.find variables (ctrl,var_name) in
	  Hashtbl.remove variables (ctrl,var_name);
          ( match !g_tmo with
              | None -> ()
              | Some g -> Unixqueue.clear ctrl#event_system g
          );
	  ( match owner with
              | None -> ()
              | Some ssn ->
	           let ovars =
	             try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	           let nvars =
	             List.filter (fun n -> n <> var_name) ovars in
	           Hashtbl.replace owns (ctrl,ssn) nvars
	  );
	  Queue.iter
	    (fun f ->
	       self # schedule_callback ctrl f `shvar_notfound
	    )
	    q;
	with
	  | Not_found ->
               ()


      method private set_value ctrl cid var_name var_value ty =
	let ssn = cid#socket_service_name in
	try
	  let (_, owner, ro, vty, tmo, g_tmo, _, q, count) = 
	    Hashtbl.find variables (ctrl,var_name) in
	  incr count;
	  ( match owner with
	      | None -> ()
	      | Some ssn' -> if ssn <> ssn' && ro then raise No_perm
	  );
	  if ty <> vty then raise Bad_type;
	  let q' = Queue.create() in
	  Queue.transfer q q';
	  Hashtbl.replace
	    variables
	    (ctrl,var_name)
	    (var_value, owner, ro, vty, tmo, g_tmo, true, q, count);
          self # restart_timer ctrl var_name g_tmo tmo;
	  Queue.iter
	    (fun f ->
	       self # schedule_callback ctrl f (`shvar_ok var_value)
	    )
	    q';
	  `shvar_ok
	with
	  | Not_found ->
	      `shvar_notfound
	  | No_perm ->
	      `shvar_noperm
	  | Bad_type ->
	      `shvar_badtype


      method get_value ctrl var_name ty =
	try
	  let (v, _, _, vty, tmo, g_tmo, _, _, count) = 
	    Hashtbl.find variables (ctrl,var_name) in
	  incr count;
	  if ty <> vty then 
	    `shvar_badtype
	  else (
            self # restart_timer ctrl var_name g_tmo tmo;
	    `shvar_ok v
          )
	with
	  | Not_found -> 
	      `shvar_notfound

      method private wait_for_value ctrl cid var_name ty emit =
	try
	  let (v, _, _, vty, _, _, is_set, q, count) = 
	    Hashtbl.find variables (ctrl,var_name) in
	  incr count;
	  if vty <> ty then
	    emit `shvar_badtype
	  else (
	    if is_set then
	      emit (`shvar_ok v)
	    else (
	      Queue.push emit q
	    )
	  )
	with
	  | Not_found -> 
	      emit `shvar_notfound


      method private schedule_callback ctrl f arg =
	let g = Unixqueue.new_group ctrl#event_system in
	Unixqueue.once ctrl#event_system g 0.0 (fun () -> f arg)

      method dump var_name levstr =
	let lev =
	  Netlog.level_of_string levstr in
	Hashtbl.iter
	  (fun (_, n) (_, _, _, _, _, _, _, _, count) ->
	     if var_name ="*" || var_name = n then (
	       Netlog.logf lev
		 "Netplex_sharedvar.dump: name=%s count=%d"
		 n !count
	     )
	  )
	  variables

    end
  )

let plugin = (x_plugin :> plugin)


let () =
  (* Release memory after [fork]: *)
  Netsys_posix.register_post_fork_handler
    (object
       method name = "Netplex_sharedvar"
       method run () = !release()
     end
    )

let create_var ?(own=false) ?(ro=false) ?(enc=false) ?(timeout = -1.0)
               var_name =
  let cont = Netplex_cenv.self_cont() in
  let ty = if enc then "encap" else "string" in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'create_var'res
      (cont # call_plugin plugin "create_var"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'create_var'arg 
	    (var_name,own,ro,ty,timeout))) in
  code = `shvar_ok
      
let delete_var var_name =
  let cont = Netplex_cenv.self_cont() in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'delete_var'res
      (cont # call_plugin plugin "delete_var"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'delete_var'arg var_name)) in
  code = `shvar_ok

let set_value var_name var_value =
  let cont = Netplex_cenv.self_cont() in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'set_value'res
      (cont # call_plugin plugin "set_value"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'set_value'arg 
	    (var_name,var_value,"string"))) in
  match code with
    | `shvar_ok -> true
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_notfound -> false
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | _ -> false

let set_enc_value var_name (var_value:encap) =
  let cont = Netplex_cenv.self_cont() in
  let str_value =
    Marshal.to_string var_value [] in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'set_value'res
      (cont # call_plugin plugin "set_value"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'set_value'arg 
	    (var_name,str_value,"encap"))) in
  match code with
    | `shvar_ok -> true
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_notfound -> false
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | _ -> false

let get_value var_name =
  let r =
    match Netplex_cenv.self_obj() with
      | `Container cont ->
	  Netplex_ctrl_aux._to_Sharedvar'V2'get_value'res
	    (cont # call_plugin plugin "get_value"
	       (Netplex_ctrl_aux._of_Sharedvar'V2'get_value'arg 
		  (var_name,"string"))) 
      | `Controller ctrl ->
	  x_plugin # get_value ctrl var_name "string" in
  ( match r with
      | `shvar_ok s -> (Some s)
      | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
      | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
      | `shvar_notfound -> None
      | _ -> None
  )

let get_enc_value var_name =
  let r =
    match Netplex_cenv.self_obj() with
      | `Container cont ->
	  Netplex_ctrl_aux._to_Sharedvar'V2'get_value'res
	    (cont # call_plugin plugin "get_value"
	       (Netplex_ctrl_aux._of_Sharedvar'V2'get_value'arg 
		  (var_name,"encap"))) 
      | `Controller ctrl ->
	  x_plugin # get_value ctrl var_name "encap" in
  ( match r with
      | `shvar_ok s -> 
	  let v = Marshal.from_string s 0 in
	  Some v
      | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
      | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
      | `shvar_notfound -> None
      | _ -> None
  )

let wait_for_value var_name =
  let cont = Netplex_cenv.self_cont() in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'wait_for_value'res
      (cont # call_plugin plugin "wait_for_value"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'wait_for_value'arg 
	    (var_name, "string"))) in
  match code with
    | `shvar_ok s -> (Some s)
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | `shvar_notfound -> None
    | _ -> None
  
let wait_for_enc_value var_name =
  let cont = Netplex_cenv.self_cont() in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'wait_for_value'res
      (cont # call_plugin plugin "wait_for_value"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'wait_for_value'arg 
	    (var_name, "encap"))) in
  match code with
    | `shvar_ok s -> 
	let v = Marshal.from_string s 0 in
	Some v
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | `shvar_notfound -> None
    | _ -> None
  


let get_lazily_any set wait var_name f =
  if create_var var_name then (
    let v_opt =
      try Some(f()) with _ -> None in
    ( match v_opt with
	| None -> 
	    let ok = delete_var var_name in assert ok; ()
	| Some v -> 
	    let ok = set var_name v in assert ok; ()
    );
    v_opt
  )
  else
    wait var_name

let get_lazily =
  get_lazily_any set_value wait_for_value

let get_enc_lazily =
  get_lazily_any set_enc_value wait_for_enc_value

let dump var_name lev =
  let levstr = Netlog.string_of_level lev in
  match Netplex_cenv.self_obj() with
    | `Container cont ->
	ignore
	  (cont # call_plugin plugin "dump"
	     (Netplex_ctrl_aux._of_Sharedvar'V2'dump'arg 
		(var_name,levstr))) 
    | `Controller ctrl ->
	x_plugin # dump var_name levstr

module Make_var_type(T:Netplex_cenv.TYPE) = struct
  type t = T.t
  module E = Netplex_encap.Make_encap(T)

  let get name =
    match get_enc_value name with
      | Some e -> 
	  ( try E.unwrap e
	    with Netplex_encap.Type_mismatch -> 
	      raise(Sharedvar_type_mismatch name)
	  )
      | None -> raise(Sharedvar_not_found name)

  let set name x =
    let ok = 
      set_enc_value name (E.wrap x) in
    if not ok then
      raise(Sharedvar_not_found name)
end
