(* $Id$ *)

open Netplex_types
open Printf

exception Sharedvar_type_mismatch of string
exception Sharedvar_no_permission of string
exception Sharedvar_not_found of string
exception Sharedvar_null

exception No_perm
exception Bad_type


let release = ref (fun () -> ())

let shm_size = 1024

let create_shm() =
  if Netsys_posix.have_posix_shm() then
    let fd, name = Netsys_posix.shm_create "/netplexshv" (8*shm_size) in
    let ba =
#ifdef HAVE_UNIX_MAP_FILE
      try
        Bigarray.array1_of_genarray
          (Unix.map_file fd Bigarray.int64 Bigarray.c_layout true [|shm_size|])
      with
        | Unix.Unix_error(error,_,file) ->
            raise (Sys_error
                     ((if file <> "" then file ^ ": " else "") ^
                        Unix.error_message error))
#else
      Bigarray.Array1.map_file
      fd Bigarray.int64 Bigarray.c_layout true shm_size
#endif
    in
    Bigarray.Array1.fill ba 0L;
    Unix.close fd;
    Netsys_posix.shm_unlink name;
    Some ba
  else
    None


let vsucc n =
  (* avoid any problems with cache coherency by duplicating the bits 24-31
     into 32-39
   *)
  let p =
    Int64.logor
      (Int64.logand n 0xffff_ffffL)
      (Int64.shift_right_logical (Int64.logand n 0xffff_ff00_0000_0000L) 8) in
  let p' = Int64.succ p in
  Int64.logor
    (Int64.logand p' 0xffff_ffffL)
    (Int64.shift_left (Int64.logand p' 0x00ff_ffff_ff00_0000L) 8)

let vok n =
  (* Check that the bits are duplicated *)
  let x1 = Int64.shift_right_logical (Int64.logand n 0xff00_0000L) 24 in
  let x2 = Int64.shift_right_logical (Int64.logand n 0xff_0000_0000L) 32 in
  x1 = x2

let vbigger v1 v2 =
  (* Return true if either v1 or v2 is not ok. Otherwise v1 > v2 *)
  not(vok v1) || not(vok v2) || v1 > v2


type var =
    { var_value : string;
      var_owner : string option;   (* ssn *)
      var_ro : bool;
      var_ty : string;             (* "encap" or "string" *)
      var_tmo : float;
      var_group : Unixqueue.group option ref;
      var_is_set : bool;
      var_notify : (Netplex_ctrl_aux.shvar_get -> unit) Queue.t;
      var_version : int64;
      var_shm_index : int option;
      mutable var_count : int;
    }


let x_plugin =
  ( object (self)
      val mutable variables = Hashtbl.create 50
      val mutable owns = Hashtbl.create 50
      val mutable shm = None
      val mutable shm_end = 1
      val mutable version = 0L

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

      method ctrl_added _ =
        if shm = None then
          shm <- create_shm()

      method ctrl_unplugged ctrl =
	List.iter
	  (fun cid ->
	     self # ctrl_container_finished ctrl cid true
	  )
	  ctrl#containers

      method ctrl_receive_call ctrl cid procname arg reply =
	let ssn = cid#socket_service_name in
	match procname with
	  | "ping" ->
	      reply(Some(Netplex_ctrl_aux._of_Sharedvar'V2'ping'res ()))

	  | "create_var" ->
	      let (var_name, own_flag, ro_flag, ty, tmo) =
		Netplex_ctrl_aux._to_Sharedvar'V2'create_var'arg arg in
              let owner =
                if own_flag then Some ssn else None in
	      let success =
		self # create_var ctrl owner var_name ro_flag ty tmo in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'create_var'res success))

	  | "set_value" ->
	      let (var_name, var_value, ty) =
		Netplex_ctrl_aux._to_Sharedvar'V2'set_value'arg arg in
	      let code =
		self # set_value ctrl (Some ssn) var_name var_value ty in
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
		self # delete_var ctrl (Some ssn) var_name in
	      reply(
		Some(Netplex_ctrl_aux._of_Sharedvar'V2'delete_var'res success))

	  | "wait_for_value" ->
	      let (var_name, ty) =
		Netplex_ctrl_aux._to_Sharedvar'V2'wait_for_value'arg arg in
	      self # wait_for_value ctrl ssn var_name ty
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
          | "shm_slot" ->
              let var_name =
                Netplex_ctrl_aux._to_Sharedvar'V2'shm_slot'arg arg in
              let r = self # shm_slot ctrl var_name in
              reply
                (Some
                   (Netplex_ctrl_aux._of_Sharedvar'V2'shm_slot'res r))
	  | _ ->
	      failwith ("Netplex_sharedvar: unknown proc " ^ procname)

      method ctrl_container_finished ctrl cid is_last =
	if is_last then (
	  let ssn = cid#socket_service_name in
	  let vars = try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	  Hashtbl.remove owns (ctrl,ssn);
	  List.iter
	    (fun var_name ->
	       ignore(self # delete_var ctrl (Some ssn) var_name)
	    )
	    vars
	)

      method shm = shm

      method variables = variables

      method create_var ctrl owner var_name ro_flag ty tmo =
	if Hashtbl.mem variables (ctrl,var_name) then
	  `shvar_exists
	else (
          let g_tmo = ref None in
          let var =
            { var_value = "";
              var_owner = owner;
              var_ro = ro_flag;
              var_ty = ty;
              var_tmo = tmo;
              var_group = g_tmo;
              var_is_set = false;
              var_notify = Queue.create();
              var_count = 0;
              var_version = vsucc version;
              var_shm_index = None;
            } in
	  Hashtbl.add variables (ctrl,var_name) var;
          ( match owner with
              | Some ssn ->
	          let ovars =
	            try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	          Hashtbl.replace owns (ctrl,ssn) (var_name :: ovars)
              | None -> ()
	  );
          self # restart_timer ctrl var_name g_tmo tmo;
          self # incr_version None;
	  `shvar_ok
	)

      method shm_slot ctrl var_name =
        try
          let var = Hashtbl.find variables (ctrl,var_name) in
          match var.var_shm_index with
            | Some i ->
                Some i
            | None ->
                ( match shm with
                    | None -> None
                    | Some ba ->
                        if shm_end < shm_size then (
                          let i = shm_end in
                          let var' =
                            { var with var_shm_index = Some i } in
                          shm_end <- shm_end + 1;
                          ba.{ i } <- var.var_version;
                          Hashtbl.replace variables (ctrl,var_name) var';
                          Some i
                        ) else
                          Some 0 (* the slot for the global version *)
                )
        with
          | Not_found -> None

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
               ignore(self # delete_var ctrl None var_name)
            )
        )
        else
          g_tmo := None

      method private incr_version idx_opt =
        version <- vsucc version;
        match shm with
          | None -> ()
          | Some ba ->
              ba.{ 0 } <- version;
              ( match idx_opt with
                  | None -> ()
                  | Some idx -> ba.{ idx } <- version
              )

      method delete_var ctrl ssn_opt var_name =
	try
	  let var =
	    Hashtbl.find variables (ctrl,var_name) in
	  ( match var.var_owner with
	      | None -> ()
	      | Some _ ->
                  if ssn_opt <> None && ssn_opt <> var.var_owner then
                    raise Not_found
	  );
	  Hashtbl.remove variables (ctrl,var_name);
          ( match !(var.var_group) with
              | None -> ()
              | Some g -> Unixqueue.clear ctrl#event_system g
          );
	  ( match var.var_owner with
              | Some ssn ->
	          let ovars =
	            try Hashtbl.find owns (ctrl,ssn) with Not_found -> [] in
	          let nvars =
	            List.filter (fun n -> n <> var_name) ovars in
	          Hashtbl.replace owns (ctrl,ssn) nvars
              | None -> ()
	  );
          self # incr_version var.var_shm_index;
	  Queue.iter
	    (fun f ->
	       self # schedule_callback ctrl f `shvar_notfound
	    )
	    var.var_notify;
	  `shvar_ok
	with
	  | Not_found ->
	      `shvar_notfound


      method set_value ctrl ssn_opt var_name var_value ty =
	try
	  let var = 
	    Hashtbl.find variables (ctrl,var_name) in
	  var.var_count <- var.var_count + 1;
	  ( match var.var_owner with
	      | None -> ()
	      | Some _ ->
                  if ssn_opt <> None && ssn_opt <> var.var_owner then
                    raise No_perm
	  );
	  if ty <> var.var_ty then raise Bad_type;
	  let q = Queue.create() in
	  Queue.transfer var.var_notify q;
          let var' =
            { var with
              var_value;
              var_is_set = true;
              var_version = vsucc version
            } in
	  Hashtbl.replace variables (ctrl,var_name) var';
          self # restart_timer ctrl var_name var.var_group var.var_tmo;
          self # incr_version var.var_shm_index;
	  Queue.iter
	    (fun f ->
	       self # schedule_callback
                        ctrl f (`shvar_ok(var_value,var'.var_version))
	    )
	    q;
	  `shvar_ok var'.var_version
	with
	  | Not_found ->
	      `shvar_notfound
	  | No_perm ->
	      `shvar_noperm
	  | Bad_type ->
	      `shvar_badtype


      method get_value ctrl var_name ty =
	try
	  let var =
	    Hashtbl.find variables (ctrl,var_name) in
	  var.var_count <- var.var_count + 1;
	  if ty <> var.var_ty then 
	    `shvar_badtype
	  else (
            self # restart_timer ctrl var_name var.var_group var.var_tmo;
	    `shvar_ok (var.var_value, var.var_version)
          )
	with
	  | Not_found -> 
	      `shvar_notfound

      method private wait_for_value ctrl ssn var_name ty emit =
	try
	  let var =
	    Hashtbl.find variables (ctrl,var_name) in
	  var.var_count <- var.var_count + 1;
	  if var.var_ty <> ty then
	    emit `shvar_badtype
	  else (
	    if var.var_is_set then
	      emit (`shvar_ok (var.var_value, var.var_version))
	    else (
	      Queue.push emit var.var_notify
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
	  (fun (_, n) var ->
	     if var_name ="*" || var_name = n then (
	       Netlog.logf lev
		 "Netplex_sharedvar.dump: name=%s count=%d"
		 n var.var_count
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

let dual_call name of_arg to_res arg f_ctrl =
  match Netplex_cenv.self_obj() with
    | `Container cont ->
        to_res (cont # call_plugin plugin name (of_arg arg))
    | `Controller ctrl ->
        f_ctrl ctrl

let create_var ?(own=false) ?(ro=false) ?(enc=false) ?(timeout = -1.0)
               ?ssn
               var_name =
  let ty = if enc then "encap" else "string" in
  let code =
    dual_call
      "create_var" 
      Netplex_ctrl_aux._of_Sharedvar'V2'create_var'arg
      Netplex_ctrl_aux._to_Sharedvar'V2'create_var'res
      (var_name,own,ro,ty,timeout)
      (fun ctrl ->
         if own && ssn=None then
           invalid_arg "Netplex_sharedvar.create_var: need 'ssn' parameter";
         x_plugin # create_var ctrl ssn var_name ro ty timeout
      ) in
  code = `shvar_ok
      
let delete_var var_name =
  let code =
    dual_call
      "delete_var"
      Netplex_ctrl_aux._of_Sharedvar'V2'delete_var'arg
      Netplex_ctrl_aux._to_Sharedvar'V2'delete_var'res
      var_name
      (fun ctrl -> x_plugin # delete_var ctrl None var_name) in
  code = `shvar_ok

let set_value_1 ty var_name var_value =
  let code =
    dual_call
      "set_value"
      Netplex_ctrl_aux._of_Sharedvar'V2'set_value'arg
      Netplex_ctrl_aux._to_Sharedvar'V2'set_value'res
      (var_name,var_value,ty)
      (fun ctrl -> x_plugin # set_value ctrl None var_name var_value ty) in
  match code with
    | `shvar_ok version -> Some version
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_notfound -> None
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | _ -> None

let set_value var_name var_value =
  set_value_1 "string" var_name var_value <> None

let set_enc_value var_name (var_value:encap) =
  let str_value =
    Marshal.to_string var_value [] in
  set_value_1 "encap" var_name str_value <> None

let shm_slot var_name =
  dual_call
    "shm_slot"
    Netplex_ctrl_aux._of_Sharedvar'V2'shm_slot'arg 
    Netplex_ctrl_aux._to_Sharedvar'V2'shm_slot'res
    var_name
    (fun ctrl -> x_plugin # shm_slot ctrl var_name)

let get_version var_name ty =
  let r =
    dual_call
      "get_value"
      Netplex_ctrl_aux._of_Sharedvar'V2'get_value'arg
      Netplex_ctrl_aux._to_Sharedvar'V2'get_value'res
      (var_name,ty)
      (fun ctrl -> x_plugin # get_value ctrl var_name ty) in
  ( match r with
      | `shvar_ok s -> (Some s)
      | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
      | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
      | `shvar_notfound -> None
      | _ -> None
  )

let get_value var_name =
  match get_version var_name "string" with
    | None -> None
    | Some(v,_) -> Some v

let get_enc_version var_name =
  match get_version var_name "encap" with
    | None -> None
    | Some(s,version) -> Some((Marshal.from_string s 0 : encap),version)


let get_enc_value var_name =
  match get_enc_version var_name with
    | None -> None
    | Some(v,_) -> Some v

let wait_for_value_1 ty var_name =
  let cont = Netplex_cenv.self_cont() in
  let code =
    Netplex_ctrl_aux._to_Sharedvar'V2'wait_for_value'res
      (cont # call_plugin plugin "wait_for_value"
	 (Netplex_ctrl_aux._of_Sharedvar'V2'wait_for_value'arg 
	    (var_name, ty))) in
  match code with
    | `shvar_ok(s,_) -> (Some s)
    | `shvar_badtype -> raise (Sharedvar_type_mismatch var_name)
    | `shvar_noperm -> raise (Sharedvar_no_permission var_name)
    | `shvar_notfound -> None
    | _ -> None
  
let wait_for_value var_name =
  wait_for_value_1 "string" var_name

let wait_for_enc_value var_name =
  match wait_for_value_1 "encap" var_name with
    | Some s ->
        Some (Marshal.from_string s 0)
    | None ->
        None


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

type _ payloadtype =
  | T_string : string payloadtype
  | T_encap : encap payloadtype

type 'a versioned_value =
    { vv_name : string;
      mutable vv_payload : ('a * int64) option;
      mutable vv_slot : int option;
      vv_type : 'a payloadtype;
    }

let get_payload : type t . t payloadtype -> string -> (t * int64) option =
  fun ty var_name ->
    match ty with
      | T_string -> get_version var_name "string"
      | T_encap -> get_enc_version var_name

let set_payload : type t . t payloadtype -> string -> t -> int64 option =
  fun ty var_name data ->
    match ty with
      | T_string -> set_value_1 "string" var_name data
      | T_encap -> set_value_1 "string" var_name (Marshal.to_string data [])

let vv_access_1 ty var_name =
  let vv_payload = get_payload ty var_name in
  { vv_name = var_name;
    vv_payload;
    vv_slot = None;
    vv_type = ty
  }

let vv_access var_name =
  vv_access_1 T_string var_name

let vv_access_enc var_name =
  vv_access_1 T_encap var_name

let vv_get vv =
  match vv.vv_payload with
    | Some(v,_) -> Some v
    | None -> None

let vv_version vv =
  match vv.vv_payload with
    | Some(_,v) -> v
    | None -> raise Not_found

let vv_update vv =
  let slot_opt =
    match vv.vv_slot with
      | Some k -> Some k
      | None -> shm_slot vv.vv_name in
  vv.vv_slot <- slot_opt;
  let need_update =
    match vv.vv_payload, slot_opt, x_plugin#shm with
      | Some(_, old_version), Some k, Some shm ->
          vbigger shm.{k} old_version
      | _ ->
          true in
  if need_update then
    vv.vv_payload <- get_payload vv.vv_type vv.vv_name;
  need_update

let vv_set vv new_value =
  match set_payload vv.vv_type vv.vv_name new_value with
    | Some version ->
        vv.vv_payload <- Some(new_value,version);
        true
    | None ->
        vv.vv_payload <- None;
        false

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

module type VV_TYPE =
  sig
    type t
    type var
    val access : string -> var
    val get : var -> t
    val set : var -> t -> unit
    val version : var -> int64
    val update : var -> bool
  end


module Make_vv(T:Netplex_cenv.TYPE) = struct
  type t = T.t
  type var = encap versioned_value
  module E = Netplex_encap.Make_encap(T)

  let access name = vv_access_enc name
  let get vv =
    match vv_get vv with
      | Some e -> 
	  ( try E.unwrap e
	    with Netplex_encap.Type_mismatch -> 
	      raise(Sharedvar_type_mismatch vv.vv_name)
	  )
      | None -> raise(Sharedvar_not_found vv.vv_name)
  let set vv x =
    let ok = 
      vv_set vv (E.wrap x) in
    if not ok then
      raise(Sharedvar_not_found vv.vv_name)
  let version vv =
    vv_version vv
  let update vv =
    vv_update vv
end


let global_prefix = "global."

let global_propagator() : Netsys_global.propagator =
  let ctrl =
    try
      match Netplex_cenv.self_obj() with
        | `Container _ -> raise Not_found
        | `Controller ctrl -> ctrl
    with
      | Not_found ->
          failwith "Netplex_sharedvar.global_propagator: must be called from \
                    controller context" in
  let version_offset = ref 0L in
  Netsys_global.iter
    (fun name value version ->
       version_offset := max !version_offset version;
       let netplex_name = global_prefix ^ name in
       let code =
         x_plugin # create_var ctrl None netplex_name false "string" (-1.0) in
       if code = `shvar_ok then (
         ignore(x_plugin # set_value ctrl None netplex_name value "string")
       )
    );
  let slot_tab = Hashtbl.create 51 in
  object
    method propagate name value =
      let netplex_name = global_prefix ^ name in
      match set_payload T_string netplex_name value with
        | Some version ->
            Int64.add version !version_offset
        | None ->
            ignore(create_var netplex_name);
            ( match set_payload T_string netplex_name value with
                | Some version ->
                    Int64.add version !version_offset
                | None ->
                    failwith ("Netplex_sharedvar.global_propagator: \
                               Cannot set variable: " ^ netplex_name)
            )

    method update name version =
      let netplex_name = global_prefix ^ name in
      let netplex_version = Int64.sub version !version_offset in
      let slot_opt =
        try
          Hashtbl.find slot_tab netplex_name
        with Not_found ->
          shm_slot netplex_name in
      Hashtbl.replace slot_tab netplex_name slot_opt;
      let need_update =
        match slot_opt, x_plugin#shm with
          | Some k, Some shm ->
              vbigger shm.{k} netplex_version
          | _ ->
              true in
      if need_update then
        match get_payload T_string netplex_name with
          | Some(value,np_vers) ->
              Some(value,Int64.add np_vers !version_offset)
          | None ->
              None
      else
        None
  end


let propagate_back ctrl =
  let lp = String.length global_prefix in
  Hashtbl.iter
    (fun (vctrl,netplex_name) var ->
       if vctrl = ctrl then (
         if String.length netplex_name >= lp &&
              String.sub netplex_name 0 lp = global_prefix
         then (
           let name =
             String.sub netplex_name lp (String.length netplex_name-lp) in
           Netsys_global.internal_set name var.var_value var.var_version
         )
       )
    )
    x_plugin#variables
