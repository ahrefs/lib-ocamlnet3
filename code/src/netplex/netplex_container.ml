(* $Id$ *)

open Netplex_types
open Netplex_ctrl_aux
open Printf

class std_container ?(esys = Unixqueue.create_unix_event_system()) 
                    ptype sockserv =
object(self)
  val sys_esys = Unixqueue.create_unix_event_system()
  val mutable rpc = None
  val mutable sys_rpc = None
  val mutable nr_conns = 0
  val mutable engines = []

  method socket_service = sockserv

  method event_system = esys

  method start fd_clnt sys_fd_clnt =
    if rpc <> None then
      failwith "#start: already started";
    ( match ptype with
	| `Multi_processing ->
	    ( match sockserv # socket_service_config # change_user_to with
		| None -> ()
		| Some(uid,gid) ->
		    (* In Netplex_config it has already been checked whether the
                     * effective uid of the process is root. So the following 
                     * drops all privileges:
		     *)
		    Unix.setgid gid;
		    Unix.setuid uid
	    )
	| _ -> ()
    );
    rpc <-
      Some(Netplex_ctrl_clnt.Control.V1.create_client
	     ~esys
	     (Rpc_client.Descriptor fd_clnt)
	     Rpc.Tcp);
    sys_rpc <-
      Some(Netplex_ctrl_clnt.System.V1.create_client
	     ~esys:sys_esys
	     (Rpc_client.Descriptor sys_fd_clnt)
	     Rpc.Tcp);
    self # protect "post_start_hook"
      (sockserv # processor # post_start_hook) (self : #container :> container);
    self # setup_polling();
    self # protect "run" Unixqueue.run esys;
    self # protect "pre_finish_hook"
      (sockserv # processor # pre_finish_hook) (self : #container :> container);
    rpc <- None

  method private protect : 's. string -> ('s -> unit) -> 's -> unit =
    fun label f arg ->
      try
	f arg 
      with
	| error ->
	    ( match rpc with
		| None -> ()  (* no way to report this error *)
		| Some r ->
		    self # log `Err (label ^ ": Exception " ^ 
				       Printexc.to_string error)
	    )

  method private setup_polling() =
    match rpc with
      | None -> assert false
      | Some r ->
	  Netplex_ctrl_clnt.Control.V1.poll'async r nr_conns
	    (fun getreply ->
	       let continue =
		 ( try
		     let reply = getreply() in
		     ( match reply with
			 | `event_none ->
			     false
			 | `event_accept -> 
			     self # enable_accepting();
			     true
			 | `event_noaccept -> 
			     self # disable_accepting();
			     true
			 | `event_received_message msg ->
			     self # protect
			       "receive_message"
			       (sockserv # processor # receive_message
				  (self : #container :> container)
				  msg.msg_name)
			       msg.msg_arguments;
			     true
			 | `event_received_admin_message msg ->
			     self # protect
			       "receive_admin_message"
			       (sockserv # processor # receive_admin_message
				  (self : #container :> container)
				  msg.msg_name)
			       msg.msg_arguments;
			     true
			 | `event_shutdown ->
			     self # disable_accepting();
			     self # protect
			       "shutdown"
			       (sockserv # processor # shutdown)
			       ();
			     Rpc_client.shut_down r;
			     false
		     )
		   with
		     | error ->
			 self # log `Err ("poll: Exception " ^ 
					    Printexc.to_string error);
			 true
		 ) in
	       if continue then
		 self # setup_polling()
	    )
    
  method private enable_accepting() =
    if engines = [] then (
      List.iter
	(fun (proto, fd_array) ->
	   Array.iter
	     (fun fd ->
		let acc = new Uq_engines.direct_socket_acceptor fd esys in
		let e = acc # accept() in
		Uq_engines.when_state
		  ~is_done:(fun (fd_slave,_) ->
			      self # accepted fd_slave proto
			   )
		  ~is_error:(fun err ->
			       self # log `Err
				 ("accept: Exception " ^ 
				    Printexc.to_string err)
			    )
		  e;
		engines <- e :: engines
	     )
	     fd_array
	)
	sockserv#sockets
    )

  method private disable_accepting() =
    List.iter (fun e -> e # abort()) engines;
    engines <- [];

  method private accepted fd_slave proto =
    match rpc with
      | None -> assert false
      | Some r ->
	  self # disable_accepting();
	  Rpc_client.add_call
	    ~when_sent:(fun () ->
			  nr_conns <- nr_conns + 1;
			  self # protect
			    "process"
			    (sockserv # processor # process
			       ~when_done:(fun fd ->
					     nr_conns <- nr_conns - 1
					  )
			       (self : #container :> container)
			       fd_slave
			    )
			    proto;
			  self # setup_polling();
			  false
		       )
	    r
	    "accepted"
	    Xdr.XV_void
	    (fun _ -> ())

  method system =
    match sys_rpc with
      | None -> failwith "#system: No RPC client available"
      | Some r -> r

  method shutdown() =
    self # disable_accepting();
    match rpc with
      | None -> ()
      | Some r -> Rpc_client.shut_down r

  method log level message =
    match sys_rpc with
      | None -> ()
      | Some r ->
	  let lev = 
	    match level with
	      | `Emerg -> log_emerg
	      | `Alert -> log_alert
	      | `Crit -> log_crit
	      | `Err -> log_err
	      | `Warning -> log_warning
	      | `Notice -> log_notice
	      | `Info -> log_info
	      | `Debug -> log_debug in
	  Rpc_client.add_call
	    ~when_sent:(fun () -> false)
	    r
	    "log"
	    (_of_System'V1'log'arg(lev,message))
	    (fun _ -> ());
	  Unixqueue.run sys_esys

  method lookup service protocol =
    match sys_rpc with
      | None -> failwith "#lookup: No RPC client available"
      | Some r ->
	  Netplex_ctrl_clnt.System.V1.lookup r (service,protocol)

  method send_message pat msg_name msg_arguments =
    match sys_rpc with
      | None -> failwith "#send_message: No RPC client available"
      | Some r ->
	  let msg =
	    { msg_name = msg_name;
	      msg_arguments = msg_arguments
	    } in
	  Netplex_ctrl_clnt.System.V1.send_message r (pat, msg)

end


class admin_container esys ptype sockserv =
object(self)
  inherit std_container ~esys ptype sockserv

  method start fd_clnt sys_fd_clnt =
    let fd_clnt' = Unix.dup fd_clnt in
    if rpc <> None then
      failwith "#start: already started";
    rpc <-
      Some(Netplex_ctrl_clnt.Control.V1.create_client
	     ~esys
	     (Rpc_client.Descriptor fd_clnt')
	     Rpc.Tcp);
    sys_rpc <-
      Some(Netplex_ctrl_clnt.System.V1.create_client
	     ~esys:sys_esys
	     (Rpc_client.Descriptor sys_fd_clnt)
	     Rpc.Tcp);
    self # setup_polling();
end


let create_container ptype sockserv =
  new std_container ptype sockserv

let create_admin_container esys ptype sockserv =
  new admin_container esys ptype sockserv