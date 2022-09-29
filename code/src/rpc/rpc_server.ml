(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Netnumber
open Netxdr
open Unixqueue
open Uq_engines
open Rpc_common
open Rpc
open Printf


exception Connection_lost

class connection_id sock_name_lz peer_name_lz = 
object 
  method socket_name = (Lazy.force sock_name_lz : Unix.sockaddr)
  method peer_name = (Lazy.force peer_name_lz : Unix.sockaddr)
end ;;


class connection_id_for_mplex mplex =
  let sock_name_lz =
    lazy ( match mplex # getsockname with
	     | `Implied -> failwith "Cannot determine own socket name"
	     | `Sockaddr a -> a
	 ) in
  let peer_name_lz =
    lazy ( match mplex # getpeername with
	     | `Implied -> failwith "Cannot determine peer socket name"
	     | `Sockaddr a -> a
	 ) in
  connection_id sock_name_lz peer_name_lz
;;


class no_connection_id : connection_id = 
object 
  method socket_name = failwith "Cannot determine own socket name"
  method peer_name = failwith "Cannot determine peer socket name"
end ;;


type rule =
    [ `Deny
    | `Drop
    | `Reject
    | `Reject_with of Rpc.server_error
    | `Accept
    | `Accept_limit_length of (int * rule)
    ]

type auth_result =
    Auth_positive of
      (string * string * string * Netxdr.encoder option * Netxdr.decoder option *
         Netsys_gssapi.server_props option)

  | Auth_negative of Rpc.server_error
  | Auth_reply of (Netxdr_mstring.mstring list * string * string)
  | Auth_drop


type auth_peeker =
    [ `None
    | `Peek_descriptor of Unix.file_descr -> string option
    | `Peek_multiplexer of Rpc_transport.rpc_multiplex_controller -> string option
    ]


exception Late_drop

class type auth_details =
object
  method server_addr : Unix.sockaddr option
  method client_addr : Unix.sockaddr option
  method program : uint4
  method version : uint4
  method procedure : uint4
  method xid : uint4
  method credential : string * string
  method verifier : string * string
  method frame_len : int
  method message : Rpc_packer.packed_value
  method transport_user : string option
end


class type ['t] pre_auth_method =
object
  method name : string
  method flavors : string list
  method peek : auth_peeker
  method authenticate :
    't ->
    connection_id ->
    auth_details ->
    (auth_result -> unit) ->
      unit

  method invalidate_connection : connection_id -> unit
  method invalidate : unit -> unit
end


module Uint4 = struct
  type t = uint4
  let compare (a:uint4) (b:uint4) =
    (* avoid calling Stdlib.compare *)
    let a' = logical_int32_of_uint4 a in
    let b' = logical_int32_of_uint4 b in
    if a' = b' then
      0
    else
      if a' < b' then
	-1
      else
	1
end


module Uint4Map = Map.Make(Uint4)


let rec uint4_map_mk f l =
  match l with
      [] -> Uint4Map.empty
    | x :: l' ->
	let (key,value) = f x in
	Uint4Map.add key value (uint4_map_mk f l')
;;


let uint4_min m =
  Uint4Map.fold
    (fun n _ acc ->
       let p =
	 Netnumber.int64_of_uint4 n < Netnumber.int64_of_uint4 acc in
       if p then n else acc)
    m
    (Netnumber.uint4_of_int64 0xffffffffL) ;;
       

let uint4_max m =
  Uint4Map.fold
    (fun n _ acc ->
       let p =
	 Netnumber.int64_of_uint4 n > Netnumber.int64_of_uint4 acc in
       if p then n else acc)
    m
    (Netnumber.uint4_of_int 0) ;;


type internal_pipe =
  Netxdr.xdr_value Netsys_polypipe.polypipe

type internal_socket =
  Netxdr.xdr_value Netsys_polysocket.polyserver


type acceptor =
  | Sock_acc of server_endpoint_acceptor
  | Engine_acc of unit Uq_engines.engine


type t =
      { mutable main_socket_name : Rpc_transport.sockaddr;
        mutable dbg_name : string ref;
	mutable dummy : bool;
	mutable service : (Rpc_program.t * binding Uint4Map.t) 
	                    Uint4Map.t Uint4Map.t;
	        (* Program nr/version nr/procedure nr *)
	mutable portmapped : 
                  (Unix.inet_addr * int * Rpc_portmapper.t option * int) option;
	mutable esys : event_system;
	mutable prot : protocol;
	mutable exception_handler : exn -> string -> unit;
	mutable unmap_port : (unit -> unit);
	mutable onclose : (connection_id -> unit) list;
	mutable filter : (Rpc_transport.sockaddr -> connection_id -> rule);
	mutable auth_methods : (string, t pre_auth_method) Hashtbl.t;
	mutable auth_peekers : (auth_peeker * t pre_auth_method) list;
	mutable connections : connection list;
	mutable master_acceptor : acceptor option;
	mutable transport_timeout : float;
	mutable nolog : bool;
	mutable get_last_proc : unit->string;
	mutable mstring_factories : Netxdr_mstring.named_mstring_factories;
        mutable internal : bool;
      }

and connection =
    (* For connected streams, but also used for datagram servers. *)
      { whole_server : t;
	conn_id : connection_id;
        mutable trans : Rpc_transport.rpc_multiplex_controller option;
	mutable fd : Unix.file_descr option;

	mutable rule : rule option;
        (* TODO: The rule exists per incoming message, not per connection.
	 * Is it better to put it into Rpc_transport?
	 *)

	mutable next_call_id : int;

	(* replies to do: *)
	mutable replies : session Queue.t;

	mutable close_when_empty : bool;
	(* If true, the connection will be closed when [replies] becomes
         * empty.
         *)

	(* RPC does not define how to check if replies are delivered,
	 * so there is no "re-reply" mechanism. The client has to call
	 * again; but the server cannot identify such repetitions.
	 * (The xid field cannot be used for this purpose!)
	 *)

	mutable peeked :        bool;           (* whether already peeked *)
	mutable peeked_user :   string option;
	mutable peeked_method : t pre_auth_method;
      }

and session =
    (* intentionally immutable to make value sharing possible *)
      { server : connection;
	prog : Rpc_program.t option;  (* None for errors etc. *)
	sess_conn_id : connection_id;
	sockaddr : Unix.sockaddr Lazy.t;   (* own address *)
	peeraddr : Rpc_transport.sockaddr;
	call_id : int;
	client_id : uint4;         (* xid *)
	procname : string;
	parameter : xdr_value;     (* XV_void if not used *)
	result : Rpc_packer.packed_value;
         (* complete result; "" if not used *)
	ptrace_result :string;  (* ptrace only; "" if not used *)
	auth_method : t pre_auth_method;
	auth_user : string;
	auth_ret_flav : string;
	auth_ret_data : string;
	encoder : Netxdr.encoder option;
        tls_session_props : Nettls_support.tls_session_props option;
        gssapi_props : Netsys_gssapi.server_props option;
      }

and connector =
      Localhost of int                     (* port, 0: automatically chosen *)
    | Portmapped
    | Internet of (Unix.inet_addr * int)   (* addr, port *)
    | Unix of string                       (* path to unix dom sock *)
    | W32_pipe of string
    | Descriptor of Unix.file_descr
    | Dynamic_descriptor of (unit -> Unix.file_descr)

and binding_sync =
      { sync_name : string;
	sync_proc : t -> xdr_value -> xdr_value
      }

and binding_async =
      { async_name : string;
	async_invoke : t -> session -> xdr_value -> unit
                                            (* invocation of this procedure *)
      }

and binding =
      Sync of binding_sync
    | Async of binding_async

class type auth_method = [t] pre_auth_method ;;

class auth_none : auth_method =
object
  method name = "AUTH_NONE"
  method flavors = [ "AUTH_NONE" ]
  method peek = `None
  method authenticate _ _ _ f = 
    f(Auth_positive("","AUTH_NONE","",None,None,None))
  method invalidate() = ()
  method invalidate_connection _ = ()
end

let auth_none = new auth_none

class auth_too_weak : auth_method =
object
  method name = "AUTH_TOO_WEAK"
  method flavors = []
  method peek = `None
  method authenticate _ _ _ f = 
    f(Auth_negative Auth_too_weak)
  method invalidate() = ()
  method invalidate_connection _ = ()
end

let auth_too_weak = new auth_too_weak

class auth_transport : auth_method =
object
  method name = "AUTH_TRANSPORT"
  method flavors = [ "AUTH_TRANSPORT" ]   (* special-cased! *)
(* The following would be too early, before the TLS handshake! *)
(*
  method peek = 
    `Peek_multiplexer
      (fun mplex ->
	 mplex # peer_user_name
      )
 *)
  method peek = `None
  method authenticate _ _ ad f = 
    match ad#transport_user with
      | None ->
           f(Auth_negative Auth_too_weak)
      | Some u ->
           f(Auth_positive(u, "AUTH_NONE", "", None, None, None))
  method invalidate() = ()
  method invalidate_connection _ = ()
end

let auth_transport = new auth_transport

  (*****)

module Debug = struct
  let enable = ref false
  let enable_ctrace = ref false
  let enable_ptrace = ref false
  let ptrace_verbosity = ref `Name_abbrev_args
  let disable_for_server srv = srv.nolog <- true
end

let dlog0 = Netlog.Debug.mk_dlog "Rpc_server" Debug.enable
let dlogr0 = Netlog.Debug.mk_dlogr "Rpc_server" Debug.enable

let dlog srv m = if not srv.nolog then dlog0 m
let dlogf srv fmt = ksprintf (dlog srv) fmt
let dlogr srv m = if not srv.nolog then dlogr0 m

let dlog0_ctrace = Netlog.Debug.mk_dlog "Rpc_server.Ctrace" Debug.enable_ctrace
let dlogr0_ctrace = Netlog.Debug.mk_dlogr "Rpc_server.Ctrace" Debug.enable_ctrace

let dlog_ctrace srv m = if not srv.nolog then dlog0_ctrace m
let dlogr_ctrace srv m = if not srv.nolog then dlogr0_ctrace m


let dlog0_ptrace = Netlog.Debug.mk_dlog "Rpc_server.Ptrace" Debug.enable_ptrace
let dlogr0_ptrace = Netlog.Debug.mk_dlogr "Rpc_server.Ptrace" Debug.enable_ptrace

let dlog_ptrace srv m = if not srv.nolog then dlog0_ptrace m
let dlogr_ptrace srv m = if not srv.nolog then dlogr0_ptrace m


let () =
  Netlog.Debug.register_module "Rpc_server" Debug.enable;
  Netlog.Debug.register_module "Rpc_server.Ctrace" Debug.enable_ctrace;
  Netlog.Debug.register_module "Rpc_server.Ptrace" Debug.enable_ptrace

  (*****)

let connector_of_sockaddr =
  function
    | Unix.ADDR_INET(ip,p) ->
	Internet(ip,p)
    | Unix.ADDR_UNIX s ->
	Unix s

let connector_of_socksymbol sym =
  connector_of_sockaddr
    (Uq_resolver.sockaddr_of_socksymbol sym)


let sockaddrname sa =
  match sa with
    | Unix.ADDR_INET(addr, port) ->
	Unix.string_of_inet_addr addr ^ ":" ^ string_of_int port
    | Unix.ADDR_UNIX path ->
	String.escaped path

let portname fd =
  try 
    sockaddrname (Unix.getsockname fd)
  with
    | _ -> "anonymous"

let portoptname fd_opt =
  match fd_opt with
    | None -> "unknown"
    | Some fd -> portname fd

let mplexname mplex =
  try
    match mplex # getpeername with
      | `Implied -> "implied"
      | `Sockaddr a -> sockaddrname a
  with
    | _ -> "anonymous"

let mplexoptname mplex_opt =
  match mplex_opt with
    | None -> "unknown"
    | Some mplex -> mplexname mplex


let xidname xid =
  Int32.to_string (Netnumber.int32_of_uint4 xid)

let errname =
  function
    | Unavailable_program      -> "Unavailable_program"
    | Unavailable_version(_,_) -> "Unavailable_version"
    | Unavailable_procedure    -> "Unavailable_procedure"
    | Garbage                  -> "Garbage"
    | System_err               -> "System_err"
    | Rpc_mismatch(_,_)        -> "Rpc_mismatch"
    | Auth_bad_cred            -> "Auth_bad_cred"
    | Auth_rejected_cred       -> "Auth_rejected_cred"
    | Auth_bad_verf            -> "Auth_bad_verf"
    | Auth_rejected_verf       -> "Auth_rejected_verf"
    | Auth_too_weak            -> "Auth_too_weak"
    | Auth_invalid_resp        -> "Auth_invalid_resp"
    | Auth_failed              -> "Auth_failed"
    | RPCSEC_GSS_ctxproblem    -> "RPCSEC_GSS_ctxproblem"
    | RPCSEC_GSS_credproblem   -> "RPCSEC_GSS_credproblem"

  (*****)

let null_packed_value =
  Rpc_packer.packed_value_of_string ""

let no_conn_id = new no_connection_id

  (*****)

let check_for_output = ref (fun _ _ -> ())

let pack_accepting_reply srv =
  if srv.internal then
    Rpc_packer.pack_accepting_reply_pseudo
  else
    Rpc_packer.pack_accepting_reply

let pack_rejecting_reply srv =
  if srv.internal then
    Rpc_packer.pack_rejecting_reply_pseudo
  else
    Rpc_packer.pack_rejecting_reply


let pack_successful_reply ?encoder srv =
  if srv.internal then
    Rpc_packer.pack_successful_reply_pseudo
  else
    Rpc_packer.pack_successful_reply ?encoder

  (*****)

type reaction =
    Execute_procedure
  | Reject_procedure of server_error

let process_incoming_message srv conn sockaddr_lz peeraddr message reaction =
  let sockaddr_opt =
    try Some(Lazy.force sockaddr_lz) with _ -> None in

  let sockaddr =
    match sockaddr_opt with
      | Some a -> `Sockaddr a
      | None -> `Implied in

  let peeraddr_opt =
    match peeraddr with
      | `Sockaddr a -> Some a
      | `Implied -> None in

  let peeraddr_lz =
    lazy ( match peeraddr with
	     | `Implied -> failwith "Cannot determine peer socket name"
	     | `Sockaddr a -> a
	 ) in

  let get_tls_session_props() =
    match conn.trans with
      | None -> None
      | Some trans -> trans # tls_session_props in

  let get_trans_user() =
    match conn.trans with
      | None -> None
      | Some trans -> trans # peer_user_name in

  let make_immediate_answer xid procname result f_ptrace_result =
    srv.get_last_proc <- 
      (fun () -> 
	 if procname = "" then "Unavailable" else "Response " ^ procname);
    { server = conn;
      prog = None;
      sess_conn_id = if srv.prot = Rpc.Tcp then conn.conn_id
                     else new connection_id sockaddr_lz peeraddr_lz;
      sockaddr = sockaddr_lz;
      peeraddr = peeraddr;
      call_id = (-1);          (* not applicable *)
      client_id = xid;
      procname = procname;
      parameter = XV_void;
      result = result;
      auth_method = auth_none;
      auth_user = "";
      auth_ret_flav = "AUTH_NONE";
      auth_ret_data = "";
      encoder = None;
      ptrace_result = (if !Debug.enable_ptrace then f_ptrace_result() else "");
      tls_session_props = get_tls_session_props();
      gssapi_props = None;
    }
  in

  let schedule_answer answer =
    Queue.add answer conn.replies;
    !check_for_output srv conn
  in

  let protect_protect f =
    try
      f()
    with
	any ->
          let bt = Printexc.get_backtrace() in
	  (try srv.exception_handler any bt with _ -> ());
  in

  let protect ?(ret_flav="AUTH_NONE") ?(ret_data="") f =
    try
      f()
    with
	Rpc_server(Unavailable_program | Unavailable_version(_,_)|
                   Unavailable_procedure | Garbage | System_err
		   as condition) ->
	  protect_protect
	    (fun () ->
	       let xid = Rpc_packer.peek_xid message in
	       let reply =
                 pack_accepting_reply srv xid ret_flav ret_data condition in
	       let answer = 
		 make_immediate_answer xid "" reply 
		   (fun () -> "Error " ^ errname condition) in
	       schedule_answer answer
	    )
      | (Netxdr.Xdr_format _
	| Netxdr.Xdr_format_message_too_long _ as e
	) ->
          (* Convert to Garbage *)
	   protect_protect
	     (fun () ->
		dlogr srv
		 (fun () ->
		    sprintf "Emitting Garbage after exception: %s"
		      (Netexn.to_string e)
		 );
	       let xid = Rpc_packer.peek_xid message in
	       let reply =
                 pack_accepting_reply srv xid ret_flav ret_data Garbage in
	       let answer = make_immediate_answer xid "" reply 
 		 (fun () -> "Error Garbage") in
	       schedule_answer answer
	    )
      | Rpc_server condition ->
	  protect_protect
	    (fun () ->
	       let xid = Rpc_packer.peek_xid message in
	       let reply = pack_rejecting_reply srv xid condition in
	       let answer = make_immediate_answer xid "" reply 
		 (fun () -> "Error " ^ errname condition) in
	       schedule_answer answer
	    )
      | Late_drop ->
	  Netlog.logf `Err
	    "Dropping response message"
      | Abort(_,_) as x ->
	  raise x
      | any ->
	  (* Reply "System_err": *)
          let bt = Printexc.get_backtrace() in
	  (try srv.exception_handler any bt with _ -> ());
	  protect_protect
	    (fun () ->
	       let xid = Rpc_packer.peek_xid message in
	       let reply =
                 pack_accepting_reply srv xid ret_flav ret_data System_err in
	       let answer = make_immediate_answer xid "" reply
		 (fun () -> "Error System_err") in
	       schedule_answer answer
	    )
  in

  protect
    (fun () ->
       match reaction with
	   Execute_procedure ->
	     let
	       xid, prog_nr, vers_nr, proc_nr,
	       flav_cred, data_cred, flav_verf, data_verf, frame_len
	       = Rpc_packer.unpack_call_frame_l message
	     in

	     dlogr_ptrace srv
	       (fun () ->
		  sprintf
		    "Request (sock=%s,peer=%s,xid=%lu,dbgname=%s) for \
                     [0x%lx,0x%lx,0x%lx]"
		    (Rpc_transport.string_of_sockaddr sockaddr)
		    (Rpc_transport.string_of_sockaddr peeraddr)
		    (Netnumber.logical_int32_of_uint4 xid)
                    !(srv.dbg_name)
		    (Netnumber.logical_int32_of_uint4 prog_nr)
		    (Netnumber.logical_int32_of_uint4 vers_nr)
		    (Netnumber.logical_int32_of_uint4 proc_nr)
	       );
	     
	     let sess_conn_id =
	       if srv.prot = Rpc.Tcp then 
		 conn.conn_id
	       else 
		 new connection_id sockaddr_lz peeraddr_lz
	     in

	     (* First authenticate: *)
	     let (auth_m, authenticate) =
	       match conn.peeked_user with
		 | Some uid ->
		     (conn.peeked_method,
		      (fun _ _ _ cb ->
			 cb (Auth_positive(uid, "AUTH_NONE", "", 
                                           None, None, None)))
		     )
		 | None ->
		     ( let m =
			 try Hashtbl.find srv.auth_methods flav_cred
			 with Not_found ->
                           ( try Hashtbl.find srv.auth_methods "AUTH_TRANSPORT"
                             with Not_found -> auth_too_weak
                           ) in
		       (m, m#authenticate)
		     )
	     in

	     let auth_details =
	       ( object
		   method server_addr = sockaddr_opt
		   method client_addr = peeraddr_opt
		   method program = prog_nr
		   method version = vers_nr
		   method procedure = proc_nr
		   method xid = xid
		   method credential = (flav_cred, data_cred)
		   method verifier = (flav_verf, data_verf)
		   method frame_len = frame_len
		   method message = message
                   method transport_user = get_trans_user()
		 end
	       ) in

	     (* The [authenticate] method will call the passed function
	      * when the authentication is done. This may be at any time
	      * in the future.
	      *)
	     authenticate
	       srv sess_conn_id auth_details
	       (function 
		  Auth_positive(user,ret_flav,ret_data,enc_opt,dec_opt,gss) ->
		  (* user: the username (method-dependent)
		   * ret_flav: flavour of verifier to return
		   * ret_data: data of verifier to return
		   *)
		  protect ~ret_flav ~ret_data
		    (fun () ->
		       (* Find the right binding *)
		       let prog_map =
			 try
			   Uint4Map.find prog_nr srv.service
			 with Not_found ->
			   raise (Rpc_server Unavailable_program) in

		       let (prog, binding) =
			 try
			   Uint4Map.find vers_nr prog_map
			 with Not_found ->
			   let min_vers = uint4_min prog_map in
			   let max_vers = uint4_max prog_map in
			   raise 
			     (Rpc_server 
				(Unavailable_version (min_vers, max_vers))) in

		       let proc =
			 try
			   Uint4Map.find proc_nr binding
			 with Not_found -> 
			   raise (Rpc_server Unavailable_procedure)
		       in

		       let procname =
			 match proc with
			     Sync p -> p.sync_name
			   | Async p -> p.async_name
		       in

		       let param =
			 Rpc_packer.unpack_call_body
			   ~mstring_factories:srv.mstring_factories
			   ?decoder:dec_opt
			   prog procname message frame_len in

		       srv.get_last_proc <-
			 (fun () ->
			    (* no [string_of_request] - we would keep a
                               reference to param forever!
			     *)
			    "Invoke " ^ procname ^ "()"
			 );

		       dlogr_ptrace srv
			 (fun () ->
			    sprintf
			      "Invoke (sock=%s,peer=%s,xid=%lu,dbgname=%s): %s"
			      (Rpc_transport.string_of_sockaddr sockaddr)
			      (Rpc_transport.string_of_sockaddr peeraddr)
			      (Netnumber.logical_int32_of_uint4 xid)
                              !(srv.dbg_name)
			      (Rpc_util.string_of_request
				 !Debug.ptrace_verbosity
				 prog
				 procname
				 param
			      )
			 );

		       begin match proc with
			   Sync p ->
			     let result_value =
			       p.sync_proc srv param
			     in
			     (* Exceptions raised by the encoder are
				handled by [protect]
			      *)
			     let reply = 
                               pack_successful_reply
                                 ?encoder:enc_opt srv
				 prog p.sync_name xid
				 ret_flav ret_data result_value in
			     let answer = make_immediate_answer
			       xid procname reply 
			       (fun () ->
				  Rpc_util.string_of_response
				    !Debug.ptrace_verbosity
				    prog
				    procname
				    result_value
			       )
			     in
			     schedule_answer answer
			 | Async p ->
			     let u, m = match conn.peeked_user with
				 Some uid -> uid, conn.peeked_method
			       | None -> user, auth_m
			     in
			     let this_session =
			       { server = conn;
				 prog = Some prog;
				 sess_conn_id = sess_conn_id;
				 sockaddr = sockaddr_lz;
				 peeraddr = peeraddr;
				 call_id = conn.next_call_id;
				 client_id = xid;
				 procname = p.async_name;
				 parameter = param;
				 result = null_packed_value;
				 auth_method = m;
				 auth_user = u;
				 auth_ret_flav = ret_flav;
				 auth_ret_data = ret_data;
				 ptrace_result = "";  (* not yet known *)
				 encoder = enc_opt;
                                 tls_session_props = get_tls_session_props();
                                 gssapi_props = gss;
			       } in
			     conn.next_call_id <- conn.next_call_id + 1;
			     p.async_invoke srv this_session param
		       end
		    )
		  | Auth_negative code ->
		      protect (fun () -> raise(Rpc_server code))
		  | Auth_reply (data, ret_flav, ret_data) ->
                      if srv.internal then
                        failwith "Rpc_server: raw auth replies not supported \
                                  for internal connections";
		      let reply = 
			Rpc_packer.pack_successful_reply_raw
			  xid ret_flav ret_data data in
		      let answer = 
			make_immediate_answer
			  xid "" reply 
			  (fun () -> "") in
		      schedule_answer answer
		  | Auth_drop ->
		      dlog srv "auth_drop";
		      ()
		      
	       )
	 | Reject_procedure reason ->
	     srv.get_last_proc <-
	       (fun () ->
		  "Reject " ^ Rpc.string_of_server_error reason
	       );
	     protect (fun () -> raise(Rpc_server reason))
    )
;;

  (*****)

let terminate_any srv conn =
  match conn.trans with
    | None ->
	()
    | Some mplex ->
	dlogr_ctrace srv
	  (fun () ->
	     sprintf "(sock=%s,peer=%s,dbgname=%s): Closing"
	       (Rpc_transport.string_of_sockaddr mplex#getsockname)
	       (Rpc_transport.string_of_sockaddr mplex#getpeername)
               !(srv.dbg_name));
	conn.trans <- None;
	mplex # abort_rw();
	( try
	    mplex # start_shutting_down
	      ~when_done:(fun exn_opt ->
			    (* CHECK: Print exception? *)
			    mplex # inactivate())
	      ();
	  with _ -> mplex # inactivate()
	);
        Hashtbl.iter
          (fun _ auth_meth -> auth_meth # invalidate_connection conn.conn_id)
          srv.auth_methods;
	srv.connections <- 
	  List.filter (fun c -> c != conn) srv.connections;
	if srv.prot = Tcp then (
	  List.iter
	    (fun action ->
	       try
		 action conn.conn_id
	       with
		 | any ->
                     let bt = Printexc.get_backtrace() in
		     (try srv.exception_handler any bt with _ -> ())
	    )
	    srv.onclose
	)


let terminate_connection srv conn =
  if srv.prot = Tcp then (
    terminate_any srv conn
  )

  (*****)


let rec unroll_rule r length =
  match r with
    | `Accept_limit_length(limit,r') ->
	if length > limit then unroll_rule r' length else `Accept
    | (`Drop | `Reject | `Reject_with _ | `Deny | `Accept as other) -> 
	other
;;


let rec handle_incoming_message srv conn r =
  (* Called when a complete message has been read by the transporter *)
  match r with
    | `Error e ->
	terminate_connection srv conn;
	raise e

    | `Ok(in_rec,trans_addr) ->
	dlog srv "got message";

	if conn.close_when_empty then (
	    dlog srv "ignoring msg after shutdown";
	) else (

	  (* First check whether the message matches the filter rule: *)
	  
	  let peeraddr = trans_addr in

	  let sockaddr, trans_sockaddr =
	    match conn.trans with
	      | None -> assert false
	      | Some trans ->
		  ( lazy ( match trans # getsockname with
			     | `Sockaddr a -> a
			     | `Implied -> failwith "Address not available" ),
		    trans#getsockname
		  ) in
		  
	  ( match in_rec with
	      | `Deny ->
		  dlogr_ptrace srv
		    (fun () ->
		       sprintf
			 "Request (sock=%s,peer=%s,dbgname=%s): Deny"
			 (Rpc_transport.string_of_sockaddr trans_sockaddr)
			 (Rpc_transport.string_of_sockaddr peeraddr)
                         !(srv.dbg_name)
		    );
		  terminate_connection srv conn (* for safety *)
	      | `Drop ->
		  (* Simply forget the message *)
		  dlogr_ptrace srv
		    (fun () ->
		       sprintf
			 "Request (sock=%s,peer=%s,dbgname=%s): Drop"
			 (Rpc_transport.string_of_sockaddr trans_sockaddr)
			 (Rpc_transport.string_of_sockaddr peeraddr)
                         !(srv.dbg_name)
		    );
		  ()
	      | `Accept pv ->
		  process_incoming_message
		    srv conn sockaddr peeraddr pv Execute_procedure
	      | `Reject pv ->
		  process_incoming_message
		    srv conn sockaddr peeraddr pv
		    (Reject_procedure Auth_too_weak)
	      | `Reject_with(pv,code) ->
		  process_incoming_message
		    srv conn sockaddr peeraddr pv
		    (Reject_procedure code)
	  );
	  next_incoming_message srv conn  (* if still connected *)
	)

    | `End_of_file ->
        dlogf srv "End_of_file dbgname=%s" !(srv.dbg_name);
	terminate_connection srv conn


and next_incoming_message srv conn =
  match conn.trans with
    | None -> ()
    | Some trans -> next_incoming_message' srv conn trans

and next_incoming_message' srv conn trans =
  let filter_var = ref None in
  trans # start_reading
    ~peek:(fun () -> peek_credentials srv conn)
    ~before_record:(handle_before_record srv conn filter_var)
    ~when_done:(fun r -> handle_incoming_message srv conn r)
    ()

and handle_before_record srv conn filter_var n trans_addr =
  dlog srv "Checking filter before_record";
(*
  let filter = 
    match !filter_var with
      | Some filter -> 
	  filter
      | None ->
 *)
	  let filter = srv.filter trans_addr conn.conn_id in
(*
	  filter_var := Some filter;
	  filter in
 *)
  ( match unroll_rule filter n with
      | `Accept -> `Accept
      | `Deny   -> terminate_connection srv conn; `Deny
      | `Drop   -> `Drop
      | `Reject -> `Reject
      | `Reject_with code -> `Reject_with code
  )

and peek_credentials srv conn =
  if not conn.peeked && (* srv.prot = Tcp && *) srv.auth_peekers <> [] then begin
    (* This is used by AUTH_LOCAL to get the credentials of the peer. Thus
     * we need the file descriptor. Without descriptor, we just cannot
     * authenticate!
     *)
    dlog srv "peek_credentials";
    let u = ref None in
    let m = ref auth_none in
    try
      List.iter
	(fun (peeker, meth) ->
	   match peeker with
	     | `Peek_descriptor p ->
		 ( match conn.fd with
		     | Some fd ->
			 let uid_opt = p fd in
			 if uid_opt <> None then (
			   u := uid_opt; 
			   m := meth; 
			   raise Exit
			 )
		     | None -> ()
		 )
	     | `Peek_multiplexer p ->
		 ( match conn.trans with
		     | Some mplex ->
			 let uid_opt = p mplex in
			 if uid_opt <> None then (
			   u := uid_opt; 
			   m := meth; 
			   raise Exit
			 )
		     | None -> ()
		 )
	     | _ -> ()
	)
	srv.auth_peekers;
    with
	Exit ->
	  conn.peeked <- true;
	  conn.peeked_user <- !u;
	  conn.peeked_method <- !m;
	  dlogr srv (fun () ->
		       sprintf "peek_credentials: user=%s" 
			 ( match !u with
			     | None -> "./."
			     | Some s -> s
			 )
		    );
  end
;;


let rec handle_outgoing_message srv conn r =
  (* Called after a complete message has been sent by the transporter *)
  match r with
    | `Error e ->
	terminate_connection srv conn;
	raise e

    | `Ok () ->
        dlog srv "message writing finished";
	if conn.close_when_empty && Queue.is_empty conn.replies then (
	  dlog srv "closing connection gracefully";
	  terminate_connection srv conn
	)
	else
          next_outgoing_message srv conn

and next_outgoing_message srv conn =
  match conn.trans with
    | None -> ()   (* Not yet initialized *)
    | Some trans ->
        if not trans#writing then
          next_outgoing_message' srv conn trans

and next_outgoing_message' srv conn trans =
  let reply_opt =
    try Some(Queue.take conn.replies) with Queue.Empty -> None in

  match reply_opt with
    | Some reply ->
	dlogr_ptrace srv
	  (fun () ->
	     let sockaddr =
	       try `Sockaddr (Lazy.force reply.sockaddr)
	       with _ -> `Implied in
	     sprintf
	       "Response (sock=%s,peer=%s,cid=%d,xid=%ld,dbgname=%s): %s"
	       (Rpc_transport.string_of_sockaddr sockaddr)
	       (Rpc_transport.string_of_sockaddr reply.peeraddr)
	       reply.call_id
	       (Netnumber.logical_int32_of_uint4 reply.client_id)
               !(srv.dbg_name)
	       reply.ptrace_result
	  );

	dlog srv "next reply";
	trans # start_writing
	  ~when_done:(fun r ->
			handle_outgoing_message srv conn r)
	  reply.result
	  reply.peeraddr
    | None ->
	(* this was the last reply in the queue *)
	dlog srv "last reply"
;;

check_for_output := next_outgoing_message ;;

  (*****)

class type socket_config =
object
  method listen_options : listen_options
  method multiplexing : 
    dbg_name:string ref ->
    close_inactive_descr:bool ->
    protocol -> Unix.file_descr -> Unixqueue.event_system ->
      Rpc_transport.rpc_multiplex_controller engine
end


type mode2 =
    [ `Socket_endpoint of protocol * Unix.file_descr
    | `Multiplexer_endpoint of Rpc_transport.rpc_multiplex_controller
    | `Socket of protocol * connector * socket_config
    | `Dummy of protocol
    | `Internal_endpoint of internal_pipe * internal_pipe
    | `Internal_socket of internal_socket
    ]


let create2_srv prot esys =
  let default_exception_handler ex bt =
    Netlog.log
      `Crit
      ("Rpc_server exception handler: Exception " ^ Netexn.to_string ex);
    dlog0
      ("Rpc_server exception handler: Backtrace: " ^ bt);
  in

  let none = Hashtbl.create 3 in
  Hashtbl.add none "AUTH_NONE" auth_none;

  let mf = Hashtbl.create 1 in
  Hashtbl.add mf "*" Netxdr_mstring.bytes_based_mstrings;
  
  { main_socket_name = `Implied;
    dbg_name = ref "<server>";
    dummy = false;
    service = Uint4Map.empty;
    portmapped = None;
    esys = esys;
    prot = prot;
    exception_handler = default_exception_handler;
    unmap_port = (fun () -> ());
    onclose = [];
    filter = (fun _ _ -> `Accept);
    auth_methods = none;
    auth_peekers = [];
    connections = [];
    master_acceptor = None;
    transport_timeout = (-1.0);
    nolog = false;
    get_last_proc = (fun () -> "");
    mstring_factories = mf;
    internal = false;
  }  
;;


let connection srv mplex =
  let conn =
    { whole_server = srv;
      fd = None;
      conn_id = 
	( match mplex # protocol with
	    | Tcp -> new connection_id_for_mplex mplex
	    | Udp -> no_conn_id
	);
      rule = None;
      trans = Some mplex;
      next_call_id = 0;
      replies = Queue.create();
      peeked = false;
      peeked_user = None;
      peeked_method = auth_none;
      close_when_empty = false;
    } in
  srv.connections <- conn :: srv.connections;
  conn
;;


let on_trans_timeout srv conn () =
  terminate_any srv conn
;;


let track fd =
  Netlog.Debug.track_fd
    ~owner:"Rpc_server"
    ~descr:(sprintf "RPC connection %s"
	      (Netsys.string_of_fd fd))
    fd


let track_server fd =
  Netlog.Debug.track_fd
    ~owner:"Rpc_server"
    ~descr:(sprintf "RPC server %s" (Netsys.string_of_fd fd))
    fd


let disable_nagle fd =
  try
    Unix.setsockopt fd Unix.TCP_NODELAY true
  with _ -> ()


let create2_multiplexer_endpoint ?dbg_name mplex =
  let prot = mplex#protocol in
  let srv  = create2_srv prot mplex#event_system in
  ( match dbg_name with
      | None -> ()
      | Some sref -> srv.dbg_name <- sref
  );
  let conn = connection srv mplex in
  srv.main_socket_name <- mplex # getsockname;
  conn.fd <- mplex # file_descr;
  (* Start serving not before the event loop is entered. *)
  Unixqueue.once 
    mplex#event_system
    (Unixqueue.new_group mplex#event_system)
    0.0
    (fun () ->
       (* Try to peek credentials. This can be too early, however. *)
       if conn.trans <> None then (
	 dlogr_ctrace srv
	   (fun () ->
	      sprintf "(sock=%s,peer=%s,dbgname=%s): Serving connection"
		(Rpc_transport.string_of_sockaddr mplex#getsockname)
		(portoptname mplex#file_descr)
                !(srv.dbg_name));
	 if srv.transport_timeout >= 0.0 then
	   mplex # set_timeout 
	     ~notify:(on_trans_timeout srv conn) srv.transport_timeout;
	 peek_credentials srv conn;
	 next_incoming_message srv conn;
       )
	 (* else: server might have been closed *)
    );
  srv
;;


let mplex_of_fd ~dbg_name ~close_inactive_descr ~tls prot fd esys =
  let preclose() =
    Netlog.Debug.release_fd fd in
  match prot with
    | Tcp ->
        Rpc_transport.stream_rpc_multiplex_controller
          ~dbg_name
          ~close_inactive_descr ~preclose ~role:`Server ?tls fd esys
    | Udp ->
        if tls <> None then (* a little ad... *)
          failwith "Rpc_server: It is not supported to use TLS with datagrams. \
                    Generally, there is an approach to solve this (via the \
                    DTLS protocol variant of TLS), but this has not yet been \
                    implemented. If it happens that you have some money left \
                    in your pockets, you may support Gerd Stolpmann to \
                    implement this feature. Contact gerd@gerd-stolpmann.de";
        Rpc_transport.datagram_rpc_multiplex_controller
          ~dbg_name
          ~close_inactive_descr ~preclose ~role:`Server fd esys 
;;


class default_socket_config : socket_config = 
object
  method listen_options = Uq_server.default_listen_options

  method multiplexing ~dbg_name ~close_inactive_descr prot fd esys =
    let mplex =
      mplex_of_fd ~dbg_name ~close_inactive_descr ~tls:None prot fd esys in
    let eng = new Uq_engines.epsilon_engine (`Done mplex) esys in

    when_state
      ~is_aborted:(fun () -> mplex # inactivate())
      ~is_error:(fun _ -> mplex # inactivate())
      eng;

    eng
end


class tls_socket_config tls_config : socket_config = 
object
  method listen_options = Uq_server.default_listen_options

  method multiplexing ~dbg_name ~close_inactive_descr prot fd esys =
    let tls = Some(tls_config,None) in
    let mplex =
      mplex_of_fd ~dbg_name ~close_inactive_descr ~tls prot fd esys in
    let eng = new Uq_engines.epsilon_engine (`Done mplex) esys in

    when_state
      ~is_aborted:(fun () -> mplex # inactivate())
      ~is_error:(fun _ -> mplex # inactivate())
      eng;

    eng
end


let default_socket_config = new default_socket_config 
let tls_socket_config = new tls_socket_config 


let create2_socket_endpoint ?(close_inactive_descr=true)
                            prot fd esys =
  disable_nagle fd;
  if close_inactive_descr then track fd;
  let dbg_name = ref "" in
  let mplex =
    mplex_of_fd ~dbg_name ~close_inactive_descr ~tls:None prot fd esys in
  create2_multiplexer_endpoint ~dbg_name mplex 
;;


let create2_socket_server ?(config = default_socket_config)
		          ?override_listen_backlog
		          prot conn esys =
  let srv = create2_srv prot esys in
  let stype = 
    if prot = Tcp then Unix.SOCK_STREAM else Unix.SOCK_DGRAM in
  let backlog =
    match override_listen_backlog with
      | Some n -> n
      | None -> config#listen_options.lstn_backlog in
  let opts =
    { config#listen_options with
      lstn_backlog = backlog
    } in

  let create_multiplexer_eng ?(close_inactive_descr = true)  fd prot =
    disable_nagle fd;
    if close_inactive_descr then track fd;
    let dbg_name = srv.dbg_name in
    config # multiplexing ~close_inactive_descr ~dbg_name prot fd esys in

  let rec accept_connections acc =  (* for stream sockets *)
    let eng = acc # accept () in
    when_state
      ~is_done:(fun (slave_fd, _) ->
		  let mplex_eng = create_multiplexer_eng slave_fd Tcp in
		  when_state
		    ~is_done:(fun mplex ->
				let conn = connection srv mplex in
				conn.fd <- Some slave_fd;
				dlogr_ctrace srv
				  (fun () ->
				     sprintf "(sock=%s,peer=%s,dbgname=%s): \
                                              Serving connection"
				       (Rpc_transport.string_of_sockaddr 
					  mplex#getsockname)
				       (portname slave_fd)
                                       !(srv.dbg_name));
				if srv.transport_timeout >= 0.0 then
				  mplex # set_timeout 
				    ~notify:(on_trans_timeout srv conn) 
				    srv.transport_timeout;
				(* Try to peek credentials. This can be too
                                 * early, however.
				 *)
				peek_credentials srv conn;
				next_incoming_message srv conn;
				accept_connections acc
			     )
		    ~is_error:(fun exn ->
				 srv.exception_handler exn ""
			      )
		    mplex_eng
	       )
      ~is_error:(fun exn ->
		   srv.exception_handler exn ""
		)
      eng in

  let get_port s =
    match Unix.getsockname s with
      | Unix.ADDR_INET(addr,port) -> addr, port
      | _ -> assert false in

  let dlog_anon_port port =
    dlogr srv
	  (fun () ->
	     sprintf "Using anonymous port %d" port) in
    
  let get_descriptor() =
    let (fd, close_inactive_descr) =
      match conn with
	| Localhost port ->
             let addr =
               Unix.inet_addr_loopback in
	     let s = 
               Uq_server.listen_on_inet_socket
                 addr port stype opts in
	    (s, true)
	| Internet (addr,port) ->
	    let s = 
              Uq_server.listen_on_inet_socket
                addr port stype opts in
            if port = 0 then (
	      let _, p = get_port s in
              dlog_anon_port p;
            );
	    (s, true)
	| Portmapped ->
            let s = 
              Uq_server.listen_on_inet_socket
                Unix.inet6_addr_any 0 stype opts in
	    ( try
		let addr, port = get_port s in
                dlog_anon_port port;
		srv.portmapped <- Some(addr,port,None,0);
		(s, true)
	      with
		  any -> Unix.close s; raise any
	    )
	| Unix path ->
            let s =
              Uq_server.listen_on_unix_socket path stype opts in
	    (s, true)
	| W32_pipe path ->
            let s =
              Uq_server.listen_on_w32_pipe
                Netsys_win32.Pipe_duplex path opts in 
	    (s, true)
	| Descriptor s -> 
	    (s, false)
	| Dynamic_descriptor f -> 
	    let s = f() in
	    (s, true)
    in
    srv.main_socket_name <- ( try
				`Sockaddr (Unix.getsockname fd)
			      with _ -> 
				`Implied 
			    );
    (fd, close_inactive_descr)
  in

  match prot with
    | Udp ->
	let (fd, close_inactive_descr) = get_descriptor() in
	let mplex_eng = create_multiplexer_eng ~close_inactive_descr fd prot in
	when_state
	  ~is_done:(fun mplex ->
		      let conn = connection srv mplex in
		      conn.fd <- Some fd;
		      dlogr_ctrace srv
			(fun () ->
			   sprintf "(sock=%s,peer=%s,dbgname=%s): \
                                    Accepting datagrams"
			     (Rpc_transport.string_of_sockaddr 
				mplex#getsockname)
			     (portname fd)
                             !(srv.dbg_name));
		      if srv.transport_timeout >= 0.0 then
			mplex # set_timeout 
			  ~notify:(on_trans_timeout srv conn) 
			  srv.transport_timeout;
		      (* Try to peek credentials. This can be too early, 
                       * however. 
		       *)
		      peek_credentials srv conn;
		      next_incoming_message srv conn;
		   )
	  ~is_error:(fun exn ->
		       srv.exception_handler exn ""
		    )
	  mplex_eng;
	srv

    | Tcp ->
	let (fd, close_inactive_descr) = get_descriptor() in

	dlogr_ctrace srv
	  (fun () ->
	     sprintf "(sock=%s): Listening"
	       (portname fd));
	if close_inactive_descr then track_server fd;	  
	let acc = 
	  new Uq_server.direct_acceptor 
	    ~close_on_shutdown: close_inactive_descr
	    ~preclose:(fun () -> Netlog.Debug.release_fd fd)
	    fd esys in
	srv.master_acceptor <- Some (Sock_acc acc);
	accept_connections acc;
	srv
;;


let rec set_internal_acceptor srv psock esys =
  dlog_ctrace srv "(internal): waiting for connect";
  let rec attempt() =
    srv.master_acceptor <- None;
    let ok =
      try
        let (rd,wr) =
          Netsys_polysocket.accept ~nonblock:true psock in
        dlog_ctrace srv "(internal): connected";
        let mplex =
          Rpc_transport.internal_rpc_multiplex_controller
            ~dbg_name:srv.dbg_name ~close_inactive_descr:true
            rd wr esys in
        let conn = connection srv mplex in
        conn.fd <- None;
        dlog_ctrace srv "(internal): Serving connection";
        if srv.transport_timeout >= 0.0 then
          mplex # set_timeout 
                ~notify:(on_trans_timeout srv conn) 
                srv.transport_timeout;
        (* Try to peek credentials. This can be too
         * early, however.
         *)
        peek_credentials srv conn;
        next_incoming_message srv conn;
        true
      with
        | Unix.Unix_error(Unix.EAGAIN,_,_)
        | Unix.Unix_error(Unix.EINTR,_,_) ->
            false in
    if ok then wait()
  and wait() =
    let e1 = new Uq_engines.signal_engine esys in
    Netsys_polysocket.set_accept_notify
      psock
      (fun () ->
         e1 # signal (`Done());
      );
    let e1 = (e1 :> _ Uq_engines.engine) in
    srv.master_acceptor <- Some(Engine_acc e1);
    Uq_engines.when_state
      ~is_done:attempt
      e1;
    attempt() in
  wait()
    

let create2 mode esys =
  match mode with
    | `Socket_endpoint(prot,fd) ->
	create2_socket_endpoint prot fd esys
    | `Multiplexer_endpoint mplex ->
	if mplex#event_system != esys then
	  failwith "Rpc_server.create2: Multiplexer is attached \
                    to the wrong event system";
	create2_multiplexer_endpoint mplex 
    | `Socket(prot,conn,config) ->
	create2_socket_server ~config prot conn esys
    | `Dummy prot ->
	let srv = create2_srv prot esys in
	srv.dummy <- true;
	srv
    | `Internal_endpoint(rd,wr) ->
        let dbg_name = ref "<server>" in
        let mplex =
          Rpc_transport.internal_rpc_multiplex_controller
            ~dbg_name ~close_inactive_descr:true
            rd wr esys in
        let srv = create2_multiplexer_endpoint ~dbg_name mplex in
        srv.internal <- true;
        srv
    | `Internal_socket psock ->
        let srv = create2_srv Rpc.Tcp esys in
        srv.internal <- true;
        set_internal_acceptor srv psock esys;
        srv
;;


let is_dummy srv = srv.dummy


let get_pm srv =
  match srv.portmapped with
    | None -> assert false
    | Some(addr, port, pm_opt, pm_count) ->
         ( match pm_opt with
             | None ->
                  let pm =
                    Rpc_portmapper.create_local ~esys:srv.esys () in
                  srv.portmapped <- Some(addr, port, Some pm, 1);
                  pm
             | Some pm ->
                  srv.portmapped <- Some(addr, port, Some pm, pm_count+1);
                  pm
         )

let close_pm srv =
  match srv.portmapped with
    | None -> assert false
    | Some(addr, port, pm_opt, pm_count) ->
         ( match pm_opt with
             | None -> ()
             | Some pm ->
                  srv.portmapped <- Some(addr, port, 
                                         (if pm_count=1 then None else pm_opt),
                                         pm_count-1);
                  if pm_count = 1 then
                    Rpc_portmapper.shut_down pm
         )

let bind ?program_number ?version_number ?(pm_continue=false) prog0 procs srv =
  let prog = Rpc_program.update ?program_number ?version_number prog0 in
  let prog_nr = Rpc_program.program_number prog in
  let vers_nr = Rpc_program.version_number prog in

  let procs =
    uint4_map_mk
      (fun b ->
	 let name =
	   match b with
	     | Sync b' -> b'.sync_name
	     | Async b' -> b'.async_name
	 in
	 Rpc_program.procedure_number prog name, b
      )
      procs in

  let update_service() =
    let old_progbinding =
      try Uint4Map.find prog_nr srv.service
      with Not_found -> Uint4Map.empty in
    
    srv.service <-
      ( Uint4Map.add 
	  prog_nr 
	  ( Uint4Map.add
	      vers_nr
	      (prog, procs)
	      old_progbinding
	  )
	  srv.service 
      ) in

  let pm_error error =
    close_pm srv;
    (try srv.exception_handler error "" with _ -> ()) in

  let pm_unset pm f =
    dlogr srv
      (fun () ->
	 sprintf "unregistering old port");
    Rpc_portmapper.unset_rpcbind'async
      pm prog_nr vers_nr "" "" ""
      (fun get_result ->
	 try
	   let success = get_result() in
	   dlogr srv
	     (fun () ->
		sprintf "portmapper reports %s"
		  (if success then "success" else "failure"));
	   if not success then
	     failwith "Rpc_server.bind: Cannot unregister old port";
	   f ()
	 with
	   | error -> pm_error error
      ) in

  let pm_set_new_port_1 pm addr port f =
    let netid = Rpc.netid_of_inet_addr addr srv.prot in
    let uaddr = Rpc.create_inet_uaddr addr port in
    let owner = string_of_int (Unix.getuid()) in
    dlogr srv
      (fun () ->
	 sprintf "registering netid=%s uaddr=%s owner=%s" netid uaddr owner);
    Rpc_portmapper.set_rpcbind'async
      pm prog_nr vers_nr netid uaddr owner
      (fun get_result ->
	 try
	   let success = get_result() in
	   dlogr srv
	     (fun () ->
		sprintf "portmapper reports %s"
		  (if success then "success" else "failure"));
	   if not success then
	     failwith "Rpc_server.bind: Cannot register port";
	   f ()
	 with
	   | error -> pm_error error
      ) in
  let pm_set_new_port pm addr port f =
    let addrl =
      if Netsys.is_ipv6_inet_addr addr then (
        if addr = Unix.inet6_addr_any then
          [ addr; Unix.inet_addr_any ]
        else if addr = Unix.inet6_addr_loopback then
          [ addr; Unix.inet_addr_loopback ]
        else
          [addr]
      )
      else [addr] in
    let rec recurse l () =
      match l with
        | [] -> f()
        | a :: l' -> pm_set_new_port_1 pm a port (recurse l') in
    recurse addrl () in

  let pm_update_service pm () =
    update_service();
    Rpc_portmapper.shut_down pm in

  match srv.portmapped with
    | None ->
	update_service()

    | Some(addr, port, _, _) ->
	let pm = get_pm srv in
        if pm_continue then
          pm_set_new_port pm addr port (pm_update_service pm)
        else
	  pm_unset
            pm
            (fun () ->
	       pm_set_new_port pm addr port (pm_update_service pm)
	    )
;;


let unbind' ?(followup = fun () -> ()) 
            prog_nr vers_nr srv =

  let update_service() =
    let old_progbinding =
      try Uint4Map.find prog_nr srv.service
      with Not_found -> Uint4Map.empty in
    
    let exists = 
      try ignore(Uint4Map.find vers_nr old_progbinding); true
      with Not_found -> false in

    let progbinding =
      Uint4Map.remove vers_nr old_progbinding in
    
    srv.service <-
      if progbinding = Uint4Map.empty then
	Uint4Map.remove prog_nr srv.service
      else
	Uint4Map.add prog_nr progbinding srv.service;

    exists
  in

  let pm_error error =
    close_pm srv;
    (try srv.exception_handler error "" with _ -> ()) in

  let pm_unset pm f =
    dlogr srv
      (fun () ->
	 sprintf "unregistering port");
    Rpc_portmapper.unset_rpcbind'async
      pm prog_nr vers_nr "" "" ""
      (fun get_result ->
	 try
	   let success = get_result() in
	   dlogr srv
	     (fun () ->
		sprintf "portmapper reports %s"
		  (if success then "success" else "failure"));
	   if not success then
	     failwith "Rpc_server.bind: Cannot unregister old port";
	   f ()
	 with
	   | error -> pm_error error
      ) in

  match srv.portmapped with
    | None ->
	ignore(update_service());
	followup()

    | Some _ ->
	let exists = update_service() in

	if exists then (
	  let pm = get_pm srv in
	  pm_unset pm (fun () -> close_pm srv; followup())
	)
        else
          followup()
;;


let unbind ?program_number ?version_number prog0 srv =
  let prog = Rpc_program.update ?program_number ?version_number prog0 in
  let prog_nr = Rpc_program.program_number prog in
  let vers_nr = Rpc_program.version_number prog in
  unbind' prog_nr vers_nr srv ;;


let unbind_all srv =
  let rec next l =
    match l with
      | [] -> ()
      | (prog_nr, vers_nr) :: l'->
	  unbind' ~followup:(fun () -> next l') prog_nr vers_nr srv
  in
  let l = ref [] in
  Uint4Map.iter
    (fun prog_nr progbinding ->
       Uint4Map.iter
	 (fun vers_nr _ ->
	    l := (prog_nr, vers_nr) :: !l
	 )
	 progbinding
    )
    srv.service;
  next !l
;;


let bound_programs srv =
  let l = ref [] in
  Uint4Map.iter
    (fun prog_nr progbinding ->
       Uint4Map.iter
	 (fun vers_nr (prog,_) ->
	    l := prog :: !l
	 )
	 progbinding
    )
    srv.service;
  !l
;;


let create ?program_number ?version_number
           esys conn prot mode prog0 procs max_clients =

  (* Backwards-compatible! *)

  let srv =
    match mode with
      | BiPipe ->
	  let fd, close_inactive_descr =
	    match conn with
	      | Descriptor fd -> (fd, false)
	      | Dynamic_descriptor f -> ( f(), true )
	      | _ ->
		  invalid_arg "Rpc_server.create: mode incompatible with connector" in
	  create2_socket_endpoint ~close_inactive_descr prot fd esys
      | Socket ->
	  create2_socket_server
	    ~override_listen_backlog:max_clients
	    prot conn esys 
  in
  bind ?program_number ?version_number prog0 procs srv;
  srv
;;


  (*****)

let set_debug_name srv name =
  srv.dbg_name := name

let get_debug_name srv =
  !(srv.dbg_name)

let get_event_system a_session =
    a_session.server.whole_server.esys

let get_connection_id a_session =
    a_session.sess_conn_id

let get_xid a_session =
    a_session.client_id

let get_socket_name a_session =
    Lazy.force a_session.sockaddr

let get_peer_name a_session =
  match a_session.peeraddr with
    | `Implied -> failwith "Cannot determine peer socket name"
    | `Sockaddr a -> a

let get_conn_socket_name conn_id = conn_id # socket_name

let get_conn_peer_name conn_id = conn_id # peer_name

let get_protocol srv = srv.prot

let get_srv_event_system srv = srv.esys

let get_main_socket_name srv =
  match srv.main_socket_name with
    | `Implied -> failwith "Cannot determine main socket name"
    | `Sockaddr a -> a

let get_server sess = sess.server.whole_server

let get_user sess = sess.auth_user

let get_auth_method sess = sess.auth_method

let get_last_proc_info srv = srv.get_last_proc()

let get_tls_session_props sess = sess.tls_session_props

let get_gssapi_props sess = sess.gssapi_props

  (*****)

let reply_error a_session condition =
    let conn = a_session.server in
    let srv = conn.whole_server in
    if conn.trans = None then raise Connection_lost;

    let reply =
      match condition with
	  Unavailable_program
	| Unavailable_version(_,_)
	| Unavailable_procedure
	| Garbage
	| System_err ->
	    pack_accepting_reply
	      srv a_session.client_id
	      a_session.auth_ret_flav a_session.auth_ret_data
              condition
	| _ ->
	    pack_rejecting_reply
	      srv a_session.client_id condition
    in

    let reply_session =
      { a_session with
	  parameter = XV_void;
	  result = reply;
	  ptrace_result = (if !Debug.enable_ptrace then
			     "Error " ^ errname condition
			   else ""
			  )

      }
    in

    Queue.add reply_session conn.replies;

    next_outgoing_message srv conn


let reply a_session result_value =
  let conn = a_session.server in
  let srv = conn.whole_server in

  dlogr srv
    (fun () ->
       sprintf "reply xid=%Ld dbgname=%s have_encoder=%B"
	 (Netnumber.int64_of_uint4 a_session.client_id)
         !(srv.dbg_name)
	 (a_session.encoder <> None)
    );
  
  if conn.trans = None then raise Connection_lost;
  
  let prog =
    match a_session.prog with
      | None -> assert false
      | Some p -> p in

  let f =
    try
      let reply =
        pack_successful_reply
	  ?encoder:a_session.encoder
	  srv prog a_session.procname a_session.client_id
	  a_session.auth_ret_flav a_session.auth_ret_data
	  result_value in
  
      let reply_session =
	{ a_session with
	    parameter = XV_void;
	    result = reply;
	    ptrace_result = (if !Debug.enable_ptrace then
	  		       Rpc_util.string_of_response
				 !Debug.ptrace_verbosity
				 prog
			       a_session.procname
				 result_value
			     else ""
			    )
	}
      in
      (fun () ->
	 Queue.add reply_session conn.replies;
	 next_outgoing_message srv conn
      )
    with (* exceptions raised by the encoder *)
      | Late_drop ->
	  Netlog.logf `Err
	    "Dropping response message";
	  (fun () -> ())
      | Rpc_server condition ->
	  reply_error a_session condition;
	  (fun () -> ())
  in
  f()
    

let set_exception_handler srv eh =
  srv.exception_handler <- eh

let set_onclose_action srv a =
  srv.onclose <- a :: srv.onclose

let set_session_filter_2 srv f =
  srv.filter <- f

let set_session_filter srv f =
  srv.filter <- (fun addr conn_id -> f addr)

let set_auth_methods srv l =
  let h = Hashtbl.create 20 in
  let p = ref [] in
  List.iter
    (fun m ->
       List.iter (fun name -> Hashtbl.add h name m) m#flavors;
       match m # peek with
	 | `None -> ()
	 | other -> p := !p @ [ other, m ];
    )
    l;
  srv.auth_methods <- h;
  srv.auth_peekers <- !p

let set_timeout srv tmo =
  srv.transport_timeout <- tmo

let set_mstring_factories srv fac =
  srv.mstring_factories <- fac

let stop_server ?(graceful = false) srv =
  dlogr srv
    (fun () ->
       sprintf "Stopping %s" (if graceful then " gracefully" else ""));
  (* Close TCP server socket, if present: *)
  ( match srv.master_acceptor with
      | Some (Sock_acc acc) -> 
	  acc # shut_down();
	  srv.master_acceptor <- None
      | Some (Engine_acc e) ->
          e # abort();
	  srv.master_acceptor <- None
      | None -> ()
  );
  unbind_all srv;
  if graceful then (
    let l = srv.connections in
    List.iter
      (fun conn ->
	 if Queue.is_empty conn.replies then
	   terminate_any srv conn;
	 conn.close_when_empty <- true
      )
      l;
  ) else (
    let l = srv.connections in
    srv.connections <- [];
    List.iter
      (fun conn ->
	 terminate_any srv conn
      )
      l
  )

let stop_connection srv conn_id =
  if srv.prot = Tcp then (
    try
      let conn =
	List.find
	  (fun c -> c.conn_id = conn_id)
	  srv.connections in
      terminate_connection srv conn
    with
      | Not_found -> ()
  )

let detach srv =
  (* Detach from connections: *)
    let l = srv.connections in
    srv.connections <- [];
    List.iter
      (fun conn ->
	 conn.fd <- None;
	 match conn.trans with
	   | Some t -> 
	       t#abort_rw();
	       t#cancel_shutting_down()
	   | None -> ()
      )
      l

let xdr_ctx srv =
  if srv.internal then
    Netxdr.default_ctx
  else
    Netxdr.direct_ctx

let verbose b =
  Debug.enable := b;
  Debug.enable_ctrace := b
