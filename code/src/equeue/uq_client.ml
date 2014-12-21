(* $Id$ *)

open Uq_engines
open Printf

type inetspec = Uq_engines.inetspec
type sockspec = Uq_engines.sockspec
type connect_address = Uq_engines.connect_address
type connect_options = Uq_engines.connect_options =
    { conn_bind : sockspec option }

type connect_status = Uq_engines.connect_status

class type client_endpoint_connector = Uq_engines.client_endpoint_connector



let default_connect_options = { conn_bind = None }

let sockspec_of_sockaddr st =
  function
    | Unix.ADDR_INET(ip,port) -> `Sock_inet(st, ip, port)
    | Unix.ADDR_UNIX path -> `Sock_unix(st, path)


let sockspec_of_socksymbol st =
  function
    | `Inet(ip,port) -> `Sock_inet(st, ip, port)
    | `Inet_byname(n,port) -> `Sock_inet_byname(st, n, port)
    | `Unix p -> `Sock_unix(st, p)

let client_endpoint =
  function
      `Socket(fd,_) -> fd
    | `Command(fd,_) -> fd
    | `W32_pipe fd -> fd


let addr_of_name name =
  let entry = Uq_resolver.get_host_by_name name in
  entry.Unix.h_addr_list.(0)
;;


let getsockspec stype s =
  match Unix.getsockname s with
      Unix.ADDR_UNIX path ->
	`Sock_unix(stype, path)
    | Unix.ADDR_INET(addr, port) ->
	`Sock_inet(stype, addr, port)
;;


(*
let getpeerspec stype s =
  (* Warning: this function may fail if the socket is connected and the
     peer does not have an address (e.g. older OSX)
   *)
  match Netsys.getpeername s with
      Unix.ADDR_UNIX path ->
	`Sock_unix(stype, path)
    | Unix.ADDR_INET(addr, port) ->
	`Sock_inet(stype, addr, port)
;;
 *)


let getinetpeerspec stype s =
  try
    match Netsys.getpeername s with
        Unix.ADDR_UNIX path ->
	  None
      | Unix.ADDR_INET(addr, port) ->
	  Some(`Sock_inet(stype, addr, port))
  with
    | _ -> None
;;


(*
let getconnerror s = (* Call this after getpeerspec raised ENOTCONN *)
  try 
    let b = String.make 1 ' ' in
    let _ = Unix.recv s b 0 1 [] in
    assert false
  with
    | error -> error
 *)


(*
type xdom =
    [ `Socket of socket_domain
    | `Pipe
    ]
 *)


(* - new impl, not yet ready *)
(*
class direct_socket_connector() : client_endpoint_connector =
object (self)
  method connect connaddr ues =

    let const_eng v =
      new epsilon_engine(`Done v) ues in

    let sock_prim_data_eng sockspec =
      match sockspec with
	| `Sock_unix(stype, path) ->
	    let addr = Unix.ADDR_UNIX path in
	    const_eng(`Socket Unix.PF_UNIX, stype, addr)
	| `Sock_inet(stype, ip, port) ->
	    let dom = Netsys.domain_of_inet_addr ip in
	    let addr = Unix.ADDR_INET(ip,port) in
	    const_eng(`Socket dom, stype, addr)
	| `Sock_inet_by_name(stype, name, port) ->
	    let ip_opt = XXX in
	    ( match ip_opt with
		| Some ip ->
		    let dom = Netsys.domain_of_inet_addr ip in
		    let addr = Unix.ADDR_INET(ip, port) in
		    const_eng(`Socket dom, stype, addr)
		| None ->
		    (* Now need a real host lookup *)
		    let r = Uq_resolver.current_resolver() in
		    let eng = r # host_by_name name ues in
		    new map_engine
		      ~map_done:(fun he ->
				   let dom = he.Unix.h_addrtype in
				   let ip = he.Unix.h_addr_list.(0) in
				   let addr = Unix.ADDR_INET(ip, port) in
				   `Done(`Socket dom, stype, addr)
				)
		      eng
	    )

	    
	| `Pipe XXX ->
    in

    let sock_data_eng sockspec opts =
      (* Creates an engine that finds out the relevant data to create
         the socket
       *)
      match opts.conn_bind with
	| None ->
	    new map_engine
	      ~map_done:(fun (dom, stype, addr) ->
			   `Done(dom, stype, addr, None))
	      (sock_prim_data_eng sockspec)
	| Some bind_sockspec ->
	    (* Run two resolver engines in parallel *)
	    let d1_eng = sock_prim_data_eng sockspec in
	    let d2_eng = sock_prim_data_eng bind_sockspec in
	    new map_engine
	      ~map_done:(fun ((dom1, stype1, addr1), (dom2, _, addr2)) ->
			   if dom1 <> dom2 then
			     `Error(Failure("direct_socket_connector: Socket domain mismatch"))
			   else
			     `Done(dom1, stype1, addr1, Some addr2)
			)
	      (new sync_engine d1_eng d2_eng)
    in

    let sock_data_check sockspec opts =
      (* Check whether params are valid *) 
      match (sockspec, opts.conn_bind) with
	| `Sock_unix(stype,_), None -> ()
	| `Sock_unix(stype,_), Some(`Sock_unix(stype, _)) -> ()
	| `Sock_inet(stype,_,_), None -> ()
	| `Sock_inet_byname(stype,_,_), None -> ()
	| `Sock_inet(stype,_,_), Some(`Sock_inet(stype,_,_)) -> ()
	| `Sock_inet(stype,_,_), Some(`Sock_inet_byname(stype,_,_)) -> ()
	| `Sock_inet_byname(stype,_,_), Some(`Sock_inet(stype,_,_)) -> ()

	| `Sock_inet_byname(stype,_,_), Some(`Sock_inet_byname(stype,_,_)) -> ()
	| `Pipe(_,_), None -> ()
	| `Pipe(_,_), Some(`Pipe(_,_)) -> ()
	| _ ->
	    invalid_arg "direct_socket_connector: socket type mismatch"
    in

    let create_eng sockspec (dom, stype, addr, bind_addr_opt) ->
      (* Create and connect the socket s, and return the connect engine
       *)
      match dom with
	| `Socket sockdom ->
	    let connect_tried = ref false in
	    let s = Unix.socket sockdom 0 in
	    ( try
		Netsys.set_close_on_exec s;
		Unix.set_nonblock s;
		( match bind_addr_opt with
		    | None -> ()
		    | Some bind_addr ->
			Unix.bind s bind_addr
		);
		connect_tried := true;
		Unix.connect s addr;
		Netsys.connect_check s;
		let fake_conn_eng =
		  const_eng(`Socket(s, getsockspec stype s)) in
		when_state
		  ~is_aborted:(fun _ -> Unix.close s)
		  fake_conn_eng;
		fake_conn_eng
	      with
		| Unix.Unix_error((Unix.EINPROGRESS|Unix.EWOULDBLOCK),_,_) 
		    when !connect_tried -> 
		    (* Note: Win32 returns EWOULDBLOCK instead of EINPROGRESS *)
		    (* Wait until the socket is writeable. Win32 reports connect
                       errors by signaling that out-of-band data can be received
                       (funny, right?), so we wait for that condition, too.
		     *)
		    let poll_eng = 
		      new poll_engine [ Unixqueue.Wait_out s, (-1.0);
					Unixqueue.Wait_oob s, (-1.0)
				      ] ues in
		    let conn_eng =
		      new map_engine
			~map_done:(fun _ ->
				     try
				       Netsys.connect_check s;
				       `Done(getsockspec stype s)
				     with
				       | error -> 
					   Unix.close s; `Error error
				  )
			~map_error:(fun e ->
				      Unix.close s; `Error e)
			~map_aborted:(fun _ ->
					Unix.close s; `Aborted)
			(poll_eng :> Unixqueue.event engine) in
		    conn_eng
		| e ->
		    Unix.close s; raise e
	    )

	| `Pipe ->
	    ( match sockspec with
		| `Pipe(mode,name) ->
		    let ph = Netsys_win32.pipe_connect name mode in
		    let s = Netsys_win32.pipe_descr ph in
		    (s, None)
		      (* CHECK: do we need
		         Netsys_win32.pipe_shutdown ph
		       *)
		| _ ->
		    assert false
	    )
    in

    match connaddr with
      | `Socket(sockspec,opts) ->
	  (* Check on wrong arguments: *)
	  sock_data_check sockspec opts;
	  (* Create and use the engines: *)
	  let data_eng = sock_data_eng sockspec opts in
	  new seq_engine
	    data_eng
	    (fun sock_data ->
	       create_eng sockspec sock_data)
      | _ ->
	  raise Addressing_method_not_supported
end
 *)


(* Old impl with sync name lookup *)
  class direct_connector() : client_endpoint_connector =
  object (self)
    method connect connaddr ues =

      let setup_socket s stype dest_addr opts =
	try
	  Netsys.set_close_on_exec s;
	  Unix.set_nonblock s;
	  ( match opts.conn_bind with
	      | Some bind_spec ->
		  ( match bind_spec with
		      | `Sock_unix(stype', path) ->
			  if stype <> stype' then 
			    invalid_arg "Socket type mismatch";
			  Unix.bind s (Unix.ADDR_UNIX path)
		      | `Sock_inet(stype', addr, port) ->
			  if stype <> stype' then 
			    invalid_arg "Socket type mismatch";
			  Unix.bind s (Unix.ADDR_INET(addr,port))
		      | `Sock_inet_byname(stype', name, port) ->
			  if stype <> stype' then 
			    invalid_arg "Socket type mismatch";
			  let addr = addr_of_name name in
			  Unix.bind s (Unix.ADDR_INET(addr,port))
		  )
	      | None -> ()
	  );
	  Unix.connect s dest_addr;
	  (s, stype, true)
	with
	    Unix.Unix_error((Unix.EINPROGRESS|Unix.EWOULDBLOCK),_,_) -> 
	      (s,stype,false)
		(* Note: Win32 returns EWOULDBLOCK instead of EINPROGRESS *)
	  | error ->
	      (* Remarks:
               * We can get here EAGAIN. Unfortunately, this is a kind of
               * "catch-all" error for Unix.connect, e.g. you can get it when
               * you are run out of local ports, or if the backlog limit is
               * exceeded. It is totally unclear what to do in this case,
               * so we do not handle it here. The user is supposed to connect
               * later again.
               *)
	      Unix.close s; raise error
      in

      match connaddr with
	  `Socket(sockspec,opts) ->
	    let (s, stype, is_connected) = 
	      match sockspec with
		| `Sock_unix(stype, path) ->
		    let s = Unix.socket Unix.PF_UNIX stype 0 in
		    setup_socket s stype (Unix.ADDR_UNIX path) opts;
		| `Sock_inet(stype, addr, port) ->
		    let dom = Netsys.domain_of_inet_addr addr in
		    let s = Unix.socket dom stype 0 in
		    setup_socket s stype (Unix.ADDR_INET(addr,port)) opts;
		| `Sock_inet_byname(stype, name, port) ->
		    let addr = addr_of_name name in
		    let dom = Netsys.domain_of_inet_addr addr in
		    let s = Unix.socket dom stype 0 in
		    setup_socket s stype (Unix.ADDR_INET(addr,port)) opts;
	    in
	    let conn_eng =
	      if is_connected then (
		let status =
		  try 
		    Netsys.connect_check s;
		    `Done(`Socket(s, getsockspec stype s))
		  with
		    | error -> 
			`Error error in
		new epsilon_engine status ues
	      )
	      else (
		(* Now wait until the socket is writeable. Win32 reports connect
                   errors by signaling that out-of-band data can be received
                   (funny, right?), so we wait for that condition, too.
		 *)
		let e = new poll_engine [ Unixqueue.Wait_out s, (-1.0);
					  Unixqueue.Wait_oob s, (-1.0)
					] ues in
		new map_engine
		  ~map_done:(fun _ ->
			       try
				 Netsys.connect_check s;
				 `Done(`Socket(s, getsockspec stype s))
			       with
				 | error -> 
				     `Error error
			    )
		  (e :> Unixqueue.event engine)
	      ) in
	    (* It is possible that somebody aborts conn_eng. In this case,
             * the socket must be closed. Same when we enter an error state.
             *)
	    when_state
	      ~is_aborted:(fun () -> Unix.close s)
	      ~is_error:(fun _ -> Unix.close s)
	      conn_eng;
	    (* conn_eng is what the user sees: *)
	    conn_eng

	| `W32_pipe(mode,name) ->
	    let ph = Netsys_win32.pipe_connect name mode in
	    let s = Netsys_win32.pipe_descr ph in
	    let status = `Done(`W32_pipe s) in
	    let conn_eng = new epsilon_engine status ues in
	    (* It is possible that somebody aborts conn_eng. In this case,
             * the descr must be closed. The error state cannot be reached.
             *)
	    let close() =
	      Netsys_win32.pipe_shutdown ph;
	      Unix.close s
	    in
	    when_state
	      ~is_aborted:(fun () -> close())
	      conn_eng;
	    (* conn_eng is what the user sees: *)
	    conn_eng

	| _ ->
	    raise Addressing_method_not_supported
  end ;;

(* TODO: Close u, v on abort/error *)
(* TODO: port to Win32 *)
class command_connector () : client_endpoint_connector =
object(self)
  method connect connaddr ues =
    match connaddr with
	`Command (cmdstr,cmdcb) ->
          let (u,v) = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in

	  Unix.set_nonblock u;
	  Unix.set_nonblock v;
          Netsys.set_close_on_exec u;
          Netsys.set_close_on_exec v;
 
          let (s_in_sub, s_in) = Unix.pipe() in
          let (s_out, s_out_sub) = Unix.pipe() in
          let _e1 = 
            new Uq_transfer.copier (`Tridirectional(v, s_in, s_out)) ues in
 
	  Netsys.set_close_on_exec s_in;
          Netsys.set_close_on_exec s_out;

	  let e2 = new epsilon_engine (`Done ()) ues in
	    
	  new map_engine
	    ~map_done:(fun _ ->
			 let pid =
			   Unix.create_process
			     "/bin/sh"
			     [| "/bin/sh"; "-c"; cmdstr |]
			     s_in_sub s_out_sub Unix.stderr in
			 (* CHECK: Are the other descriptors closed? *)
			 Unix.close s_in_sub;
			 Unix.close s_out_sub;
			 cmdcb pid ues;
			 `Done (`Command(u, pid)))
	    e2

      | _ ->
	  raise Addressing_method_not_supported
end
;;


let connect_e ?proxy connaddr ues =
  let eff_proxy =
    match proxy with
	Some p -> ( p :> client_endpoint_connector )
      | None   -> 
	  ( match connaddr with
	      | `Socket _ 
	      | `W32_pipe _ ->
		  new direct_connector()
	      | `Command _ ->
		  new command_connector()
	  )
  in
  eff_proxy # connect connaddr ues
;;


let client_endpoint =
  function
      `Socket(fd,_) -> fd
    | `Command(fd,_) -> fd
    | `W32_pipe fd -> fd

let connect ?proxy addr tmo =
  let esys = Unixqueue.create_unix_event_system() in
  let run e1 =
    let e2 = Uq_engines.timeout_engine tmo Uq_engines.Timeout e1 in
    Unixqueue.run esys;
    match e2#state with
      | `Done n -> n
      | `Error err -> raise err
      | `Aborted -> failwith "Aborted"
      | `Working _ -> assert false in
  run(connect_e ?proxy addr esys)


let client_channel st timeout =
  let esys = Unixqueue.create_unix_event_system() in
  let fd = client_endpoint st in
  let dev = `Polldescr(Netsys.get_fd_style fd, fd, esys) in
  Uq_io.io_obj_channel dev timeout
