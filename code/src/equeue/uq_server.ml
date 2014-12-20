(* $Id$ *)

open Uq_engines

type listen_address =
  Uq_engines.listen_address

 and listen_options = Uq_engines.listen_options =
    { lstn_backlog : int;
      lstn_reuseaddr : bool;
    }

class type server_endpoint_acceptor =
  Uq_engines.server_endpoint_acceptor


let default_listen_options =
  { lstn_backlog = 20;
    lstn_reuseaddr = false;
  }
;;


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



class direct_acceptor ?(close_on_shutdown=true) ?(preclose=fun()->())
                      fd ues : server_endpoint_acceptor =
  let fd_style = Netsys.get_fd_style fd in
  let pipe_objects = lazy (
    let psrv = Netsys_win32.lookup_pipe_server fd in
    let cn_ev = Netsys_win32.pipe_connect_event psrv in
    let cn_ev_descr = Netsys_win32.event_descr cn_ev in
    (psrv, cn_ev, cn_ev_descr)
  ) in
  let () =
    match fd_style with
      | `Read_write | `W32_pipe | `W32_event ->
	  failwith "Uq_engines.direct_acceptor: endpoint not supported"
      | `W32_pipe_server ->
	  ignore(Lazy.force pipe_objects)
      | _ -> () in
object(self)
  val mutable acc_engine = None
			     (* The engine currently accepting connections *)

  method server_address = 
    match fd_style with
      | `W32_pipe_server ->
	  let (psrv, _, _) = Lazy.force pipe_objects in
	  let name = Netsys_win32.pipe_server_name psrv in
	  let mode = Netsys_win32.pipe_server_mode psrv in
	  let mode' = Netsys_win32.rev_mode mode in
	  `W32_pipe(mode',name)
      | `Recv_send _ | `Recvfrom_sendto | `Recv_send_implied ->
	  `Socket(getsockspec Unix.SOCK_STREAM fd,
		  Uq_client.default_connect_options)
      | _ ->
	  assert false

  method multiple_connections = true

  method accept () =
    (* Poll until the socket becomes readable, then accept it *)
    if acc_engine <> None then
      failwith "Uq_engines.direct_acceptor: Already waiting for connection";

    let socket_accept_eng() =
      let eng = new poll_engine [ Unixqueue.Wait_in fd, (-1.0) ] ues in
      new map_engine
	~map_done:(fun _ ->
		     try
		       let (fd',_) = Unix.accept fd in
		       Unix.set_nonblock fd';
		       (* There seem to be buggy kernels out there where
                        * [accept] does not always return a connected socket.
                        * We get ENOTCONN for [getpeername] then.
                        * Who does that? The super hackers at SW-Soft with
                        * their Virtuozzo shit.
                        *)
		       let ps =
			 try getinetpeerspec Unix.SOCK_STREAM fd'
			 with
			   | Unix.Unix_error(Unix.ENOTCONN,_,_) as e ->
			       Unix.close fd';
			       raise e in
		       acc_engine <- None;
		       `Done(fd', ps)
		     with
		       | Unix.Unix_error( (Unix.EAGAIN | Unix.EINTR | 
					       Unix.ENOTCONN), _, _) ->
			   eng # restart();
			   `Working 0
		       | error ->
			   `Error error
		  )
	eng
    in

    let w32_pipe_accept_eng() =
      let (psrv, cn_ev, cn_ev_descr) = Lazy.force pipe_objects in
      let eng = 
	new poll_engine [ Unixqueue.Wait_in cn_ev_descr, (-1.0) ] ues in
      new map_engine
	~map_done:(fun _ ->
		     try
		       let pipe = Netsys_win32.pipe_accept psrv in
		       let pipe_fd = Netsys_win32.pipe_descr pipe in
		       acc_engine <- None;
		       `Done(pipe_fd, None)
		     with
		       | Unix.Unix_error( (Unix.EAGAIN | Unix.EINTR | 
					       Unix.ENOTCONN), _, _) ->
			   eng # restart();
			   `Working 0
		       | error ->
			   `Error error
		  )
	eng
    in

    let acc_eng = 
      match fd_style with
	| `Recv_send _ | `Recvfrom_sendto | `Recv_send_implied ->
	    socket_accept_eng()
	| `W32_pipe_server ->
	    w32_pipe_accept_eng() 
	| _ ->
	    assert false in
    when_state
      ~is_error:(fun x -> acc_engine <- None)
      ~is_aborted:(fun () -> acc_engine <- None)
      acc_eng;

    acc_engine <- Some acc_eng;
    acc_eng

  method shut_down() =
    if close_on_shutdown then (
      preclose();
      ( match fd_style with
	  | `Recv_send _ | `Recvfrom_sendto | `Recv_send_implied ->
	      Unix.close fd
	  | `W32_pipe_server ->
	      let (psrv, _, cn_ev_descr) = Lazy.force pipe_objects in
	      Unix.close cn_ev_descr;
	      Netsys_win32.pipe_shutdown_server psrv;
	      Unix.close fd
	  | _ ->
	      assert false
      )
    );
    (* else: if not close_on_shutdown, there is no portable way of
       achieving that further connection attempts are refused by the
       kernel. listen(fd,0) works on some systems, but not on all.
     *)
    match acc_engine with
	None -> 
	  ()
      | Some acc -> 
	  acc # abort()

end
;;


let listen_on_inet_socket_1 addr port stype opts =
  let dom = Netsys.domain_of_inet_addr addr in
  let s = Unix.socket dom stype 0 in
  try
    Unix.set_nonblock s;
    if opts.lstn_reuseaddr then 
      Unix.setsockopt s Unix.SO_REUSEADDR true;
    Unix.bind s (Unix.ADDR_INET(addr,port));
    if stype = Unix.SOCK_STREAM || stype = Unix.SOCK_SEQPACKET then
      Unix.listen s opts.lstn_backlog;
    s
  with
    | error -> Unix.close s; raise error


let listen_on_inet_socket addr port stype opts =
  (* NB. If IPv6 is not compiled in, inet6_addr_loopback defaults to
     inet_addr_loopback (see unix.ml)
   *)
  let dom = Netsys.domain_of_inet_addr addr in
  try
    listen_on_inet_socket_1 addr port stype opts
  with
    | Unix.Unix_error(Unix.EAFNOSUPPORT,_,_) as e when dom = Unix.PF_INET6 ->
        (* fallback to IPv4 if possible *)
        if addr = Unix.inet6_addr_loopback then
          listen_on_inet_socket_1 Unix.inet_addr_loopback port stype opts
        else if addr = Unix.inet6_addr_any then
          listen_on_inet_socket_1 Unix.inet_addr_any port stype opts
        else
          raise e


let listen_on_unix_socket path stype opts =
  if Sys.os_type = "Win32" then (
    (* emulation *)
    let s = listen_on_inet_socket_1 Unix.inet_addr_loopback 0 stype opts in
    ( match Unix.getsockname s with
	| Unix.ADDR_INET(_, port) ->
	    let f = open_out path in
	    output_string f (string_of_int port ^ "\n");
	    close_out f
	| _ -> ()
    );
    s
  )
  else
    let s = Unix.socket Unix.PF_UNIX stype 0 in
    try
      Unix.set_nonblock s;
      if opts.lstn_reuseaddr then 
        Unix.setsockopt s Unix.SO_REUSEADDR true;
      Unix.bind s (Unix.ADDR_UNIX path);
      if stype = Unix.SOCK_STREAM || stype = Unix.SOCK_SEQPACKET then
        Unix.listen s opts.lstn_backlog;
      s
    with
      | error -> Unix.close s; raise error


let listen_on_w32_pipe mode name opts =
  let backlog = opts.lstn_backlog in
  let psrv = Netsys_win32.create_local_pipe_server name mode max_int in
  Netsys_win32.pipe_listen psrv backlog;
  Netsys_win32.pipe_server_descr psrv


let listen_on lstnaddr =
  match lstnaddr with
      | `Socket (sockspec, opts) ->
	  ( match sockspec with
		`Sock_unix(stype, path) ->
                  listen_on_unix_socket path stype opts
	      | `Sock_inet(stype, addr, port) ->
                  listen_on_inet_socket addr port stype opts 
	      | `Sock_inet_byname(stype, name, port) ->
		  let addr = addr_of_name name in
                  listen_on_inet_socket addr port stype opts
	  )
      | `W32_pipe (mode, name, opts) ->
          listen_on_w32_pipe mode name opts
      | _ ->
	  raise Addressing_method_not_supported



class direct_listener () : server_endpoint_listener =
object(self)
  method listen lstnaddr ues =
    let accept fd =
      let acc = new direct_acceptor fd ues in
      let eng = new epsilon_engine (`Done acc) ues in
      when_state
	~is_aborted:(fun () -> acc # shut_down())
	~is_error:(fun _ -> acc # shut_down())
	eng;
      eng  in
    let fd = listen_on lstnaddr in
    accept fd
end
;;


let listener ?proxy lstnaddr ues =
  let eff_proxy =
    match proxy with
	Some p -> ( p :> server_endpoint_listener )
      | None   -> 
	  ( match lstnaddr with
	      | `Socket _ | `W32_pipe _ ->
		  new direct_listener()
	  )
  in
  eff_proxy # listen lstnaddr ues
;;
