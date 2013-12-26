(* $Id$ *)

open Uq_engines
open Printf

let dlog = Netlog.Debug.mk_dlog "Uq_engines" Uq_engines.Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Uq_engines" Uq_engines.Debug.enable


class type multiplex_controller = 
  Uq_engines.multiplex_controller

class type datagram_multiplex_controller =
  Uq_engines.datagram_multiplex_controller

exception Mem_not_supported = Uq_engines.Mem_not_supported

let anyway ~finally f arg =
  try
    let r = f arg in
    finally();
    r
  with 
    | error ->
	finally();
	raise error
;;


class socket_multiplex_controller
         ?(close_inactive_descr = true)
         ?(preclose = fun () -> ())
         ?(supports_half_open_connection = false)
	 ?timeout
         fd esys : datagram_multiplex_controller =

  let fd_style = Netsys.get_fd_style fd in

  let get_ph() = Netsys_win32.lookup_pipe fd in
    (* To be used only when fd_style = `Pipe *)

  let supports_half_open_connection =
    match fd_style with
      | `W32_pipe -> false
      | _ -> supports_half_open_connection in

  let mem_supported =
    match fd_style with
      | `Read_write -> true
      | `Recv_send _ -> true
      | `Recv_send_implied -> true
      | _ -> false in

  let start_timer f =
    (* Call [f x] when the timer fires *)
    match timeout with
      | None ->
	  None
      | Some (tmo, x) ->
	  let tmo_g = Unixqueue.new_group esys in
	  Unixqueue.once esys tmo_g tmo (fun () -> f x);
	  Some (tmo_g, f) in

  let stop_timer r =
    match !r with
      | None -> ()
      | Some (old_tmo_g, f) ->
	  Unixqueue.clear esys old_tmo_g;
	  r := None in

(*
  let () =
    prerr_endline ("fd style: " ^ Netsys.string_of_fd_style fd_style) in
 *)

object(self)
  val mutable alive = true
  val mutable read_eof = false
  val mutable wrote_eof = false
  val mutable reading = `None
  val mutable reading_tmo = ref None
  val mutable writing = `None
  val mutable writing_tmo = ref None
  val mutable writing_eof = None
  val mutable shutting_down = None
  val mutable shutting_down_tmo = ref None
  val mutable disconnecting = None
  val mutable need_linger = false
  val mutable have_handler = false

  val mutable rcvd_from = None
  val mutable send_to = None

  val group = Unixqueue.new_group esys

  method alive = alive
  method mem_supported = mem_supported
  method reading = reading <> `None
  method writing = writing <> `None || writing_eof <> None
  method shutting_down = shutting_down <> None
  method read_eof = read_eof
  method wrote_eof = wrote_eof

  method supports_half_open_connection = supports_half_open_connection

  method received_from =
    match rcvd_from with
      | None -> 
	  failwith "#received_from: Nothing received yet, or unknown address"
      | Some a -> a

  method send_to a =
    send_to <- Some a

  initializer
    ( match fd_style with
	| `W32_pipe -> ()
	| `W32_event | `W32_pipe_server | `W32_input_thread 
	| `W32_output_thread | `W32_process ->
	    invalid_arg "Uq_engines.socket_multiplex_controller: \
                       invalid type of file descriptor"
	| _ -> 
	    Unix.set_nonblock fd
    );
    dlogr (fun () ->
	     sprintf
	       "new socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))

  method private restart_all_timers() =
    match timeout with
      | None ->
	  ()
      | Some (tmo, x) ->
	  List.iter
	    (fun r ->
	       match !r with
		 | None -> ()
		 | Some (old_tmo_g, f) ->
		     Unixqueue.clear esys old_tmo_g;
		     r := start_timer f
	    )
	    [ reading_tmo; writing_tmo; shutting_down_tmo ]


  method start_reading ?(peek = fun ()->()) ~when_done s pos len =
    if pos < 0 || len < 0 || pos > String.length s - len then
      invalid_arg "#start_reading";
    if reading <> `None then
      failwith "#start_reading: already reading";
    if shutting_down <> None then
      failwith "#start_reading: already shutting down";
    if not alive then
      failwith "#start_reading: inactive connection";
    self # check_for_connect();
    Unixqueue.add_resource esys group (Unixqueue.Wait_in fd, -1.0);
    reading <- `String(when_done, peek, s, pos, len);
    reading_tmo := start_timer self#cancel_reading_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_reading socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))


  method start_mem_reading ?(peek = fun ()->()) ~when_done m pos len =
    if not mem_supported then raise Mem_not_supported;
    if pos < 0 || len < 0 || pos > Bigarray.Array1.dim m - len then
      invalid_arg "#start_mem_reading";
    if reading <> `None then
      failwith "#start_mem_reading: already reading";
    if shutting_down <> None then
      failwith "#start_mem_reading: already shutting down";
    if not alive then
      failwith "#start_mem_reading: inactive connection";
    self # check_for_connect();
    Unixqueue.add_resource esys group (Unixqueue.Wait_in fd, -1.0);
    reading <- `Mem(when_done, peek, m, pos, len);
    reading_tmo := start_timer self#cancel_reading_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_reading socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))


  method cancel_reading () =
    self # cancel_reading_with Cancelled

  method private cancel_reading_with x =
    match reading with
      | `None ->
	  ()
      | `String(f_when_done, _, _, _, _) ->
	  self # really_cancel_reading();
	  anyway
	    ~finally:self#check_for_disconnect
	    (f_when_done (Some x)) 0
      | `Mem(f_when_done, _, _, _, _) ->
	  self # really_cancel_reading();
	  anyway
	    ~finally:self#check_for_disconnect
	    (f_when_done (Some x)) 0

  method private really_cancel_reading() =
    stop_timer reading_tmo;
    if reading <> `None then (
      Unixqueue.remove_resource esys group (Unixqueue.Wait_in fd);
      reading <- `None;
      dlogr (fun () ->
	       sprintf
		 "cancel_reading socket_multiplex_controller mplex=%d fd=%Ld"
		 (Oo.id self) (Netsys.int64_of_file_descr fd))
    )

  method start_writing ~when_done s pos len =
    if pos < 0 || len < 0 || pos > String.length s - len then
      invalid_arg "#start_writing";
    if writing <> `None || writing_eof <> None then
      failwith "#start_writing: already writing";
    if shutting_down <> None then
      failwith "#start_writing: already shutting down";
    if wrote_eof then
      failwith "#start_writing: already past EOF";
   if not alive then
      failwith "#start_writing: inactive connection";
    self # check_for_connect();
    Unixqueue.add_resource esys group (Unixqueue.Wait_out fd, -1.0);
    writing <- `String(when_done, s, pos, len);
    writing_tmo := start_timer self#cancel_writing_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_writing socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))

  method start_mem_writing ~when_done m pos len =
    if not mem_supported then raise Mem_not_supported;
    if pos < 0 || len < 0 || pos > Bigarray.Array1.dim m - len then
      invalid_arg "#start_mem_writing";
    if writing <> `None || writing_eof <> None then
      failwith "#start_mem_writing: already writing";
    if shutting_down <> None then
      failwith "#start_mem_writing: already shutting down";
    if wrote_eof then
      failwith "#start_mem_writing: already past EOF";
    if not alive then
      failwith "#start_mem_writing: inactive connection";
    self # check_for_connect();
    Unixqueue.add_resource esys group (Unixqueue.Wait_out fd, -1.0);
    writing <- `Mem(when_done, m, pos, len);
    writing_tmo := start_timer self#cancel_writing_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_writing socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))

  method start_writing_eof ~when_done () =
    if not supports_half_open_connection then
      failwith "#start_writing_eof: operation not supported";
    (* From here on we know fd is not a named pipe *)
    if writing <> `None || writing_eof <> None then
      failwith "#start_writing_eof: already writing";
    if shutting_down <> None then
      failwith "#start_writing_eof: already shutting down";
    if wrote_eof then
      failwith "#start_writing_eof: already past EOF";
    if not alive then
      failwith "#start_writing_eof: inactive connection";
    self # check_for_connect();
    Unixqueue.add_resource esys group (Unixqueue.Wait_out fd, -1.0);
    writing_eof <- Some when_done;
    writing_tmo := start_timer self#cancel_writing_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_writing_eof socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))


  method cancel_writing () =
    self # cancel_writing_with Cancelled

  method private cancel_writing_with x =
    match writing, writing_eof with
      | `None, None ->
	  ()
      | (`String(f_when_done, _, _, _) | `Mem(f_when_done, _, _, _)), None ->
	  self # really_cancel_writing();
	  anyway
	    ~finally:self#check_for_disconnect
	    (f_when_done (Some x)) 0
      | `None, Some f_when_done ->
	  self # really_cancel_writing();
	  anyway
	    ~finally:self#check_for_disconnect
	    f_when_done (Some x)
      | _ ->
	  assert false

  method private really_cancel_writing() =
    stop_timer writing_tmo;
    if writing <> `None || writing_eof <> None then (
      Unixqueue.remove_resource esys group (Unixqueue.Wait_out fd);
      writing <- `None;
      writing_eof <- None;
      dlogr (fun () ->
	       sprintf
		 "cancel_writing socket_multiplex_controller mplex=%d fd=%Ld"
		 (Oo.id self) (Netsys.int64_of_file_descr fd))

    )

  method start_shutting_down ?(linger = 60.0) ~when_done () =
    if reading <> `None || writing <> `None || writing_eof <> None then
      failwith "#start_shutting_down: still reading or writing";
    if shutting_down <> None then
      failwith "#start_shutting_down: already shutting down";
    if not alive then
      failwith "#start_shutting_down: inactive connection";
    self # check_for_connect();
    let linger_timeout = 
      if need_linger then linger else 0.0 in
    let wid = Unixqueue.new_wait_id esys in
    let (op, tmo) =
      if linger_timeout = 0.0 then
	(Unixqueue.Wait wid, 0.0)
      else
	(Unixqueue.Wait_in fd, linger_timeout) in
    Unixqueue.add_resource esys group (op,tmo);
    shutting_down <- Some(when_done, op);
    shutting_down_tmo := start_timer self#cancel_shutting_down_with;
    disconnecting <- None;
    dlogr (fun () ->
	     sprintf
	       "start_shutting_down socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd))

  method cancel_shutting_down () =
    self # cancel_shutting_down_with Cancelled
    
  method private cancel_shutting_down_with x =
    match shutting_down with
      | None ->
	  ()
      | Some (f_when_done, _) ->
	  self # really_cancel_shutting_down ();
	  anyway
	    ~finally:self#check_for_disconnect
	    f_when_done (Some x)


  method private really_cancel_shutting_down () =
    stop_timer shutting_down_tmo;
    match shutting_down with
      | None -> 
	  ()
      | Some (_, op) ->
	  Unixqueue.remove_resource esys group op;
	  shutting_down <- None;
	  dlogr (fun () ->
		   sprintf
		     "cancel_shutting_down \
                        socket_multiplex_controller mplex=%d fd=%Ld"
		     (Oo.id self) (Netsys.int64_of_file_descr fd))


  method private check_for_connect() =
    if not have_handler then (
      Unixqueue.add_handler esys group (fun _ _ -> self # handle_event);
      have_handler <- true
    );
    disconnecting <- None

  method private check_for_disconnect() =
    if reading = `None && writing = `None && writing_eof = None && 
         shutting_down = None && disconnecting = None then
	   (
	     let wid = Unixqueue.new_wait_id esys in
	     let disconnector = Unixqueue.Wait wid in
	     Unixqueue.add_event esys (Unixqueue.Timeout(group,disconnector));
	     disconnecting <- Some disconnector
	   )

  method private notify_rd f_when_done exn_opt n =
    self # really_cancel_reading();
    self # restart_all_timers();
    dlogr (fun () ->
	     sprintf
	       "input_done \
                socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd));
    anyway
      ~finally:self#check_for_disconnect
      (f_when_done exn_opt) n

  method private notify_wr f_when_done exn_opt n =
    self # really_cancel_writing();
    self # restart_all_timers();
    dlogr (fun () ->
	     sprintf
	       "output_done \
                socket_multiplex_controller mplex=%d fd=%Ld"
	       (Oo.id self) (Netsys.int64_of_file_descr fd));
    anyway
      ~finally:self#check_for_disconnect
      (f_when_done exn_opt) n

  method private handle_event ev =
    match ev with
      | Unixqueue.Input_arrived(g, _) when g = group ->
	  dlogr (fun () ->
		   sprintf
		     "input_event \
                        socket_multiplex_controller mplex=%d fd=%Ld"
		     (Oo.id self) (Netsys.int64_of_file_descr fd));
	  ( match reading with
	      | `None -> ()
	      | `String (f_when_done, peek, _, _, _)
	      | `Mem    (f_when_done, peek, _, _, _) -> (
		  peek();
		  try
		    rcvd_from <- None;
		    let n = 
		      match reading with
			| `None -> assert false
			| `String(_,_, s, pos, len) -> (
			    match fd_style with
			      | `Recv_send(_,a) ->
				  let n = Unix.recv fd s pos len [] in
				  rcvd_from <- Some a;
				  n
			      | `Recvfrom_sendto ->
				  let (n, a) = Unix.recvfrom fd s pos len [] in
				  rcvd_from <- Some a;
				  n
			      | _ ->
				  Netsys.gread fd_style fd s pos len
			  )
			| `Mem(_,_, m, pos, len) -> (
			    match fd_style with
			      | `Recv_send(_,a) ->
				  let n = 
				    Netsys_mem.mem_recv fd m pos len [] in
				  rcvd_from <- Some a;
				  n
			      | `Recv_send_implied ->
				  Netsys_mem.mem_recv fd m pos len []
			      | `Read_write ->
				  Netsys_mem.mem_read fd m pos len
			      | _ ->
				  assert false
			  )  in
		    if n = 0 then (
		      read_eof <- true;
		      need_linger <- false;
		      self # notify_rd f_when_done (Some End_of_file) 0
		    )
		    else
		      self # notify_rd f_when_done None n
		  with
		    | Unix.Unix_error(Unix.EAGAIN,_,_)
		    | Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
		    | Unix.Unix_error(Unix.EINTR,_,_) ->
			()
		    | error ->
			self # notify_rd f_when_done (Some error) 0
		)
	  );
	  ( match shutting_down with
	      | Some (f_when_done, op) when op = Unixqueue.Wait_in fd ->
		  let exn_opt, notify =
		    try
		      Netsys.gshutdown fd_style fd Unix.SHUTDOWN_ALL;
		      (None, true)
		    with
		      | Unix.Unix_error(Unix.EAGAIN,_,_)
		      | Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
		      | Unix.Unix_error(Unix.EINTR,_,_) ->
			  (None, false)
		      | Unix.Unix_error(Unix.ENOTCONN,_,_) ->
			  (None, true)
		      | Unix.Unix_error(Unix.EPERM,_,_) ->
			  (None, true)
		      | error ->
			  (Some error, true)
		  in
		  if notify then (
		    self # really_cancel_shutting_down();
		    stop_timer shutting_down_tmo;
		    read_eof <- true;
		    wrote_eof <- true;
		    dlogr (fun () ->
			     sprintf
			       "shutdown_done \
                                  socket_multiplex_controller mplex=%d fd=%Ld"
			       (Oo.id self) (Netsys.int64_of_file_descr fd));
		    anyway
		      ~finally:self#check_for_disconnect
		      f_when_done exn_opt
		  )
	      | _ -> ()
	  )

      | Unixqueue.Output_readiness(g, _) when g = group ->
	  dlogr (fun () ->
		   sprintf
		     "output_event \
                        socket_multiplex_controller mplex=%d fd=%Ld"
		     (Oo.id self) (Netsys.int64_of_file_descr fd));
	  ( match writing with
	      | `None -> ()
	      | `String (f_when_done, _, _, _)
	      | `Mem    (f_when_done, _, _, _) -> (
		  try
		    let n = 
		      match writing with
			| `None -> assert false
			| `String(_, s, pos, len) -> (
			    match fd_style with
			      | `Recvfrom_sendto ->
				  ( match send_to with
				      | None ->
					  failwith "socket_multiplex_controller: Unknown receiver of message to send"
				      | Some a ->
					  Unix.sendto fd s pos len [] a
				  )
			      | _ ->
				  Netsys.gwrite fd_style fd s pos len 
			  )
			| `Mem(_, m, pos, len) -> (
			    match fd_style with
			      | `Recv_send _ ->
				  Netsys_mem.mem_send fd m pos len []
			      | `Recv_send_implied ->
				  Netsys_mem.mem_send fd m pos len []
			      | `Read_write ->
				  Netsys_mem.mem_write fd m pos len
			      | _ ->
				  assert false
			  ) in
		    self # notify_wr f_when_done None n
		  with
		    | Unix.Unix_error(Unix.EAGAIN,_,_)
		    | Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
		    | Unix.Unix_error(Unix.EINTR,_,_) ->
			()
		    | error ->
			self # notify_wr f_when_done (Some error) 0
		)
	  );
	  ( match writing_eof with
	      | None -> ()
	      | Some f_when_done ->
		  let exn_opt, notify =
		    try
		      if not wrote_eof then (
			Netsys.gshutdown fd_style fd Unix.SHUTDOWN_SEND;
			if not read_eof then need_linger <- true;
			wrote_eof <- true
		      );
		      (None, true)
		    with
		      | Unix.Unix_error(Unix.EAGAIN,_,_)
		      | Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
		      | Unix.Unix_error(Unix.EINTR,_,_) ->
			  (None, false)
		      | Netsys.Shutdown_not_supported ->
			  (None, true)
		  in
		  if notify then (
		    self # really_cancel_writing();
		    dlogr (fun () ->
			     sprintf
			       "output_eof_done \
                                  socket_multiplex_controller mplex=%d fd=%Ld"
			       (Oo.id self) (Netsys.int64_of_file_descr fd));
		    anyway
		      ~finally:self#check_for_disconnect
		      f_when_done exn_opt
		  )
	  )

      | Unixqueue.Timeout (g, op) when g = group ->
	  (* Note: The following is incompatible with [once] because we
           * always accept timeout events!
           *)
	  dlogr (fun () ->
		   sprintf
		     "other_event \
                        socket_multiplex_controller mplex=%d fd=%Ld"
		     (Oo.id self) (Netsys.int64_of_file_descr fd));
	  ( match shutting_down with
	      | Some (f_when_done, op') when op = op' ->
		  let exn_opt, notify =
		    try
		      match fd_style with
			| `W32_pipe ->
			    let ph = get_ph() in
			    Netsys_win32.pipe_shutdown ph;
			    (None, true)
			| _ ->
			    Unix.shutdown fd 
			      (if wrote_eof then Unix.SHUTDOWN_RECEIVE else
				 Unix.SHUTDOWN_ALL);
			    (None, true)
		    with
		      | Unix.Unix_error(Unix.EAGAIN,_,_)
		      | Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
		      | Unix.Unix_error(Unix.EINTR,_,_) ->
			  assert false  (* Not documented in man pages *)
		      | Unix.Unix_error(Unix.ENOTCONN,_,_) ->
			  (None, true)
		      | error ->
			  (Some error, true)
		  in
		  if notify then (
		    self # really_cancel_shutting_down();
		    read_eof <- true;
		    wrote_eof <- true;
		    dlogr (fun () ->
			     sprintf
			       "shutdown_done \
                                  socket_multiplex_controller mplex=%d fd=%Ld"
			       (Oo.id self) (Netsys.int64_of_file_descr fd));
		    anyway
		      ~finally:self#check_for_disconnect
		      f_when_done exn_opt
		  )
	      | _ -> ()
	  );
	  ( match disconnecting with
	      | Some op' when op = op' ->
		  disconnecting <- None;
		  have_handler <- false;
		  raise Equeue.Terminate

	      | _ -> ()
	  )

      | _ ->
	  raise Equeue.Reject

  method inactivate() =
    dlogr (fun () ->
	     sprintf 
	       "inactivate \
                  socket_multiplex_controller mplex=%d fd=%Ld alive=%b \
                  close_inactive_descr=%b"
	       (Oo.id self) (Netsys.int64_of_file_descr fd) alive
	       close_inactive_descr);
    if alive then (
      alive <- false;
      self # really_cancel_reading();
      self # really_cancel_writing();
      self # really_cancel_shutting_down();
      stop_timer reading_tmo;
      stop_timer writing_tmo;
      stop_timer shutting_down_tmo;
      disconnecting <- None;
      have_handler <- false;
      Unixqueue.clear esys group;
      if close_inactive_descr then (
	preclose();
	Netsys.gclose fd_style fd
 	(* It is important that Unix.close (or substitute) is the very
           last action. From here on, a thread running in parallel can
           allocate this descriptor again, so it is essential that there
           are no references anymore to it when the old descriptor is closed.
	 *)
      )
    )

  method event_system = esys

end
;;


let create_multiplex_controller_for_connected_socket 
       ?close_inactive_descr ?preclose ?supports_half_open_connection 
       ?timeout
       fd esys =
  let mplex = 
    new socket_multiplex_controller
      ?close_inactive_descr ?preclose ?supports_half_open_connection 
      ?timeout
      fd esys in
  (mplex :> multiplex_controller)
;;


let create_multiplex_controller_for_datagram_socket 
       ?close_inactive_descr ?preclose ?timeout fd esys =
  let mplex = 
    new socket_multiplex_controller
      ?close_inactive_descr ?preclose ~supports_half_open_connection:false 
      ?timeout
      fd esys in
  (mplex :> datagram_multiplex_controller)
;;
