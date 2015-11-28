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
  method tls_session_props = None
  method tls_session = None
  method tls_stashed_endpoint = failwith "#tls_stashed_endpoint"
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
    if pos < 0 || len < 0 || pos > Bytes.length s - len then
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
    if pos < 0 || len < 0 || pos > Bytes.length s - len then
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


(* TLS support *)

class type tls_adapter =
object
  method enable_recv : bool -> unit
  method enable_send : bool -> unit
  method recv : Netsys_mem.memory -> int
  method send : Netsys_mem.memory -> int -> int
  method recv_size : int
  method send_size : int
  method hidden_exn : exn option
end


let tls_adapter (mplex : multiplex_controller) on_input on_output 
    : tls_adapter =
  let en_recv = ref false in
  let en_send = ref false in
  let in_buf = 
    if mplex#mem_supported then
      `Memory (Netsys_mem.pool_alloc_memory Netsys_mem.default_pool)
    else
      `String (Bytes.create Netsys_mem.default_block_size) in 
  let in_pos = ref 0 in
  let in_size = ref 0 in
  let in_exn = ref None in
  let out_buf =
    if mplex#mem_supported then
      `Memory (Netsys_mem.pool_alloc_memory Netsys_mem.default_pool)
    else
      `String (Bytes.create Netsys_mem.default_block_size) in 
  let out_pos = ref 0 in
  let out_size = ref 0 in
  let out_exn = ref None in
  let hidden_exn = ref None in

  let update_input() =
    if !en_recv && !in_size = 0 && mplex#alive then (
      if not mplex#reading then
        let when_done exn_opt p =
          in_pos := 0;
          in_size := p;
          in_exn := exn_opt;
          hidden_exn := exn_opt;
          if exn_opt <> Some Cancelled then on_input() in
        match in_buf with
          | `Memory mem ->
               let n = Bigarray.Array1.dim mem in
               mplex # start_mem_reading ~when_done mem 0 n
          | `String str ->
               let n = Bytes.length str in
               mplex # start_reading ~when_done str 0 n
    )
    else
      mplex # cancel_reading() in

  let rec update_output() =
    if !en_send && !out_size > 0 && mplex#alive then (
      if not mplex#writing then
        let when_done exn_opt p =
          out_pos := !out_pos + p;
          out_size := !out_size - p;
          if !out_size = 0 then out_pos := 0;
          out_exn := exn_opt;
          hidden_exn := exn_opt;
          if !out_size > 0 && !out_exn = None then update_output();
          if exn_opt <> Some Cancelled then on_output() in
        match out_buf with
          | `Memory mem ->
               mplex # start_mem_writing ~when_done mem !out_pos !out_size
          | `String str ->
               mplex # start_writing ~when_done str !out_pos !out_size
    )
    (* else: never cancel writing, because we don't know then exactly
       which parts of the data reached the socket and which not.
     *)      
  in

  ( object(self)
      method enable_recv b =
        en_recv := b;
        update_input()

      method enable_send b =
        en_send := b;
        update_output()

      method recv mem =
        if !in_size > 0 then (
          let orig_in_size = !in_size in
          let size = Bigarray.Array1.dim mem in
          let n = min size !in_size in
          ( match in_buf with
              | `Memory mem_buf ->
                   Bigarray.Array1.blit
                     (Bigarray.Array1.sub mem_buf !in_pos n)
                     (Bigarray.Array1.sub mem 0 n);
                   in_pos := !in_pos + n;
              | `String str_buf ->
                   Netsys_mem.blit_bytes_to_memory
                     str_buf 0
                     mem 0
                     n;
                   in_pos := !in_pos + n;
          );
          in_size := !in_size - n;
          if !in_size = 0 then in_pos := 0;
          dlogr (fun () ->
  	           sprintf "tls_adapter: recv caller_size=%d avail_size=%d n=%d"
                           size orig_in_size n);
          n
        ) else (
          match !in_exn with
            | None ->
                 dlogr (fun () ->
  	                sprintf "tls_adapter: recv EAGAIN");
                 raise (Unix.Unix_error(Unix.EAGAIN, 
                                        "Uq_multiplex.tls_multiplex_controller",
                                        ""))
            | Some End_of_file ->
                 dlogr (fun () ->
  	                sprintf "tls_adapter: recv End_of_file");
                 0
            | Some exn ->
                 dlogr (fun () ->
  	                sprintf "tls_adapter: recv exn %s"
                                (Netexn.to_string exn));
                 (* The caller of this method is GNUTLS, so we cannot raise
                    arbitrary exceptions here. *)
                 raise (Unix.Unix_error(Unix.EAGAIN, 
                                        "Uq_multiplex.tls_adapter",
                                        ""))
        )

      method hidden_exn =
        if !hidden_exn <> Some Cancelled then
          !hidden_exn
        else
          None

      method send mem len =
        ( match !out_exn with
            | Some exn ->
                 dlogr (fun () ->
  	                sprintf "tls_adapter: send exn %s"
                                (Netexn.to_string exn));
                 (* The caller of this method is GNUTLS, so we cannot raise
                    arbitrary exceptions here. *)
                 raise (Unix.Unix_error(Unix.EAGAIN, 
                                        "Uq_multiplex.tls_adapter",
                                        ""))
            | None ->
               ()
        );
        if !out_size = 0 then (
          out_pos := 0;
          ( match out_buf with
              | `Memory mem_buf ->
                   let n = min len (Bigarray.Array1.dim mem_buf) in
                   Bigarray.Array1.blit
                     (Bigarray.Array1.sub mem 0 n)
                     (Bigarray.Array1.sub mem_buf 0 n);
                   out_size := n
              | `String str_buf ->
                   let n = min len (Bytes.length str_buf) in
                   Netsys_mem.blit_memory_to_bytes
                     mem 0
                     str_buf 0
                     n;
                   out_size := n
          );
          dlogr (fun () ->
  	           sprintf "tls_adapter: send caller_size=%d n=%d"
                           len !out_size);
          !out_size
        )
        else (
          dlogr (fun () ->
  	           sprintf "tls_adapter: send EAGAIN");
          raise (Unix.Unix_error(Unix.EAGAIN, 
                                 "Uq_multiplex.tls_multiplex_controller",
                                 ""))
        )

      method recv_size = !in_size

      method send_size = !out_size

    end
  )


let new_tls_endpoint ?resume ~role ~peer_name config mplex on_input on_output =
  let module Config = (val config : Netsys_crypto_types.TLS_CONFIG) in
  let module P = Config.TLS in
  let adapter = tls_adapter mplex on_input on_output in
  let ep = 
    match resume with
      | None ->
           P.create_endpoint
             ~role ~recv:adapter#recv ~send:adapter#send ~peer_name
             Config.config
      | Some data ->
           if role <> `Client then 
             failwith
               "Uq_multiplex.tls_multiplex_controller: can only resume clients";
           P.resume_client
             ~recv:adapter#recv ~send:adapter#send ~peer_name 
             Config.config data in
  let module Endpoint = struct
    module TLS = P
    let endpoint = ep
  end in
  let ep_mod = (module Endpoint : Netsys_crypto_types.TLS_ENDPOINT) in
  (ep_mod, adapter)


let restore_tls_endpoint exn config mplex on_input on_output =
  let module Config = (val config : Netsys_crypto_types.TLS_CONFIG) in
  let module P = Config.TLS in
  let adapter = tls_adapter mplex on_input on_output in
  let ep = P.restore_endpoint ~recv:adapter#recv ~send:adapter#send exn in
  let module Endpoint = struct
    module TLS = P
    let endpoint = ep
  end in
  let ep_mod = (module Endpoint : Netsys_crypto_types.TLS_ENDPOINT) in
  (ep_mod, adapter)


let notify f_opt =
  match f_opt with
    | Some f -> f()
    | None -> ()


class tls_multiplex_controller get_ep config mplex on_handshake
      : multiplex_controller =
  let on_input = ref (fun () -> ()) in
  let on_output = ref (fun () -> ()) in
  let ep_mod, adapter =
    get_ep
      config mplex
      (fun () -> !on_input())
      (fun () -> !on_output()) in
  let esys = mplex#event_system in
  let g = Unixqueue.new_group esys in
object(self)
  val mutable alive = true
  val mutable read_eof = false
  val mutable wrote_eof = false
  val mutable reading = `None
  val mutable writing = `None
  val mutable writing_eof = None
  val mutable shutting_down = None
  val mutable tls_handshake = None
  val mutable tls_shutdown = None
  val mutable tls_session_props = None
  val mutable tls_session = None
  val mutable fatal_exn = None
  val mutable will_update = false

  val aux_buf_lz = lazy(Netsys_mem.pool_alloc_memory Netsys_mem.default_pool)

  method alive = alive
  method mem_supported = true
  method reading = reading <> `None
  method writing = writing <> `None || writing_eof <> None
  method shutting_down = shutting_down <> None
  method read_eof = read_eof
  method wrote_eof = wrote_eof

  method supports_half_open_connection = true

  initializer
    on_input := self#on_input;
    on_output := self#on_output;
    ignore(self # cont_handshake())


  method tls_session_props =
    match tls_session_props with
      | Some props ->
           Some props
      | None ->
           let module EP = (val ep_mod : Netsys_crypto_types.TLS_ENDPOINT) in
           let ep = EP.endpoint in
           let state = EP.TLS.get_state ep in
           if state = `Start || state = `Handshake then (
             None
           )
           else (
             let props =
               Nettls_support.get_tls_session_props ep_mod in
             tls_session_props <- Some props;
             Some props
           )

  method tls_session =
    match tls_session with
      | Some(id,data) ->
           Some(id,data)
      | None ->
           let module EP = (val ep_mod : Netsys_crypto_types.TLS_ENDPOINT) in
           let ep = EP.endpoint in
           let state = EP.TLS.get_state ep in
           if state = `Start || state = `Handshake then
             None
           else
             let id = EP.TLS.get_session_id ep in
             let data = EP.TLS.get_session_data ep in
             tls_session <- Some (id,data);
             Some(id,data)

  method tls_stashed_endpoint() =
    let module EP = (val ep_mod : Netsys_crypto_types.TLS_ENDPOINT) in
    let ep = EP.endpoint in
    EP.TLS.stash_endpoint ep
           

  method start_reading ?(peek = fun ()->()) ~when_done s pos len =
    if pos < 0 || len < 0 || pos > Bytes.length s - len then
      invalid_arg "#start_reading";
    if reading <> `None then
      failwith "#start_reading: already reading (tls)";
    if shutting_down <> None then
      failwith "#start_reading: already shutting down (tls)";
    if not alive then
      failwith "#start_reading: inactive connection (tls)";
    reading <- `String(when_done, peek, s, pos, len);
    dlogr (fun () ->
	     sprintf
	       "start_reading tls_multiplex_controller mplex=%d"
	       (Oo.id self));
    self # update_reading();


  method start_mem_reading ?(peek = fun ()->()) ~when_done m pos len =
    if pos < 0 || len < 0 || pos > Bigarray.Array1.dim m - len then
      invalid_arg "#start_mem_reading";
    if reading <> `None then
      failwith "#start_mem_reading: already reading (tls)";
    if shutting_down <> None then
      failwith "#start_mem_reading: already shutting down (tls)";
    if not alive then
      failwith "#start_mem_reading: inactive connection (tls)";
    reading <- `Mem(when_done, peek, m, pos, len);
    dlogr (fun () ->
	     sprintf
	       "start_reading tls_multiplex_controller mplex=%d"
	       (Oo.id self));
    self # update_reading();


  method cancel_reading () =
    self # cancel_reading_with Cancelled

  method private cancel_reading_with x =
    match reading with
      | `None ->
	  ()
      | `String(f_when_done, _, _, _, _) ->
	  self # really_cancel_reading();
	  f_when_done (Some x) 0
      | `Mem(f_when_done, _, _, _, _) ->
	  self # really_cancel_reading();
	  f_when_done (Some x) 0

  method private really_cancel_reading() =
    reading <- `None;
    self # update_soon();
    dlogr (fun () ->
	   sprintf
	     "cancel_reading tls_multiplex_controller mplex=%d"
	     (Oo.id self))


  method start_writing ~when_done s pos len =
    if pos < 0 || len < 0 || pos > Bytes.length s - len then
      invalid_arg "#start_writing";
    if writing <> `None || writing_eof <> None then
      failwith "#start_writing: already writing (tls)";
    if shutting_down <> None then
      failwith "#start_writing: already shutting down (tls)";
    if wrote_eof then
      failwith "#start_writing: already past EOF (tls)";
   if not alive then
      failwith "#start_writing: inactive connection (tls)";
    writing <- `String(when_done, s, pos, len);
    dlogr (fun () ->
	     sprintf
	       "start_writing tls_multiplex_controller mplex=%d pos=%d len=%d"
	       (Oo.id self) pos len);
    self # update_writing();

  method start_mem_writing ~when_done m pos len =
    if pos < 0 || len < 0 || pos > Bigarray.Array1.dim m - len then
      invalid_arg "#start_mem_writing";
    if writing <> `None || writing_eof <> None then
      failwith "#start_mem_writing: already writing (tls)";
    if shutting_down <> None then
      failwith "#start_mem_writing: already shutting down (tls)";
    if wrote_eof then
      failwith "#start_mem_writing: already past EOF (tls)";
    if not alive then
      failwith "#start_mem_writing: inactive connection (tls)";
    writing <- `Mem(when_done, m, pos, len);
    dlogr (fun () ->
	     sprintf
	       "start_writing tls_multiplex_controller mplex=%d pos=%d len=%d"
	       (Oo.id self) pos len);
    self # update_writing();

  method start_writing_eof ~when_done () =
    (* From here on we know fd is not a named pipe *)
    if writing <> `None || writing_eof <> None then
      failwith "#start_writing_eof: already writing (tls)";
    if shutting_down <> None then
      failwith "#start_writing_eof: already shutting down (tls)";
    if wrote_eof then
      failwith "#start_writing_eof: already past EOF (tls)";
    if not alive then
      failwith "#start_writing_eof: inactive connection (tls)";
    writing_eof <- Some when_done;
    dlogr (fun () ->
	     sprintf
	       "start_writing_eof tls_multiplex_controller mplex=%d"
	       (Oo.id self));
    self # update_writing();


  method cancel_writing () =
    self # cancel_writing_with Cancelled

  method private cancel_writing_with x =
    match writing, writing_eof with
      | `None, None ->
	  ()
      | (`String(f_when_done, _, _, _) | `Mem(f_when_done, _, _, _)), None ->
	  self # really_cancel_writing();
	  f_when_done (Some x) 0
      | `None, Some f_when_done ->
	  self # really_cancel_writing();
	  f_when_done (Some x)
      | _ ->
	  assert false

  method private really_cancel_writing() =
    writing <- `None;
    writing_eof <- None;
    self # update_soon();
    dlogr (fun () ->
	   sprintf
	     "cancel_writing tls_multiplex_controller mplex=%d"
	     (Oo.id self))


  method start_shutting_down ?linger ~when_done () =
    if reading <> `None || writing <> `None || writing_eof <> None then
      failwith "#start_shutting_down: still reading or writing (tls)";
    if shutting_down <> None then
      failwith "#start_shutting_down: already shutting down (tls)";
    if not alive then
      failwith "#start_shutting_down: inactive connection (tls)";
    shutting_down <- Some when_done;
    tls_shutdown <- Some (if wrote_eof then `R else `W);
    dlogr (fun () ->
	     sprintf
	       "start_shutting_down tls_multiplex_controller mplex=%d"
	       (Oo.id self));
    self # update_writing();

  method cancel_shutting_down () =
    self # cancel_shutting_down_with Cancelled
    
  method private cancel_shutting_down_with x =
    match shutting_down with
      | None ->
	  ()
      | Some f_when_done ->
	  self # really_cancel_shutting_down ();
	  f_when_done (Some x)


  method private really_cancel_shutting_down () =
    shutting_down <- None;
    self # update_soon();
    dlogr (fun () ->
	   sprintf
	     "cancel_shutting_down \
              tls_multiplex_controller mplex=%d"
	     (Oo.id self))


  method private update_reading() =
    (* read conditions have changed. Check whether we can immediately react *)
    if tls_handshake = None && shutting_down = None then
      match self # try_tls_read() with
        | Some noti -> notify (Some noti)
        | None -> self # update_soon()
    else
      self # update_soon() 


  method private update_writing() =
    (* write conditions have changed. Check whether we can immediately react *)
    if tls_handshake = None && shutting_down = None then
      match self # try_tls_write() with
        | Some noti -> notify (Some noti)
        | None -> self # update_soon()
      else
        self # update_soon()

  method private update_soon() =
    if not will_update then (
      will_update <- true;
      Unixqueue.once esys g 0.0
        (fun () -> 
           will_update <- false;
           notify (self # update())
        )
    )

  method private update() =
    (* any conditions have changed. Return the notification callback *)
    dlog "tls_multiplex_controller: update";
    match fatal_exn with
      | Some exn ->
           (* a delayed exception from the handshake *)
           self # cancel_reading_with exn;
           self # cancel_writing_with exn;
           self # cancel_shutting_down_with exn;
           None

      | None ->
           self # config_adapter();

           if tls_handshake <> None then (
             let progress = self # cont_handshake() in
             if progress then 
               self#update()
             else
               None
           )
           else (
             match shutting_down with
               | Some when_done ->
                    self # cont_shutdown when_done
               | None ->
                    ( match self # try_tls_write() with
                        | Some noti -> Some noti
                        | None -> self # try_tls_read()
                    )
           )

  method private config_adapter() =
    let need_rd = 
      (reading <> `None && tls_handshake = None)
      || tls_handshake = Some `R
      || tls_shutdown = Some `R in
    dlogr 
      (fun () ->
         sprintf "tls_multiplex_controller: config_adapter recv=%B" need_rd);
    adapter # enable_recv need_rd;
    adapter # enable_send true


  method private try_tls_write () : (unit -> unit) option =
    let report = ref (fun _ _ -> ()) in
    let notify_data n () =
      !report None n in
    let notify_error exn () =
      !report (Some exn) 0 in
    try
      ( match writing with
          | `String(when_done, s, pos, len) ->
              report := (fun exn_opt n -> writing <- `None;
                                          when_done exn_opt n
                        );
              dlogr 
                (fun () ->
                   sprintf "tls_multiplex_controller: \
                            tls_send(str) pos=%d len=%d" pos len);
              let aux_buf = Lazy.force aux_buf_lz in
              let len' = min len (Bigarray.Array1.dim aux_buf) in
              Netsys_mem.blit_bytes_to_memory s pos aux_buf 0 len';
              let n = Netsys_tls.mem_send ep_mod aux_buf 0 len' in
              dlogr 
                (fun () ->
                 sprintf "tls_multiplex_controller: tls_send got %d" n);
              self # config_adapter();
              Some(notify_data n)
          | `Mem(when_done, mem, pos, len) ->
              report := (fun exn_opt n -> writing <- `None;
                                          when_done exn_opt n
                        );
              dlogr 
                (fun () ->
                   sprintf "tls_multiplex_controller:  \
                            tls_send(mem) pos=%d len=%d" pos len);
              let n = Netsys_tls.mem_send ep_mod mem pos len in
              dlogr 
                (fun () ->
                 sprintf "tls_multiplex_controller: tls_send got %d" n);
              self # config_adapter();
              Some(notify_data n)
          | `None ->
              ( match writing_eof with
                  | Some when_done ->
                      report := (fun exn_opt n -> writing_eof <- None;
                                                  when_done exn_opt
                                );
                      dlog "tls_multiplex_controller: tls_send shutdown";
                      Netsys_tls.shutdown ep_mod Unix.SHUTDOWN_SEND;
                      dlog "tls_multiplex_controller: tls_send shutdown ok";
                      wrote_eof <- true;
                      self # config_adapter();
                      Some(notify_data 0)
                  | None ->
                      None
              )
      )
    with
      | Netsys_types.EAGAIN_RD ->
          (* This means there was a re-handshake *)
          ( match self # check_for_hidden_exn "send" notify_error with
              | None ->
                  dlog "tls_multiplex_controller: tls_send EAGAIN_RD";
                  tls_handshake <- Some `R;
                  self # config_adapter();
                  None
              | noti -> noti
          )
      | Netsys_types.EAGAIN_WR ->
          ( match self # check_for_hidden_exn "send" notify_error with
              | None ->
                  (* There is a pending output operation. Some time in the
                     future, on_output will be called back and we try then again
                   *)
                  dlog "tls_multiplex_controller: tls_send EAGAIN_WR";
                  self # config_adapter();
                  None
              | noti -> noti
          )
      | other ->
          dlogr 
            (fun () ->
               sprintf "tls_multiplex_controller: tls_send exn=%s"
                       (Netexn.to_string other));
          Some(notify_error other)

  method private try_tls_read() : (unit -> unit) option =
    (* try another TLS data read. Return the notification *)
    let report = ref (fun _ _ -> ()) in
    let notify_data n () =
      if n=0 then (
        read_eof <- true;
        !report (Some End_of_file) 0
      )
      else
        !report None n in
    let notify_error exn () =
      !report (Some exn) 0 in
    try
      ( match reading with
          | `String(when_done, peek, s, pos, len) ->
               report := 
                 (fun exn_opt n -> reading <- `None; when_done exn_opt n);
               peek();
               dlogr 
                 (fun () ->
                    sprintf "tls_multiplex_controller: \
                             tls_recv(str) len=%d" len);
               let aux_buf = Lazy.force aux_buf_lz in
               let len' = min len (Bigarray.Array1.dim aux_buf) in
               let n = Netsys_tls.mem_recv ep_mod aux_buf 0 len' in
               Netsys_mem.blit_memory_to_bytes aux_buf 0 s pos n;
               dlogr 
                 (fun () ->
                    sprintf "tls_multiplex_controller: tls_recv got %d" n);
               reading <- `None; 
               self # config_adapter();
               Some (notify_data n)
          | `Mem(when_done, peek, mem, pos, len) ->
               report := 
                 (fun exn_opt n -> reading <- `None; when_done exn_opt n);
               peek();
               dlogr 
                 (fun () ->
                    sprintf "tls_multiplex_controller: \
                             tls_recv(mem) len=%d" len);
               let n = Netsys_tls.mem_recv ep_mod mem pos len in
               dlogr 
                 (fun () ->
                    sprintf "tls_multiplex_controller: tls_recv got %d" n);
               reading <- `None; 
               self # config_adapter();
               Some(notify_data n)
          | `None ->
               None
      )
    with
      | Netsys_types.EAGAIN_RD ->
           ( match self # check_for_hidden_exn "recv" notify_error with
               | None ->
                   dlog "tls_multiplex_controller: tls_recv EAGAIN_RD";
                   self # config_adapter();
                   None
               | noti ->
                   noti
           )
      | Netsys_types.EAGAIN_WR ->
           (* This means there was a re-handshake *)
           ( match self # check_for_hidden_exn "recv" notify_error with
               | None ->
                   dlog "tls_multiplex_controller: tls_recv EAGAIN_WR";
                   tls_handshake <- Some `W;
                   self # config_adapter();
                   None
               | noti ->
                   noti
           )
      | other ->
           dlogr 
             (fun () ->
                sprintf "tls_multiplex_controller: tls_recv exn=%s"
                        (Netexn.to_string other));
           Some(notify_error other)


  method private check_for_hidden_exn_raise() =
    match adapter#hidden_exn with
      | None -> ()
      | Some e -> raise e

  method private check_for_hidden_exn op notify_error =
    (* Check whether we have to restore an exception after EAGAIN *)
    match adapter # hidden_exn with
      | None ->
          (* a real EAGAIN *)
          None
      | Some hidden_exn ->
          dlogr 
            (fun () ->
             sprintf "tls_multiplex_controller: tls_%s hidden exn=%s"
                     op (Netexn.to_string hidden_exn));
          Some(notify_error hidden_exn)
      
  method private on_input() =
    (* this is invoked when new bytes have been received and it is reasonable
       to try another TLS read *)
    notify (self # update())

  method private on_output() =
    (* this is invoked when new bytes have been written and it is reasonable
       to try another TLS write *)
    notify (self # update())

  method private cont_handshake() =
    (* Continues the handshake. Returns whether progress was made *)
    try
      try
        dlog "tls_multiplex_controller: cont_handshake (re)start";
        Netsys_tls.handshake ep_mod;
        self # config_adapter();
        tls_handshake <- None;
        dlog "tls_multiplex_controller: cont_handshake done";
        on_handshake (self :> multiplex_controller);
        true
      with
        | Netsys_types.EAGAIN_RD ->
            (* There is a pending input operation. Some time in the future,
              on_output will be called back, and we try then again
             *)
            self # check_for_hidden_exn_raise();
            tls_handshake <- Some `R;
            self # config_adapter();
            dlog "tls_multiplex_controller: cont_handshake EAGAIN_RD";
            false
        | Netsys_types.EAGAIN_WR ->
            (* There is a pending output operation. Some time in the future,
              on_output will be called back, and we try then again
             *)
            self # check_for_hidden_exn_raise();
            tls_handshake <- Some `W;
            self # config_adapter();
            dlog "tls_multiplex_controller: cont_handshake EAGAIN_WR";
            false
    with
      | other ->
           dlogr 
             (fun () ->
                sprintf "tls_multiplex_controller: cont_handshake exn=%s"
                        (Netexn.to_string other));
           if fatal_exn = None then
             fatal_exn <- Some other;
           true

  method private cont_shutdown when_done =
    try
      try
        dlog "tls_multiplex_controller: cont_shutdown (re)start";
        Netsys_tls.shutdown ep_mod Unix.SHUTDOWN_ALL;
        tls_shutdown <- None;
        read_eof <- true;
        wrote_eof <- true;
        adapter # enable_recv false;
        dlog "tls_multiplex_controller: cont_shutdown done";
        Some(fun () -> shutting_down <- None; when_done None)
      with
        | Netsys_types.EAGAIN_RD ->
            (* There is a pending input operation. Some time in the future,
              on_output will be called back, and we try then again
             *)
            self # check_for_hidden_exn_raise();
            tls_shutdown <- Some `R;
            self # config_adapter();
            dlog "tls_multiplex_controller: cont_shutdown EAGAIN_RD";
            None
        | Netsys_types.EAGAIN_WR ->
            (* There is a pending output operation. Some time in the future,
              on_output will be called back, and we try then again
             *)
            self # check_for_hidden_exn_raise();
            tls_shutdown <- Some `W;
            self # config_adapter();
            dlog "tls_multiplex_controller: cont_shutdown EAGAIN_WR";
            None
    with
      | other ->
           dlogr 
             (fun () ->
                sprintf "tls_multiplex_controller: cont_shutdown exn=%s"
                        (Netexn.to_string other));
           Some(fun () -> shutting_down <- None; when_done (Some other))

  method inactivate() =
    dlog "tls_multiplex_controller: inactivate";
    alive <- false;
    Unixqueue.clear esys g;
    mplex # inactivate()

  method event_system = esys
end


class tls_multiplex_controller_1 ?resume ?(on_handshake=fun _ -> ())
                                 ~role ~peer_name config mplex
      : multiplex_controller =
  let get_ep config mplex on_input on_output =
    new_tls_endpoint
      ?resume ~role ~peer_name config mplex on_input on_output in
  tls_multiplex_controller get_ep config mplex on_handshake


class tls_multiplex_controller_2 ?(on_handshake=fun _ -> ()) exn config mplex
      : multiplex_controller =
  let get_ep config mplex on_input on_output =
    restore_tls_endpoint
      exn config mplex on_input on_output in
  tls_multiplex_controller get_ep config mplex on_handshake


let tls_multiplex_controller ?resume ?on_handshake 
                             ~role ~peer_name config mplex =
  new tls_multiplex_controller_1
      ?resume ?on_handshake ~role ~peer_name config mplex


let restore_tls_multiplex_controller ?on_handshake exn config mplex =
  new tls_multiplex_controller_2 ?on_handshake exn config mplex


(* What needs to be done for DTLS:

   DTLS is different because we need to create a new endpoint per
   peeraddr, as a UDP socket can communicate with many different peers
   at once.

   tls_adapter needs to be changed so that the peeraddr of received
   messages is stored with these messages, and that the peeraddr can be
   set for sent messages. Also, on_input and on_output need to be
   changed so that the peeraddr is also passed.

   tls_multiplex_controller covers only a single endpoint. This is ok,
   but this is not the API the user wants to have. We need another
   layer on top of this, dtls_multiplex_controller. This controller
   creates the tls_adapter, and gets on_input and on_output callbacks.
   Cases:
    - on_input for new peers: create a new internal tls_multiplex_controller,
      and set it up so that the handshake is run
    - on_input for known peers: pass it down to the existing
      tls_multiplex_controller
    - on_output for known peers: pass it down to the existing
      tls_multiplex_controller
    - (is on_output possible for unknown peers?)

   The API provided by dtls_multiplex_controller is the same as for
   datagram_multiplex_controller. Methods like start_reading and
   start_writing are forwarded to the internal tls_multiplex_controller
   provided for the peeraddr. 

   Also:
    - tls_session_props is like received_from, and returns the properties
      of the last received message
    - tls_stashed_endpoint: not supported
    - we need to honour the retransmission timer in tls_multiplex_controller
      (i.e. if a handshake raises EAGAIN, ensure that the handshake is
      continued after this number of seconds)
 *)
