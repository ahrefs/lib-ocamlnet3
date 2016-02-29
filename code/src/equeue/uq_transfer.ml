(* $Id$ *)

open Uq_engines

class type async_out_channel =
  Uq_engines.async_out_channel

class type async_in_channel =
  Uq_engines.async_in_channel

class type async_out_channel_engine =
  Uq_engines.async_out_channel_engine

class type async_in_channel_engine =
  Uq_engines.async_in_channel_engine

type onshutdown_out_spec =
  Uq_engines.onshutdown_out_spec

type onshutdown_in_spec =
  Uq_engines.onshutdown_in_spec

type copy_task =
  Uq_engines.copy_task


let is_active state =
  match state with
      `Working _ -> true
    | _          -> false
;;



class pseudo_async_in_channel ch : async_in_channel =
object
  method input = ch # input
  method close_in = ch # close_in
  method pos_in = ch # pos_in
  method can_input = true
  method request_notification _ = ()
end


let pseudo_async_in_channel = new pseudo_async_in_channel



class pseudo_async_out_channel ch : async_out_channel =
object
  method output = ch # output
  method close_out = ch # close_out
  method pos_out = ch # pos_out
  method flush = ch # flush
  method can_output = true
  method request_notification _ = ()
end


let pseudo_async_out_channel = new pseudo_async_out_channel


(* TODO: Avoid the usage of Extra events here. Extra events are more
 * expensive than other events because all handlers see them.
 * Can be substituted with Timeout events.
 *)

exception Receiver_attn of Unixqueue.group ;;
let receiver_attn g = Unixqueue.Extra(Receiver_attn g);;

exception Sender_attn of Unixqueue.group ;;
let sender_attn g = Unixqueue.Extra(Sender_attn g);;


let buf_max_size = 4096;;


class receiver ~src ~(dst : #async_out_channel) ?(close_src=true) 
               ?(close_dst=true) ues 
      : [ unit ] engine = 
object(self)
  (* The receiver has to copy data if (1) the src file descriptor is
   * readable, and (2) the dst channel accepts output. There is also
   * an internal buffer that stored read data that cannot yet be 
   * written into the dst channel.
   *
   * We implement the following logic:
   *
   * - The src file descriptor is polled when there is space in the
   *   internal buffer. Every time new data is added to the buffer,
   *   the event Receiver_attn is generated
   * - When the dst state changes, the event Receiver_attn is generated
   * - The event handler catches Receiver_attn, and checks whether
   *   the output channel is ready. If so, data of the internal
   *   buffer is written to the output channel, and a new Receiver_attn
   *   event is generated. If the output channel is not ready, nothing
   *   will happen.
   *)

  inherit [unit] engine_mixin (`Working 0 : unit engine_state) ues

  val group = Unixqueue.new_group ues

  val buf = Bytes.create buf_max_size
  val mutable buf_size = 0

  val mutable in_eof = false
  val mutable in_polling = false

  val mutable out_eof = false

  val mutable deferred_exn = None

  initializer
    (* Arrange that Receiver_attn is generated when the dst state changes: *)
    dst # request_notification
      (fun () ->
	 (* Note: With MT, we do not know which thread calls this function.
	  * Fortunately, add_event is thread-safe.
	  *)
	 if is_active self#state then (
	   Unixqueue.add_event ues (receiver_attn group);
	   true
	     (* Continue notifications *)
	 )
	 else
	   false
	     (* The engine is no longer active: disable any further
	      * notification
	      *)
      );
    (* Define the event handler: *)
    Unixqueue.add_handler ues group (fun _ _ -> self # handle_event);
    (* Define the abort (exception) handler: *)
    Unixqueue.add_abort_action ues group (fun _ -> self # handle_exception);
    (* Because the internal buffer is empty initially, we can poll
     * src: 
     *)
    Unixqueue.add_resource ues group (Unixqueue.Wait_in src, -1.0);
    in_polling <- true   (* Remember add_resource *)


  method abort() =
    match self#state with
	`Working _ ->
	  if not in_eof && close_src then Unix.close src;
	  in_eof <- true;
	  if not out_eof && close_dst then dst # close_out();
	  out_eof <- true;
	  self # set_state `Aborted;
	  Unixqueue.clear ues group
      | _ ->
	  ()


  method event_system = ues


  method private rcv_count() =
    match self#state with
	`Working n -> 
	  self # set_state (`Working (n+1))
      | _ ->
	  ()


  method private handle_event ev =
    match ev with
	Unixqueue.Input_arrived(g,_) when g = group ->
	  self # handle_input();
	  self # check_input_polling();
      | Unixqueue.Extra (Receiver_attn g) when g = group ->
	  self # handle_output();
	  if out_eof then (
	    Unixqueue.clear ues group;    (* Delete the whole group *)
	    raise Equeue.Terminate        (* Deactivate this handler *)
	  )
      | _ ->
	  raise Equeue.Reject


  method private handle_exception exn =
    (* Unixqueue already ensures that the whole group will be deleted,
     * so we need not to do it here
     *)
    if not in_eof && close_src then (
      try Unix.close src
      with error ->
	Netlog.logf `Err
	  "Uq_engines.receiver#handle_exception: %s" 
	  (Netexn.to_string error) );
    in_eof <- true;
    if not out_eof && close_dst then (
      try dst # close_out()
      with error ->
	Netlog.logf `Err
	  "Uq_engines.receiver#handle_exception: %s" 
	  (Netexn.to_string error) );
    out_eof <- true;
    self # set_state (`Error exn)


  method private handle_input() =
    if not in_eof && buf_size < buf_max_size then
      try
	let n = Unix.read src buf buf_size (buf_max_size - buf_size) in
	buf_size <- buf_size + n;
	in_eof <- (n = 0);
	if in_eof && close_src then Unix.close src;
	Unixqueue.add_event ues (receiver_attn group);
	self # rcv_count();
      with
	  Unix.Unix_error(Unix.EAGAIN,_,_)
	| Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
	| Unix.Unix_error(Unix.EINTR,_,_) ->
	    (* These exceptions are expected, and can be ignored *)
	    ()
	| error ->
	    (* Any other exception stops the engine. But first it is tried to
	     * process the buffer contents:
	     *)
	    in_eof <- true;
	    deferred_exn <- Some error;
	    if in_eof && close_src then Unix.close src;
	    Unixqueue.add_event ues (receiver_attn group);
	    self # rcv_count();
	    

  method private check_input_polling() =
    let need_polling = not in_eof && buf_size < buf_max_size in
    ( if need_polling && not in_polling then
	Unixqueue.add_resource ues group (Unixqueue.Wait_in src, -1.0)
      else
	if not need_polling && in_polling then
	  Unixqueue.remove_resource ues group (Unixqueue.Wait_in src);
    );
    in_polling <- need_polling


  method private handle_output() =
    (* If this method is called when out_eof, we assume that this is
     * an event coming too late. Just ignore.
     *)
    if not out_eof then (
      (* First check the state of dst: If [pos_out] raises an exception,
       * we assume that the output channel is broken.
       *)
      ( try ignore(dst#pos_out)
	with
	    _ ->
	      (* dst is in an error state, or somebody has closed it *)
	      raise(Unixqueue.Abort(group,Broken_communication))
      );

      (* It is possible that dst#can_output is false, because we get
       * Reciever_attn events for many conditions, not just that
       * output is again accepted. Ignore this case.
       *)
      try
	if dst#can_output then (
	  if buf_size > 0 then (
	    let n = dst # output buf 0 buf_size in
	    if n > 0 then (
	      Bytes.blit buf n buf 0 (buf_size - n);
	      buf_size <- buf_size - n;
	      if (buf_size > 0 && dst#can_output) || in_eof then
		Unixqueue.add_event ues (receiver_attn group);
	      self # check_input_polling();
	      self # rcv_count();
	    )
	  )
	  else if in_eof then (
	    (* Note: we do not close dst. out_eof just means that copying
	     * is done
	     *)
	    if close_dst then dst # close_out();
	    out_eof <- true;
	    ( match deferred_exn with
		| None -> self # set_state (`Done());
		| Some err -> self # set_state (`Error err);
	    )
	  )
	)
      with
	  error ->
	    (* In most cases coming from dst#output *)
	    raise(Unixqueue.Abort(group,error))
    )

end
;;


class sender ~(src : #async_in_channel) ~dst ?(close_src=true) 
               ?(close_dst=true) ues 
      : [ unit ] engine = 
object(self)
  (* The sender has to copy data if (1) the src channel is
   * readable, and (2) the dst descriptor accepts output. There is also
   * an internal buffer that stored read data that cannot yet be 
   * written into the dst descriptor.
   *
   * We implement the following logic:
   *
   * - The dst file descriptor is polled when there is data in the
   *   internal buffer. Every time new data is added to the buffer,
   *   the event Sender_attn is generated
   * - When the src state changes, the event Sender_attn is generated
   * - The event handler catches Sender_attn, and checks whether
   *   the input channel has data. If so, the data is appended to the internal
   *   buffer, and a new Sender_attn
   *   event is generated.
   *)

  inherit [unit] engine_mixin (`Working 0 : unit engine_state) ues

  val group = Unixqueue.new_group ues

  val buf = Bytes.create buf_max_size
  val mutable buf_size = 0

  val mutable in_eof = false

  val mutable out_eof = false
  val mutable out_polling = false


  initializer
    (* Arrange that Sender_attn is generated when the src state changes: *)
    src # request_notification
      (fun () ->
	 (* Note: With MT, we do not know which thread calls this function.
	  * Fortunately, add_event is thread-safe.
	  *)
	 if is_active self#state then (
	   Unixqueue.add_event ues (sender_attn group);
	   true
	     (* Continue notifications *)
	 )
	 else
	   false
	     (* The engine is no longer active: disable any further
	      * notification
	      *)
      );
    (* Define the event handler: *)
    Unixqueue.add_handler ues group (fun _ _ -> self # handle_event);
    (* Define the abort (exception) handler: *)
    Unixqueue.add_abort_action ues group (fun _ -> self # handle_exception);
    (* Because the internal buffer is empty initially, we cannot poll
     * dst. 
     *)
    out_polling <- false;
    (* Immediately check for input: *)
    Unixqueue.add_event ues (sender_attn group);



  method abort() =
    match self#state with
	`Working _ ->
	  if not in_eof && close_src then src # close_in();
	  in_eof <- true;
	  if not out_eof && close_dst then Unix.close dst;
	  out_eof <- true;
	  self # set_state `Aborted;
	  Unixqueue.clear ues group
      | _ ->
	  ()


  method event_system = ues


  method private snd_count() =
    match self#state with
	`Working n -> 
	  self # set_state (`Working (n+1))
      | _ ->
	  ()


  method private handle_event ev =
    match ev with
	Unixqueue.Extra (Sender_attn g) when g = group ->
	  self # handle_input();
      | Unixqueue.Output_readiness(g,_) when g = group ->
	  self # handle_output();
	  self # check_output_polling();
	  if out_eof then (
	    Unixqueue.clear ues group;    (* Delete the whole group *)
	    raise Equeue.Terminate        (* Deactivate this handler *)
	  )
      | _ ->
	  raise Equeue.Reject


  method private handle_exception exn =
    (* Unixqueue already ensures that the whole group will be deleted,
     * so we need not to do it here
     *)
    if not in_eof && close_src then (
      try src # close_in();
      with error ->
	Netlog.logf `Err
	  "Uq_engines.sender#handle_exception: %s" 
	  (Netexn.to_string error) );
    in_eof <- true;
    if not out_eof && close_dst then (
      try Unix.close dst
      with error ->
	Netlog.logf `Err
	  "Uq_engines.sender#handle_exception: %s" 
	  (Netexn.to_string error) );
    out_eof <- true;
    self # set_state (`Error exn)


  method private handle_output() =
    if not out_eof then
      try
	let n = Unix.single_write dst buf 0 buf_size in
	Bytes.blit buf n buf 0 (buf_size - n);
	buf_size <- buf_size - n;
	if buf_size = 0 && in_eof then (
	  out_eof <- true;
	  if close_dst then Unix.close dst;
	  self # set_state (`Done());
	)
	else (
	  self # snd_count();
	  if n > 0 && not in_eof && src#can_input then
	    Unixqueue.add_event ues (sender_attn group);
	  (* if not src#can_input, we will be notified when input is 
	   * again possible.
	   *)
	)
      with
	  Unix.Unix_error(Unix.EAGAIN,_,_)
	| Unix.Unix_error(Unix.EWOULDBLOCK,_,_)
	| Unix.Unix_error(Unix.EINTR,_,_) ->
	    (* These exceptions are expected, and can be ignored *)
	    ()
	| error ->
	    (* Any other exception stops the engine *)
	    raise(Unixqueue.Abort(group,error))
	    

  method private check_output_polling() =
    let need_polling = not out_eof && (buf_size > 0 || in_eof) in
    ( if need_polling && not out_polling then
	Unixqueue.add_resource ues group (Unixqueue.Wait_out dst, -1.0)
      else
	if not need_polling && out_polling then
	  Unixqueue.remove_resource ues group (Unixqueue.Wait_out dst);
    );
    out_polling <- need_polling


  method private handle_input() =
    (* If this method is called when in_eof, we assume that this is
     * an event coming too late. Just ignore.
     *)
    if not in_eof then (
      (* First check the state of src: If [pos_in] raises an exception,
       * we assume that the input channel is broken.
       *)
      ( try ignore(src#pos_in)
	with
	    _ ->
	      (* src is in an error state, or somebody has closed it *)
	      raise(Unixqueue.Abort(group,Broken_communication))
      );

      (* It is possible that src#can_input is false, because we get
       * Sender_attn events for many conditions, not just that
       * input data is again available. Ignore this case.
       *)
      try
	if src#can_input then (
	  let l = Bytes.length buf in
	  if buf_size < l then (
	    try
	      let n = src # input buf buf_size (l-buf_size) in
	      if n > 0 then (
		buf_size <- buf_size + n;
		(* Check for more input data immediately: *)
		if buf_size < l then
		  Unixqueue.add_event ues (sender_attn group);
		self # check_output_polling();
		self # snd_count();
	      )
	    with
		End_of_file ->
		  (* We do see EOF for the first time! *)
		  if close_src then src # close_in();
		  in_eof <- true;
		  self # check_output_polling();
		  self # snd_count();
	  )
	)
      with
	  error ->
	    (* In most cases coming from src#input *)
	    raise(Unixqueue.Abort(group,error))
    )

end
;;


type onclose_spec = [ `Ignore | `Write_eof ]

class output_async_mplex ?(onclose = (`Ignore : onclose_spec) )
                         ?(onshutdown = (`Ignore : onshutdown_out_spec) )
                         ?buffer_size
                         (mplex : multiplex_controller)
                         : async_out_channel_engine =
object (self)

  inherit [unit] engine_mixin (`Working 0 : unit engine_state) mplex#event_system

  val data_queue = Queue.create()
		     (* The queue of strings to output *)

  val mutable data_top_pos = 0
		     (* How many bytes of the first string of data_queue
		      * have already been copied to buf.
		      *)

  val mutable data_queue_length = 0
		     (* The sum of all strings in data_queue, not counting
		      * data_top_pos
		      *)

  val buf = Bytes.create buf_max_size
	      (* The output buffer. The strings from data_queue are
	       * appended to this buffer to reduce the number of
	       * Unix.write syscalls
	       *)

  val mutable buf_size = 0
	     (* The number of bytes used at the beginning of [buf]. *)

  val mutable pos_out = 0
	     (* The position of the channel *)

  (* Note that the object buffers the strings in data_queue plus the
   * string in buf, and buffer_size is the limit for 
   * data_queue_length + buf_size
   *)

  val mutable in_eof = false
  val mutable shutdown_done = false

  method output s p l =
    if p < 0 || l < 0 || p > Bytes.length s || p+l > Bytes.length s then
      invalid_arg "Uq.engines.output_async_mplex#output";

    if in_eof then raise Closed_channel;

    let l' =
      match buffer_size with
	  None ->
	    (* Unrestricted buffers *)
	    if l > 0 then Queue.add (Bytes.sub s p l) data_queue;
	    l
	| Some max_size ->
	    let size = data_queue_length + buf_size in
	    let n = min l (max_size - size) in
	    if n > 0 then Queue.add (Bytes.sub s p n) data_queue;
	    n
    in

    pos_out <- pos_out + l';
    data_queue_length <- data_queue_length + l';
    assert(data_queue_length >= 0);  (* must never overflow *)

    if not mplex#writing && l' > 0 then 
      self # check_for_output();

    if l' > 0 then self # oam_count();
    (* If l' = 0, there was no space in the buffer. No need for notification *)

    l'


  method close_out () =
    if not in_eof then (
      in_eof <- true;
      if not mplex#writing then
	self # check_for_output();
    )


  method pos_out =
    if in_eof then raise Closed_channel;
    pos_out


  method flush () = 
    if in_eof then raise Closed_channel;
    ()


  method abort() =
    match self#state with
	`Working _ ->
	  mplex # cancel_writing();
	  self # shutdown `Aborted;
      | _ ->
	  ()

  method event_system = mplex # event_system

  method private oam_count() =
    match self#state with
	`Working n -> 
	  self # set_state (`Working (n+1))
      | _ ->
	  ()

  method can_output =
    not in_eof &&
    match buffer_size with
	None ->
	  (* Unrestricted buffers *)
	  true
      | Some max_size ->
	  let size = data_queue_length + buf_size in
	  size < max_size


  method private handle_exception exn =
    mplex # cancel_writing();
    self # shutdown (`Error exn)


  method private check_for_output() =
    assert(not mplex#writing);
    if not mplex#wrote_eof then (
      (* Refill buf: *)
      while buf_size < buf_max_size && not (Queue.is_empty data_queue) do
	let s0 = Queue.top data_queue in
	let m = Bytes.length s0 - data_top_pos in
	let space = buf_max_size - buf_size in
	let n = min space m in
	Bytes.blit s0 data_top_pos buf buf_size n;
	buf_size <- buf_size + n;
	data_top_pos <- data_top_pos + n;
	data_queue_length <- data_queue_length - n;
	if data_top_pos >= Bytes.length s0 then (
	  ignore(Queue.take data_queue);
	  data_top_pos <- 0
	);
	assert(data_queue_length >= 0);  (* must never overflow *)
	assert(data_top_pos >= 0);       (* must never overflow *)
      done;
      (* Have something to write? *)
      if buf_size > 0 then (
	let cur_buf_size = buf_size in
	mplex # start_writing 
	  ~when_done:(fun exn_opt n ->
			match exn_opt with
			  | None ->
			      assert(buf_size = cur_buf_size);
			      Bytes.blit buf n buf 0 (buf_size - n);
			      buf_size <- buf_size - n;
			      self # check_for_output();
			      if n > 0 then self # oam_count();
			      (* Note: this also implies notification because
                               * [can_output] returns true
			       *)
			  | Some Cancelled ->
			      (* Called from [abort], so ignore any data *)
			      ()
			  | Some error ->
			      self # handle_exception error
		     )
	  buf 0 cur_buf_size;
      )
      else
	if in_eof then (
	  match onclose with
	    | `Write_eof ->
		mplex # start_writing_eof
		  ~when_done:(fun exn_opt ->
				match exn_opt with
				  | None ->
				      self # shutdown (`Done());
				  | Some Cancelled ->
				      ()
				  | Some error ->
				      self # handle_exception error
			     )
		  ()
	    | `Ignore ->
		self # shutdown (`Done());
	)
    )

  method private shutdown next_state =
    (* See also input_async_mplex # shutdown *)
    if not shutdown_done then (
      shutdown_done <- true;
      in_eof <- true;
      Queue.clear data_queue;
      data_queue_length <- 0;
      data_top_pos <- 0;
      ( match onshutdown with
	  | `Ignore -> ()
	  | `Initiate_shutdown ->
	      mplex # start_shutting_down ~when_done:(fun _ -> ()) ()
		(* CHECK: What to do if shutdown not possible? E.g. because
                 * there is also a reader?
                 *)
	  | `Action f ->
	      ( try
		  f
		    (self : #async_out_channel_engine :> async_out_channel_engine)
		    mplex
		    next_state
		with error ->
		  (* CHECK: We could map that also to state Error *)
		  Netlog.logf `Err
		    "Uq_engines.output_async_mplex#shutdown: %s" 
		    (Netexn.to_string error)
	      )
      );
      self # set_state next_state
    )

end
;;


class input_async_mplex ?(onshutdown = (`Ignore : onshutdown_in_spec) )
                        ?buffer_size
                        (mplex : multiplex_controller)
                        : async_in_channel_engine =
object (self)

  inherit [unit] engine_mixin (`Working 0 : unit engine_state) mplex#event_system

  val data_queue = Queue.create()
		     (* The queue of the read strings *)

  val mutable data_top_pos = 0
		     (* How many bytes of the first string of data_queue
		      * have already been copied to the reading user.
		      *)

  val mutable data_queue_length = 0
		     (* The sum of all strings in data_queue, not counting
		      * data_top_pos
		      *)

  val buf = Bytes.create buf_max_size
	      (* The input buffer *)

  val mutable pos_in = 0

  val mutable in_eof = false
  val mutable shutdown_done = false

  initializer
    self # check_for_input()


  method input s p l =
    if p < 0 || l < 0 || p > Bytes.length s || p > Bytes.length s - l then
      invalid_arg "Uq.engines.input_async_mplex#input";

    if in_eof then raise Closed_channel;

    let l' = min l data_queue_length in
    let l_todo = ref l' in
    let s_pos = ref p in

    while !l_todo > 0 do
      let u = try Queue.peek data_queue with Queue.Empty -> assert false in
      let n = min !l_todo (Bytes.length u - data_top_pos) in
      Bytes.blit u data_top_pos s !s_pos n;
      s_pos := !s_pos + n;
      data_top_pos <- data_top_pos + n;
      l_todo := !l_todo - n;
      if data_top_pos = Bytes.length u then (
	let _ = Queue.take data_queue in
	data_top_pos <- 0
      )
    done;

    pos_in <- pos_in + l';
    data_queue_length <- data_queue_length - l';
    assert(data_queue_length >= 0);  (* must never overflow *)

    if not mplex#reading then 
      self # check_for_input();

    if l' > 0 then self # iam_count();
    (* If l' = 0, there were no data in the buffer. No need for notification *)

    if l' = 0 && mplex # read_eof then
      raise End_of_file
    else
      l'


  method close_in () =
    if not in_eof then (
      mplex # cancel_reading();
      self # shutdown (`Done())
    )


  method pos_in =
    if in_eof then raise Closed_channel;
    pos_in


  method abort() =
    match self#state with
	`Working _ ->
	  mplex # cancel_reading();
	  self # shutdown `Aborted;
      | _ ->
	  ()

  method event_system = mplex # event_system

  method private iam_count() =
    match self#state with
	`Working n -> 
	  self # set_state (`Working (n+1))
      | _ ->
	  ()

  method can_input =
    not in_eof && (data_queue_length > 0 || mplex#read_eof)


  method private handle_exception exn =
    mplex # cancel_reading();
    self # shutdown (`Error exn)


  method private check_for_input() =
    assert(not mplex#reading);
    if not mplex#read_eof then (
      (* Space to read something? *)
      let space =
	match buffer_size with
	  | None -> Bytes.length buf
	  | Some m -> min (Bytes.length buf) (m - data_queue_length) in
      if space > 0 then (
	mplex # start_reading 
	  ~when_done:(fun exn_opt n ->
			match exn_opt with
			  | None ->
			      if n > 0 then (
				let s = Bytes.sub buf 0 n in
				Queue.add s data_queue;
				data_queue_length <- data_queue_length + n;
				assert(data_queue_length >= 0);
				      (* must never overflow *)
			      );
			      self # check_for_input();
			      if n > 0 then self # iam_count()
			  | Some End_of_file ->
			      self # iam_count()
			  | Some Cancelled ->
			      (* Called from [abort], so ignore any data *)
			      ()
			  | Some error ->
			      self # handle_exception error
		     )
	  buf 0 space
      )
    )

  method private shutdown next_state =
    (* See also output_async_mplex # shutdown *)
    if not shutdown_done then (
      shutdown_done <- true;
      in_eof <- true;
      Queue.clear data_queue;
      data_top_pos <- 0;
      data_queue_length <- 0;
      ( match onshutdown with
	  | `Ignore -> ()
	  | `Initiate_shutdown ->
	      mplex # start_shutting_down ~when_done:(fun _ -> ()) ()
	  | `Action f ->
	      ( try
		  f
		    (self : #async_in_channel_engine :> async_in_channel_engine)
		    mplex
		    next_state
		with error ->
		  Netlog.logf `Err
		    "Uq_engines.input_async_mplex#shutdown: %s" 
		    (Netexn.to_string error)
	      )
      );
      self # set_state next_state
    )

end
;;




class output_async_descr ~dst ?buffer_size ?(close_dst=true) esys =
  (* Map to output_async_mplex. Be careful not to depend on socket
   * functionaliy (esp. shutdown).
   *)
  let mplex = 
    Uq_multiplex.create_multiplex_controller_for_connected_socket dst esys in
  let shutdown ach mplex _ =
    if close_dst then Unix.close dst
  in
  output_async_mplex 
    ~onclose:`Ignore
    ~onshutdown:(`Action shutdown)
    ?buffer_size
    mplex
;;


class input_async_descr ~src ?buffer_size ?(close_src=true) esys =
  (* Map to input_async_mplex. Be careful not to depend on socket
   * functionaliy (esp. shutdown).
   *)
  let mplex = 
    Uq_multiplex.create_multiplex_controller_for_connected_socket src esys in
  let shutdown ach mplex _ =
    if close_src then Unix.close src
  in
  input_async_mplex 
    ~onshutdown:(`Action shutdown)
    ?buffer_size
    mplex
;;


class copier (copy_task : copy_task) ues : [unit] engine =
object(self)
  val mutable engines = []
  val mutable last_eng_states = []
  val mutable last_count = 0

  initializer
    ( match copy_task with
	  `Unidirectional(fd1, fd2) ->
	    self # init_unidirectional fd1 fd2

	| `Uni_socket(fd1, fd2) ->
	    self # init_uni_socket fd1 fd2

	| `Bidirectional(fd1, fd2) ->
	    self # init_tridirectional true fd1 fd2 fd2
	    
	| `Tridirectional(fd1, fd2, fd3) ->
	    self # init_tridirectional false fd1 fd2 fd3
(*
	| _ ->
	    assert false
 *)
    );
    last_eng_states <- List.map (fun eng -> eng # state) engines;


  method private init_unidirectional fd1 fd2 =
    (* This is quite simple. fd2_ch is an output channel
     * writing data to fd2. fd1_rcv is a receiver transferring
     * data from fd1 to fd2_ch. If fd1_rcv is at EOF, it will
     * close fd1, and close fd2_ch. fd2_ch closes fd2 after
     * it has written all buffered data.
     *)
    let fd2_ch = new output_async_descr 
		   ~dst:fd2 
		   ~buffer_size:buf_max_size
		   ues in
    let fd1_rcv = new receiver
		    ~src:fd1 
		    ~dst:(fd2_ch :> async_out_channel)
		    ues in
    engines <- [ fd1_rcv;
		 (fd2_ch :> unit engine);
	       ]


  method private init_uni_socket fd1 fd2 =
    (* Here, we have to modify the EOF behaviour. First,
     * fd1_rcv must not close src. Of course, it must
     * close the output channel fd2_ch, otherwise the
     * channel would not know that it is at the end of 
     * the data stream. However, fd2_ch must not close
     * dst; instead we catch the EOF situation, and
     * shutdown the socket.
     *)
    let fd2_ch = new output_async_descr 
		   ~dst:fd2 
		   ~close_dst:false
		   ~buffer_size:buf_max_size
		   ues in
    let fd1_rcv = new receiver
		    ~src:fd1 
		    ~close_src:false
		    ~dst:(fd2_ch :> async_out_channel)
		    ues in
    when_state ~is_done:(fun () -> 
			   Unix.shutdown fd2 Unix.SHUTDOWN_SEND)
               fd2_ch;
    engines <- [ fd1_rcv;
		 (fd2_ch :> unit engine);
	       ]


  method private init_tridirectional bi_case fd1 fd2 fd3 =
    (* Basically, we have two `Uni_socket copiers where one copier
     * transfers data into the reverse direction as the other
     * copier. Additionally, we have to close the descriptors
     * when work is done, either successfully or with error.
     *)
    (* bi_case: fd2 = fd3 is assumed, and fd2 must be a socket
     *)

    (* Copy fd1 to fd2: *)
    let fd2_ch = new output_async_descr 
		   ~dst:fd2 
		   ~close_dst:false
		   ~buffer_size:buf_max_size
		   ues in
    let fd1_rcv = new receiver
		    ~src:fd1 
		    ~close_src:false
		    ~dst:(fd2_ch :> async_out_channel)
		    ues in
    
    (* Copy fd3 to fd1: *)
    let fd1_ch = new output_async_descr 
		   ~dst:fd1 
		   ~close_dst:false
		   ~buffer_size:buf_max_size
		   ues in
    let fd3_rcv = new receiver
		    ~src:fd3
		    ~close_src:false
		    ~dst:(fd1_ch :> async_out_channel)
		    ues in
	    
    (* Check state: *)
    let fd1_eof = ref false in  (* whether output to fd1 @ eof *)
    let fd1_closed = ref false in
    let fd2_eof = ref false in  (* whether output to fd2 @ eof *)
    let fd2_closed = ref false in
    let fd3_closed = ref false in
    let full_close _ =
      if not !fd1_closed then
	Unix.close fd1;
      fd1_eof := true;
      fd1_closed := true;

      if not !fd2_closed then (
	Unix.close fd2;
	if bi_case then fd3_closed := true;
      );
      fd2_eof := true;
      fd2_closed := true;

      if not !fd3_closed then 
	Unix.close fd3;
      fd3_closed := true;
    in
    let half_close_fd1() =
      if !fd2_eof then (
	full_close()
      ) else (
        if not !fd1_eof then
	  Unix.shutdown fd1 Unix.SHUTDOWN_SEND;
	fd1_eof := true
      ) in
    let half_close_fd2() =
      if !fd1_eof then (
	full_close()
      ) else (
        if not !fd2_eof then (
	  if bi_case then
	    Unix.shutdown fd2 Unix.SHUTDOWN_SEND
	  else (
	    Unix.close fd2;
	    fd2_closed := true;
	  )
	);
	fd2_eof := true
      ) in

    when_state ~is_done:half_close_fd2
               ~is_error:full_close
               ~is_aborted:full_close
               (fd2_ch :> 'a engine);
    when_state ~is_done:half_close_fd1
	       ~is_error:full_close
	       ~is_aborted:full_close
	       fd1_ch;

    engines <- [ fd1_rcv;
		 (fd2_ch :> unit engine);
		 fd3_rcv;
		 (fd1_ch :> unit engine);
	       ]


  method state =
    (* We inspect the states of all engines. If there is an engine
     * in error state, this state will be returned (Broken_communication
     * has lower priority than other errors). Otherwise: If there is
     * an aborted engine, we return that the copier is aborted.
     * Otherwise: If there is at least one working engine, we return
     * working state. The last case is that all engines are done, and
     * we return done.
     *
     * Note that the progress meter for `Working is emulated, and
     * the more often [state] is invoked, the more frequent the progress
     * meter is increased. But it is only increased if at least one
     * engine has made some progress.
     *
     * CHECK: This seems to be a generalization of the sync_engine above.
     * Maybe we want it as basic engine construct?
     *)

    let eng_states =
      List.map (fun eng -> eng # state) engines in

    let our_state = ref(`Done()) in

    List.iter
      (fun st ->
	 match st with
	     `Done _ -> ()
	   | `Working _ ->
	       ( match !our_state with
		     `Done _ -> our_state := `Working 0
		   | _       -> ()
	       )
	   | `Aborted ->
	       ( match !our_state with
		     `Done _ 
		   | `Working _ -> our_state := `Aborted
		   | _          -> ()
	       )
	   | `Error err ->
	       ( match !our_state with
		     `Done _
		   | `Working _ 
		   | `Aborted
		   | `Error Broken_communication ->
		       our_state := st
		   | `Error _ ->
		       ()
	       )
		       
      )
      eng_states;

    ( match !our_state with
	  `Working _ ->
	    if eng_states <> last_eng_states then 
	      last_count <- last_count + 1;
	    our_state := `Working last_count
	| _ ->
	    ()
    );
    last_eng_states <- eng_states;

    !our_state

  method abort () =
    (* Simply abort all engines *)
    List.iter
      (fun eng -> eng # abort())
      engines
      (* CHECK: Hopefully, no engine goes to an error state because the
       * other engine aborts...
       *)

  method request_notification f =
    (* Simply forward the request to all engines *)

    let enabled = ref true in
    (* After the first notification has disabled further notifications, 
     * it must be ensured that no more notifications will happen.
     * [enabled] is [true] as long as notifications are enabled.
     *)

    let f'() = 
      !enabled && 
      ( let enabled' = f() in
	enabled := !enabled && enabled';
	!enabled
      )
    in

    List.iter
      (fun eng -> eng # request_notification f')
      engines

  method request_proxy_notification _ =
    (* not implemented *)
    ()

  method event_system =  ues

end
;;


