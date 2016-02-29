(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Rpc
open Rpc_packer
open Printf


type 't result =
    [ `Ok of 't
    | `Error of exn
    ]

type 't result_eof =
    [ 't result
    | `End_of_file
    ]


type sockaddr =
    [ `Implied
    | `Sockaddr of Unix.sockaddr
    ]

let string_of_sockaddr =
  function
    | `Implied -> "<implied>"
    | `Sockaddr sa -> Netsys.string_of_sockaddr sa

exception Error of string

type in_rule =
    [ `Deny
    | `Drop
    | `Reject
    | `Reject_with of Rpc.server_error
    | `Accept
    ]

type in_record =
    [ `Deny
    | `Drop
    | `Reject of packed_value
    | `Reject_with of packed_value * Rpc.server_error
    | `Accept of packed_value
    ]

let string_of_in_rule =
  function
    | `Deny -> "Deny"
    | `Drop -> "Drop"
    | `Reject -> "Reject"
    | `Reject_with _ -> "Reject_with"
    | `Accept -> "Accept"


class type rpc_multiplex_controller =
object
  method alive : bool
  method event_system : Unixqueue.event_system
  method tls_session_props : Nettls_support.tls_session_props option
  method getsockname : sockaddr
  method getpeername : sockaddr
  method peer_user_name : string option
  method protocol : protocol
  method file_descr : Unix.file_descr option
  method reading : bool
  method read_eof : bool
  method start_reading : 
    ?peek: (unit -> unit) ->
    ?before_record:( int -> sockaddr -> in_rule ) ->
    when_done:( (in_record * sockaddr) result_eof -> unit) -> unit -> unit
  method cancel_rd_polling : unit -> unit
  method abort_rw : unit -> unit
  method writing : bool
  method start_writing :
    when_done:(unit result -> unit) -> packed_value -> sockaddr -> unit
  method start_shutting_down :
    when_done:(unit result -> unit) -> unit -> unit
  method cancel_shutting_down : unit -> unit
  method set_timeout : notify:(unit -> unit) -> float -> unit
  method inactivate : unit -> unit
end

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Rpc_transport" Debug.enable
let dlogf fmt = ksprintf dlog fmt
let dlogr = Netlog.Debug.mk_dlogr "Rpc_transport" Debug.enable

let () =
  Netlog.Debug.register_module "Rpc_transport" Debug.enable


let mem_size = Netsys_mem.pool_block_size Netsys_mem.default_pool
  (* for allocated bigarrays *)

let fallback_size = 16384   (* for I/O via Unix *)

let mem_alloc() =
  Netsys_mem.pool_alloc_memory Netsys_mem.default_pool

let mem_alloc2() =
  Netsys_mem.pool_alloc_memory2 Netsys_mem.default_pool


let mem_dummy() =
  Bigarray.Array1.create
    Bigarray.char Bigarray.c_layout 0
  

let get_user_name tls_props name =
  match name with
    | Some n -> name
    | None ->
         match tls_props with
           | Some p ->
                ( try Some(Nettls_support.get_tls_user_name p)
                  with Not_found -> None
                )
           | None -> None


class datagram_rpc_multiplex_controller
        role dbg_name
        sockname peername_opt peername_dns_opt peer_user_name_opt file_descr_opt
        (mplex : Uq_engines.datagram_multiplex_controller) esys
      : rpc_multiplex_controller =
(*
  let mplex =
    match tls_config_opt with
      | None -> 
           (mplex0 :> Uq_multiplex.multiplex_controller)
      | Some tls_config ->
           Uq_multiplex.tls_multiplex_controller
             ~role ~peer_name:peername_dns_opt tls_config
             (mplex0 :> Uq_multiplex.multiplex_controller) in
 *)
  let rd_buffer, free_rd_buffer = 
    if mplex#mem_supported then (
      let (m, f) = mem_alloc2() in
      let r = ref(`Mem m) in
      let free () = f(); r := `None in
      (r, free)
    )
    else (
      let r = ref(`Bytes(Bytes.create fallback_size)) in
      (r, (fun () -> ()))
    ) in
    (* Max. size of an Internet datagram is 64 K. See RFC 760. However,
     * the Unix library uses a buffer size of only 16 K. Longer messages
     * can neither be received nor sent without truncation.
     *)

  let wr_buffer, free_wr_buffer =
    if mplex#mem_supported then
      let (m, f) = mem_alloc2() in
      let r = ref(`Mem m) in
      let free() = f(); r := `None in
      (r, free)
    else
      (ref `None, (fun () -> ())) in

object(self)

  method alive = mplex # alive
  method event_system = esys
  method getsockname = sockname
  method getpeername = 
    match peername_opt with
      | None -> failwith "#getpeername: not connected"
      | Some a -> a
  method tls_session_props = mplex#tls_session_props
  method protocol = Udp
  method peer_user_name =
    get_user_name mplex#tls_session_props peer_user_name_opt
  method file_descr = file_descr_opt
  method reading = mplex # reading
  method read_eof = mplex # read_eof
  method writing = mplex # writing

  val mutable aborted = false


  method private rd_buffer_contents n =  (* first n bytes *)
    match !rd_buffer with
      | `Bytes s ->
	  Bytes.sub s 0 n
      | `Mem m ->
	  let s = Bytes.create n in
	  Netsys_mem.blit_memory_to_bytes m 0 s 0 n;
	  s
      | `None ->
	  failwith "Rpc_transport: read/write not possible"


  method start_reading ?peek 
                       ?(before_record = fun _ _ -> `Accept)
                       ~when_done () =
    let mplex_when_done exn_opt n =
      self # timer_event `Stop `R;
      match exn_opt with
	| None ->
	    let peer = `Sockaddr (mplex # received_from) in
	    (* TODO: Catch Failure here, and map to `Implied *)

	    let in_rule = before_record n peer in 
	    (* might have called abort_rw, hence we have to test this: *)
	    if not aborted then (
	      let r =
		match in_rule with
		  | `Deny -> `Deny
		  | `Drop -> `Drop
		  | `Reject -> 
		      let pv = 
			packed_value_of_bytes (self # rd_buffer_contents n) in
		      `Reject pv
		  | `Reject_with (code : Rpc.server_error) -> 
		      let pv = 
			packed_value_of_bytes (self # rd_buffer_contents n) in
		      `Reject_with(pv,code)
		  | `Accept -> 
		      let pv = 
			packed_value_of_bytes (self # rd_buffer_contents n) in
		      `Accept pv in
 	      when_done (`Ok(r, peer))
	    )
	| Some End_of_file ->
	    assert false
	| Some Uq_engines.Cancelled ->  (* abort case *)
	    ()   (* Ignore *)
	| Some error ->
	    when_done (`Error error)
    in
    ( match !rd_buffer with
	| `Bytes s ->
	    mplex # start_reading ?peek ~when_done:mplex_when_done 
	      s 0 (Bytes.length s)
	| `Mem m ->
	    mplex # start_mem_reading ?peek ~when_done:mplex_when_done 
	      m 0 (Bigarray.Array1.dim m)
	      (* saves us 1 string copy! *)
	| `None ->
	    failwith "Rpc_transport: read/write not possible"
    );
    self # timer_event `Start `R


  method start_writing ~when_done pv addr =
    ( match addr with
	| `Implied ->
	    failwith "Rpc_transport.datagram_rpc_multiplex_controller: \
                      Cannot send datagram to implied address"
	| `Sockaddr a ->
	    mplex # send_to a
    );
    let mplex_when_done slen exn_opt n =
      self # timer_event `Stop `W;
      match exn_opt with
	| None ->
	    if n = slen then
	      when_done (`Ok ())
	    else
	      when_done (`Error (Error "Datagram too large"))
	| Some Uq_engines.Cancelled ->
	    ()  (* ignore *)
	| Some error ->
	    when_done (`Error error) in

    let mstrings = mstrings_of_packed_value pv in
    let len = Netxdr_mstring.length_mstrings mstrings in

    if len > fallback_size && len <= mem_size && mplex#mem_supported then (
      let m =
	match !wr_buffer with
	  | `Mem m -> m
	  | `None -> failwith "Rpc_transport: read/write not possible" in
      Netxdr_mstring.blit_mstrings_to_memory mstrings m;
      mplex # start_mem_writing
	~when_done:(mplex_when_done len) m 0 len
    )
    else
      let s = Netxdr_mstring.concat_mstrings_bytes mstrings in
      mplex # start_writing
	~when_done:(mplex_when_done len) s 0 len;
    self # timer_event `Start `W
    (* start_mem_writing is only reasonable for dealing with messages larger
       than 16K that are not supported by [Unix.send].
     *)

  method cancel_rd_polling () =
    if mplex#reading then
      mplex # cancel_reading()

  method abort_rw () =
    aborted <- true;
    mplex # cancel_reading();
    mplex # cancel_writing();
    free_rd_buffer();
    free_wr_buffer()
    
  method start_shutting_down ~when_done () =
    free_rd_buffer();
    free_wr_buffer();
    mplex # start_shutting_down
      ~when_done:(fun exn_opt ->
		    self # timer_event `Stop `D;
		    match exn_opt with
		      | None -> when_done (`Ok ())
		      | Some error -> when_done (`Error error)
		 )
      ();
    self # timer_event `Start `D

  method cancel_shutting_down () =
    self # timer_event `Stop `D;
    mplex # cancel_shutting_down()

  method inactivate () =
    free_rd_buffer();
    free_wr_buffer();
    self # stop_timer();
    mplex # inactivate()

  val mutable timer = None
  val mutable timer_r = `Stop
  val mutable timer_w = `Stop
  val mutable timer_d = `Stop
  val mutable timer_group = None

  method set_timeout ~notify tmo =
    timer <- Some(notify, tmo)

  method private timer_event start_stop which =
    ( match timer with
	| None -> ()
	| Some(notify, tmo) ->
	    ( match which with
		| `R -> timer_r <- start_stop
		| `W -> timer_w <- start_stop
		| `D -> timer_d <- start_stop
	    );
	    self # stop_timer();
	    if timer_r = `Start || timer_w = `Start || timer_d = `Start then (
	      let g = Unixqueue.new_group esys in
	      timer_group <- Some g;
	      Unixqueue.once esys g tmo
		(fun () -> 
		   timer_group <- None;
		   notify()
		)
	    );
    )


  method private stop_timer() =
    ( match timer_group with
	| None -> ()
	| Some g -> Unixqueue.clear esys g
    );
    timer_group <- None;
    timer_r <- `Stop;
    timer_w <- `Stop;
    timer_d <- `Stop


end



let datagram_rpc_multiplex_controller ?(dbg_name = ref "")
                                      ?(close_inactive_descr=true)
                                      ?(preclose=fun() -> ()) 
                                      ~role fd esys =
  let sockname, peername_opt = 
    match Netsys.get_fd_style fd with
      | `Recv_send(sockaddr,peeraddr) ->
	  (`Sockaddr sockaddr, Some(`Sockaddr peeraddr))
      | `Recvfrom_sendto ->
	  (* Usually there is a sockname: *)
	  let sockname =
	    try `Sockaddr(Unix.getsockname fd)
	    with _ -> `Implied in
	  (sockname, None)
      | _ ->
	  (`Implied, Some `Implied) in
(*
  let peername_dns_opt, tls_config_opt =
    match tls with
      | Some(tls_config, peername_dns_opt) -> (peername_dns_opt,Some tls_config)
      | None -> (None, None) in
 *)
  let mplex = 
    Uq_multiplex.create_multiplex_controller_for_datagram_socket
      ~close_inactive_descr ~preclose
      fd esys in
  new datagram_rpc_multiplex_controller 
    role dbg_name sockname peername_opt None None (Some fd) mplex 
    esys
;;


class stream_rpc_multiplex_controller 
        role dbg_name
        sockname peername peername_dns_opt peer_user_name_opt file_descr_opt
        (mplex0 : Uq_engines.multiplex_controller) esys
        tls_config_opt
      : rpc_multiplex_controller =
  let () = 
    dlogr (fun () ->
	     sprintf "new stream_rpc_multiplex_controller mplex=%d"
	       (Oo.id mplex0))
  in

  let mplex =
    match tls_config_opt with
      | None -> mplex0
      | Some tls_config ->
           Uq_multiplex.tls_multiplex_controller
             ~role ~peer_name:peername_dns_opt tls_config mplex0 in

(*
  let wr_buffer, free_wr_buffer =
    if mplex#mem_supported then
      let (m, f) = mem_alloc2() in
      let r = ref(`Mem m) in
      let free() = f(); r := `None in
      (r, free)
    else
      (ref `None, (fun () -> ())) in
 *)


object(self)
  val mutable rd_buffer = Netpagebuffer.create mem_size
  val mutable rd_buffer_nomem = 
    if mplex#mem_supported then Bytes.create 0 else Bytes.create fallback_size

  val mutable rm_buffer = Bytes.create 4
  val mutable rm_buffer_len = 0

  val mutable rd_mode = `RM
  val mutable rd_pos = 0      (* start of record marker or payload section *)

  val mutable rd_queue = Queue.create()
  val mutable rd_queue_len = 0

  val mutable rd_processing = false

  method alive = mplex # alive
  method event_system = esys
  method getsockname = sockname
  method getpeername = peername
  method tls_session_props = mplex#tls_session_props
  method protocol = Tcp
  method peer_user_name =
    get_user_name mplex#tls_session_props peer_user_name_opt
  method file_descr = file_descr_opt
  method reading = mplex # reading
  method read_eof = mplex # read_eof
  method writing = mplex # writing

  val mutable aborted = false

  method start_reading ?peek
                       ?(before_record = fun _ _ -> `Accept) 
                       ~when_done () =
    assert(not mplex#reading);

    let rec est_reading (in_rule:in_rule) =
      let mplex_when_done exn_opt n =
	self # timer_event `Stop `R;
	match exn_opt with
	  | None ->
	      process in_rule
	  | Some End_of_file ->
	      if rd_mode = `RM && Queue.is_empty rd_queue then
		return_eof()   (* EOF between messages *)
	      else
		return_error (Error "EOF within message")
	  | Some Uq_engines.Cancelled ->
	      ()   (* Ignore *)
	  | Some error ->
	      return_error error 
      in
      
      rd_processing <- false;
      if mplex#mem_supported then (
	let (b, start, len) = Netpagebuffer.page_for_additions rd_buffer in
	mplex # start_mem_reading 
	  ?peek 
	  ~when_done:(fun exn_opt n ->
			dlogr (fun () ->
				 sprintf "Reading [mem]: %s%s"
				   (Rpc_util.hex_dump_m b start (min n 200))
				   (if n > 200 then "..." else "")
			      );
			Netpagebuffer.advance rd_buffer n;
			mplex_when_done exn_opt n
		     )
	  b
	  start
	  len
      )
      else (
	mplex # start_reading
	  ?peek
	  ~when_done:(fun exn_opt n ->
			dlogr (fun () ->
				 sprintf "Reading [str]: %s%s"
				   (Rpc_util.hex_dump_b
				      rd_buffer_nomem 0 (min n 200))
				   (if n > 200 then "..." else "")
			      );
			Netpagebuffer.add_subbytes
			  rd_buffer rd_buffer_nomem 0 n;
			mplex_when_done exn_opt n
		     )
	  rd_buffer_nomem
	  0
	  (Bytes.length rd_buffer_nomem)
      );
      self # timer_event `Start `R

    and process (in_rule:in_rule) =
      let len = Netpagebuffer.length rd_buffer - rd_pos in
(* eprintf "rd_pos=%d len=%d in_rule=%s\n%!" rd_pos len (string_of_in_rule in_rule); *)
      if len > 0 then (
	match rd_mode with
	  | `RM ->
(* prerr_endline "RM"; *)
	      (* Read the record marker *)
	      let m = min (4 - rm_buffer_len) len in
	      Netpagebuffer.blit_to_bytes
		rd_buffer rd_pos rm_buffer rm_buffer_len m;
	      rm_buffer_len <- rm_buffer_len + m;
	      if rm_buffer_len = 4 then (
		rd_pos <- rd_pos + 4;
		rm_buffer_len <- 0;
                let rm_00 = Char.code (Bytes.get rm_buffer 0) in
		let rm_last = rm_00 >= 128 in
		let rm_0 = (Char.chr (rm_00 land 0x7f)) in
		let rm_opt =
		  try
		    let rm =
		      Netnumber.int_of_uint4
			(Netnumber.mk_uint4 
			   (rm_0,
                            Bytes.get rm_buffer 1,
                            Bytes.get rm_buffer 2,
                            Bytes.get rm_buffer 3)) in
		    if rm > Sys.max_string_length then
		      raise(Netnumber.Cannot_represent "");
		    if rd_queue_len > Sys.max_string_length - rm then
		      raise(Netnumber.Cannot_represent "");
		    Some(rm,rm_last)
		  with
		    | Netnumber.Cannot_represent _ -> None in
		( match rm_opt with
		    | Some(rm,rm_last) ->
(*eprintf "got RM n=%d last=%b\n%!" rm rm_last; *)
			let in_rule' =
			  match in_rule with
			    | `Accept ->
				before_record (rd_queue_len + rm) peername
			    | _ ->
				in_rule in
			if in_rule' = `Drop || in_rule' = `Deny then (
			  Netpagebuffer.delete_hd rd_buffer rd_pos;
			  rd_pos <- 0;
			);
			rd_mode <- `Payload(rm,rm_last);
			process in_rule'
		    | None ->
			return_error (Error "Record too large")
		)
	      )
	      else
		est_reading in_rule
		
	  | `Payload(plen,is_last) ->
	      (* Read payload data *)
(* prerr_endline "payload"; *)
	      if len >= plen then (
(* eprintf "got fragment rd_pos=%d plen=%d\n%!" rd_pos plen; *)
		let fragment = (rd_pos, plen) in
		Queue.push fragment rd_queue;
		rd_queue_len <- rd_queue_len + plen;
		rd_pos <- rd_pos + plen;
		rd_mode <- `RM;
		if in_rule = `Drop || in_rule = `Deny then (
		  Netpagebuffer.delete_hd rd_buffer rd_pos;
		  rd_mode <- `Payload(plen-rd_pos,is_last);
		  rd_pos <- 0;
		);
		if is_last then (
		  let r =
		    match in_rule with
		      | (`Accept | `Reject | (`Reject_with _) as ar) ->
(* eprintf "creating string n=%d\n%!" rd_queue_len; *)
			  let msg = Bytes.create rd_queue_len in
			  let q = ref 0 in
			  Queue.iter
			    (fun (p,l) ->
			       Netpagebuffer.blit_to_bytes
				 rd_buffer
				 p
				 msg
				 !q
				 l;
			       q := !q + l
			    )
			    rd_queue;
			  let pv = packed_value_of_bytes msg in
			  ( match ar with
			      | `Accept -> `Accept pv
			      | `Reject -> `Reject pv
			      | `Reject_with (code:Rpc.server_error) -> 
				  `Reject_with(pv,code)
			  ) 
		      | (`Deny | `Drop as dd) ->
			  dd 
		  in
		  Queue.clear rd_queue;
		  rd_queue_len <- 0;
		  Netpagebuffer.delete_hd rd_buffer rd_pos;
		  rd_pos <- 0;
		  rd_processing <- true;
                    (* so [process] will be called again - maybe there is
		       another message
		     *)
		  return_msg r
		) else 
		  process in_rule
	      )
	      else
		est_reading in_rule
      )
      else
	est_reading in_rule

    and return_msg msg =
      if not aborted then
	when_done (`Ok(msg, peername))

    and return_error e =
      rd_processing <- false;
      if not aborted then
	when_done (`Error e)

    and return_eof () =
      rd_processing <- false;
      if not aborted then
	when_done `End_of_file 

    in

    (* It can happen that we already began to read the next message in
       the previous call. So check whether there is already a message
       (or a beginning) in the buffer.

       At this point we always start with a new message, so in_rule=`Accept.
     *)
    if rd_processing then
      process `Accept
    else
      est_reading `Accept
	    

  method start_writing ~when_done pv addr =

    assert(not mplex#writing);

    (* - `Bytes(s,p,l): We have still to write s[p] to s[p+l-1]
       - `Memory(m,p,l): We have still to write
          m[p] to m[p+l-1]
     *)

    (* Do our own buffer concatenation (instead of enabling the Nagle algo).
       If there are multiple strings to write, we avoid here to write
       small strings (smaller than a typical MSS). Instead, the strings
       are buffered up, and a single write is done.

       For some systems, we could also use TCP_CORK - however, this option
       is not available in the Unix module.
     *)

    let mss = 2000 in  (* assumed MSS *)
    let acc_limit = 65536 in (* avoid very large buffers *)

    let rec items_of_mstrings acc iacc iacc_len mstrings =
      let next_round() =
	let item = create_item (List.rev iacc) iacc_len in
        items_of_mstrings (item::acc) [] 0 mstrings in
      match mstrings with
	| ms :: mstrings' ->
	    let l = ms#length in
	    if (l < mss || iacc_len < mss) && 
	      (iacc_len=0 || iacc_len+l < acc_limit) 
	    then
	      items_of_mstrings 
		acc (ms :: iacc) (iacc_len + ms#length) mstrings'
	    else
	      next_round()
	| [] ->
	    if iacc_len > 0 then
	      next_round()
	    else
	      List.rev acc

    and create_item acc acc_len =
      if mplex#mem_supported then
	create_item_mem acc acc_len
      else
	create_item_string acc acc_len

    and create_item_mem acc acc_len =
      match acc with
	| [ms] ->
	    let (m,pos) = ms#as_memory in
	    `Memory(m, pos, acc_len)
	| _ ->
	    let m_all = 
	      Bigarray.Array1.create Bigarray.char Bigarray.c_layout acc_len in
	    let k = ref 0 in
	    List.iter
	      (fun ms ->
		 let l = ms#length in
		 ms#blit_to_memory 0 m_all !k l;
		 k := !k + l
	      )
	      acc;
	    assert(!k = acc_len);
	    `Memory(m_all, 0, acc_len)

    and create_item_string acc acc_len =
      match acc with
	| [ms] ->
	    let (s,pos) = ms#as_bytes in
	    `Bytes(s, pos, acc_len)
	| _ ->
	    let s_all = Bytes.create acc_len in
	    let k = ref 0 in
	    List.iter
	      (fun ms ->
		 let l = ms#length in
		 ms#blit_to_bytes 0 s_all !k l;
		 k := !k + l
	      )
	      acc;
	    assert(!k = acc_len);
	    `Bytes(s_all, 0, acc_len)
    in

    let item_is_empty =
      function
	| `Bytes(_,_,l) -> l=0
	| `Memory(_,_,l) -> l=0 in

    let rec est_writing item items =
      (* [item] is the current buffer to write followed by items
       *)
      let mplex_when_done exn_opt n = (* n bytes written *)
	self # timer_event `Stop `W;
	match exn_opt with
	  | None ->
	      ( match item with
		  | `Memory(m,p,l) ->
		      let l' = l-n in
		      if l' > 0 then
			est_writing (`Memory(m,p+n,l')) items
		      else
			est_writing_next items
		  | `Bytes(s,p,l) ->
		      let l' = l-n in
		      if l' > 0 then
			est_writing (`Bytes(s,p+n,l')) items
		      else 
			est_writing_next items
	      )
	  | Some Uq_engines.Cancelled ->
	      ()  (* ignore *)
	  | Some error ->
	      if not aborted then
		when_done (`Error error)
      in

      ( match item with
	  | `Memory(m,p,l) ->
	      dlogr (fun () ->
		       sprintf "Writing [mem]: %s%s" 
			 (Rpc_util.hex_dump_m m p (min l 200))
			 (if l > 200 then "..." else "")
		    );
	      mplex # start_mem_writing
		~when_done:mplex_when_done m p l
	  | `Bytes(s,p,l) ->
	      dlogr (fun () ->
		       sprintf "Writing [str]: %s%s" 
			 (Rpc_util.hex_dump_b s p (min l 200))
			 (if l > 200 then "..." else "")
		    );
	      mplex # start_writing
		~when_done:mplex_when_done s p l
      );
      self # timer_event `Start `W

    and  est_writing_next items =
      match items with
	| item :: items' ->
	    if item_is_empty item then
	      est_writing_next items'
	    else
	      est_writing item items'
	| [] ->
	    if not aborted then
	      when_done (`Ok ())
    in

    ( match addr with
	| `Implied -> ()
	| `Sockaddr a ->
	    if addr <> peername then
	      failwith "Rpc_transport.stream_rpc_multiplex_controller: \
                        cannot send to this address"
    );
    let mstrings0 = mstrings_of_packed_value pv in
    let payload_len = Netxdr_mstring.length_mstrings mstrings0 in
    (* Prepend record marker *)
    let s = Bytes.create 4 in
    let rm = Netnumber.uint4_of_int payload_len in
    Netnumber.BE.write_uint4 s 0 rm;
    Bytes.set s 0 (Char.chr (Char.code (Bytes.get s 0) lor 0x80));
    let ms = 
      Netxdr_mstring.bytes_based_mstrings # create_from_bytes
	s 0 4 false in
    let mstrings = ms :: mstrings0 in
    let items = items_of_mstrings [] [] 0 mstrings in
    est_writing_next items


  method cancel_rd_polling () =
    if mplex#reading then
      mplex # cancel_reading()

  method abort_rw () =
    aborted <- true;
    mplex # cancel_reading();
    mplex # cancel_writing();
    Netpagebuffer.clear rd_buffer;
    
  method start_shutting_down ~when_done () =
    dlogr (fun () ->
	     sprintf "start_shutting_down mplex=%d"
	       (Oo.id mplex));
    Netpagebuffer.clear rd_buffer;
    mplex # start_shutting_down
      ~when_done:(fun exn_opt ->
		    dlogr (fun () ->
			     sprintf "done shutting_down mplex=%d"
			       (Oo.id mplex));
		    self # timer_event `Stop `D;
		    match exn_opt with
		      | None -> when_done (`Ok ())
		      | Some error -> when_done (`Error error)
		 )
      ();
    self # timer_event `Start `D

  method cancel_shutting_down () =
    self # timer_event `Stop `D;
    mplex # cancel_shutting_down()

  method inactivate () =
    dlogr (fun () ->
	     sprintf "inactivate mplex=%d"
	       (Oo.id mplex));
    Netpagebuffer.clear rd_buffer;
    self # stop_timer();
    mplex # inactivate()

  val mutable timer = None
  val mutable timer_r = `Stop
  val mutable timer_w = `Stop
  val mutable timer_d = `Stop
  val mutable timer_group = None

  method set_timeout ~notify tmo =
    timer <- Some(notify, tmo)

  method private timer_event start_stop which =
    ( match timer with
	| None -> ()
	| Some(notify, tmo) ->
	    ( match which with
		| `R -> timer_r <- start_stop
		| `W -> timer_w <- start_stop
		| `D -> timer_d <- start_stop
	    );
	    self # stop_timer();
	    if timer_r = `Start || timer_w = `Start || timer_d = `Start then (
	      let g = Unixqueue.new_group esys in
	      timer_group <- Some g;
	      Unixqueue.once esys g tmo
		(fun () -> 
		   timer_group <- None;
		   notify()
		)
	    );
    )


  method private stop_timer() =
    ( match timer_group with
	| None -> ()
	| Some g -> Unixqueue.clear esys g
    );
    timer_group <- None;
    timer_r <- `Stop;
    timer_w <- `Stop;
    timer_d <- `Stop

end



let stream_rpc_multiplex_controller ?(dbg_name = ref "")
                                    ?(close_inactive_descr=true)
                                    ?(preclose=fun()->()) 
                                    ?tls
                                    ~role fd esys =
  let sockname = 
    try
      `Sockaddr(Unix.getsockname fd) 
    with
      | Unix.Unix_error(_,_,_) -> `Implied in
  let peername = 
    try
      `Sockaddr(Netsys.getpeername fd)
    with
      | Unix.Unix_error(_,_,_) -> `Implied in
  let peername_dns_opt, tls_config_opt =
    match tls with
      | Some(tls_config, peername_dns_opt) -> (peername_dns_opt,Some tls_config)
      | None -> (None, None) in
  let mplex = 
    Uq_multiplex.create_multiplex_controller_for_connected_socket
      ~close_inactive_descr ~preclose
      fd esys in
  new stream_rpc_multiplex_controller 
    role dbg_name sockname peername peername_dns_opt None (Some fd) mplex esys 
    tls_config_opt
;;


type internal_pipe =
  Netxdr.xdr_value Netsys_polypipe.polypipe

let internal_rpc_multiplex_controller
        ?(dbg_name = ref "")
        ?(close_inactive_descr=false)
        ?(preclose=fun() -> ())
        rd_pipe wr_pipe esys
      : rpc_multiplex_controller =
  let sockaddr = `Implied in
object(self)
  val mutable alive = true
  val mutable rd_engine = None
  val mutable rd_eof = false

  val mutable wr_engine = None

  val mutable timeout = (-1.0)
  val mutable tmo_notify = (fun () -> ())

  method alive = alive
  method event_system = esys
  method getsockname = sockaddr
  method getpeername = `Implied
  method tls_session_props = None
  method protocol = Tcp
  method peer_user_name = None
  method file_descr = None
  method reading = rd_engine <> None
  method read_eof = rd_eof
  method writing = wr_engine <> None

  method private notify_on_timeout e =
    Uq_engines.when_state
      ~is_error:(fun err ->
                   if err = Uq_engines.Timeout then (
                     dlogf "notify_on_timeout dbgname=%s" !dbg_name;
                     tmo_notify()
                   )
                )
      e

  method start_reading ?(peek = fun () -> ())
                       ?(before_record = fun _ _ -> `Accept)
                       ~when_done () =
    if rd_engine <> None then
      failwith "start_reading: already reading";
    dlogf "start_reading: entry dbgname=%s" !dbg_name;
    let attempt() =
      rd_engine <- None;
      try
        peek();
        let n = Netsys_polypipe.length rd_pipe in
        dlogf "start_reading dbgname=%s length=%d" !dbg_name n;
        match Netsys_polypipe.read ~nonblock:true rd_pipe with
          | Some msg ->
              let code = before_record 0 sockaddr in
              let rmsg =
                match code with
                  | `Deny -> `Deny
                  | `Drop -> `Drop
                  | `Reject_with err ->
                      `Reject_with(Rpc_packer.pseudo_value_of_xdr msg, err)
                  | `Reject -> 
                      `Reject (Rpc_packer.pseudo_value_of_xdr msg)
                  | `Accept -> 
                      `Accept (Rpc_packer.pseudo_value_of_xdr msg) in
              dlog "start_reading: done (regular case)";
              Some (`Ok(rmsg, sockaddr))
          | None ->
              rd_eof <- true;
              dlog "start_reading: done (eof case)";
              Some `End_of_file
      with
        | Unix.Unix_error(Unix.EAGAIN,_,_) ->
            None
        | Unix.Unix_error(Unix.EINTR,_,_) ->
            None
        | error ->
            dlog "start_reading: done (error case)";
            Some (`Error error) in
    let rec wait() =
      let e1 = new Uq_engines.signal_engine esys in
      let tid = (!Netsys_oothr.provider)#self#id in
      Netsys_polypipe.set_read_notify
        rd_pipe
        (fun () ->
           dlogf "start_reading: Signalling thread %d dbgname=%s"
                 tid !dbg_name;
           Netsys_polypipe.set_read_notify rd_pipe (fun () -> ());
           e1 # signal (`Done())
        );
      let e1 = (e1 :> _ Uq_engines.engine) in
      Uq_engines.when_state
        ~is_done:(fun _ -> 
                    dlogf "start_reading: repeat dbgname=%s" !dbg_name;
                    wait()
                 )
        ~is_aborted:(fun _ ->
                       dlogf "aborted dbgname=%s" !dbg_name
                    )
        e1;
      rd_engine <- Some e1;
      let res_opt = attempt() in
      match res_opt with
        | Some res ->
            dlogf "start_reading: done dbgname=%s" !dbg_name;
            Netsys_polypipe.set_read_notify rd_pipe (fun () -> ());
            e1 # abort();
            rd_engine <- None;
            when_done res
        | None ->
            let e2 = Uq_engines.timeout_engine timeout Uq_engines.Timeout e1 in
            rd_engine <- Some e2;
            self # notify_on_timeout e2;
            dlogf "start_reading: waiting dbgname=%s" !dbg_name in
    wait()

  method start_writing ~when_done pv addr =
    ( match addr with
	| `Implied -> ()
	| `Sockaddr a ->
	    failwith "Rpc_transport.internal_rpc_multiplex_controller: \
                      Cannot send message to explicit address"
    );
    if wr_engine <> None then
      failwith "start_writing: already writing";
    dlogf "start_writing: entry dbgname=%s" !dbg_name;
    let m = Rpc_packer.xdr_of_pseudo_value pv in
    let attempt() =
      wr_engine <- None;
      try
        let n = Netsys_polypipe.length wr_pipe in
        dlogf "start_writing length=%d dbgname=%s" n !dbg_name;
        Netsys_polypipe.write ~nonblock:true wr_pipe (Some m);
        dlog "start_writing: done (regular case)";
        Some (`Ok())
      with
        | Unix.Unix_error(Unix.EAGAIN,_,_) ->
            None
        | Unix.Unix_error(Unix.EINTR,_,_) ->
            None
        | error ->
            dlog "start_writing: done (error case)";
            Some (`Error error) in
    let rec wait() =
      let e1 = new Uq_engines.signal_engine esys in
      let tid = (!Netsys_oothr.provider)#self#id in
      Netsys_polypipe.set_write_notify
        wr_pipe
        (fun () ->
           dlogf "start_writing: Signalling thread %d dbgname=%s" tid !dbg_name;
           Netsys_polypipe.set_write_notify wr_pipe (fun () -> ());
           e1 # signal (`Done())
        );
      let e1 = (e1 :> _ Uq_engines.engine) in
      Uq_engines.when_state
        ~is_done:(fun _ -> 
                    dlogf "start_writing: repeat dbgname=%s" !dbg_name;
                    wait()
                 )
        e1;
      wr_engine <- Some e1;
      let res_opt = attempt() in
      match res_opt with
        | Some res ->
            dlogf "start_writing: done dbgname=%s" !dbg_name;
            Netsys_polypipe.set_write_notify wr_pipe (fun () -> ());
            e1 # abort();
            wr_engine <- None;
            when_done res
        | None ->
            let e2 = Uq_engines.timeout_engine timeout Uq_engines.Timeout e1 in
            wr_engine <- Some e2;
            self # notify_on_timeout e2;
            dlogf "start_writing: waiting dbgname=%s" !dbg_name in
    wait()

  method start_shutting_down ~when_done () =
    if wr_engine <> None then
      failwith "start_shutting_down: already writing";
    dlogf "start_shutting_down: entry dbgname=%s" !dbg_name;
    let attempt() =
      wr_engine <- None;
      try
        let n = Netsys_polypipe.length wr_pipe in
        dlogf "start_shutting_down: length=%d dbgname=%s" n !dbg_name;
        Netsys_polypipe.write ~nonblock:true wr_pipe None;
        dlog "start_shutting_down: done (regular case)";
        Some (`Ok())
      with
        | Unix.Unix_error(Unix.EAGAIN,_,_) ->
            None
        | Unix.Unix_error(Unix.EINTR,_,_) ->
            None
        | Netsys_polypipe.Closed ->
            dlog "start_shutting_down: done (already closed)";
            Some (`Ok())
        | error ->
            dlog "start_shutting_down: done (error case)";
            Some (`Error error) in
    let rec wait() =
      let e1 = new Uq_engines.signal_engine esys in
      let tid = (!Netsys_oothr.provider)#self#id in
      Netsys_polypipe.set_write_notify
        wr_pipe
        (fun () ->
           dlogf "start_shutting_down: Signalling thread %d dbgname=%s"
                 tid !dbg_name;
           Netsys_polypipe.set_write_notify wr_pipe (fun () -> ());
           e1 # signal (`Done())
        );
      let e1 = (e1 :> _ Uq_engines.engine) in
      Uq_engines.when_state
        ~is_done:(fun _ ->
                    dlogf "start_writing: repeat dbgname=%s" !dbg_name;
                    wait()
                 )
        e1;
      wr_engine <- Some e1;
      let res_opt = attempt() in
      match res_opt with
        | Some res ->
            dlogf "start_shutting_down: done dbgname=%s" !dbg_name;
            Netsys_polypipe.set_write_notify wr_pipe (fun () -> ());
            e1 # abort();
            wr_engine <- None;
            when_done res
        | None ->
            let e2 = Uq_engines.timeout_engine timeout Uq_engines.Timeout e1 in
            wr_engine <- Some e2;
            self # notify_on_timeout e2;
            dlogf "start_shutting_down: waiting dbgname=%s" !dbg_name in
    wait()

  method cancel_rd_polling () =
    dlog "cancel_rd_polling";
    match rd_engine with
      | None -> ()
      | Some e ->
          rd_engine <- None;
          e#abort()

  method private cancel_wr_polling () =
    dlogf "cancel_wr_polling dbgname=%s" !dbg_name;
    match wr_engine with
      | None -> ()
      | Some e ->
          wr_engine <- None;
          e#abort()

  method cancel_shutting_down =
    self#cancel_wr_polling

  method abort_rw () =
    self # cancel_rd_polling();
    self # cancel_wr_polling();

  method inactivate () =
    dlogf "inactivate dbgname=%s" !dbg_name;
    alive <- false;
    self#abort_rw();
    if close_inactive_descr then (
      preclose()
    )

  method set_timeout ~notify tmo =
    timeout <- tmo;
    tmo_notify <- notify
end
