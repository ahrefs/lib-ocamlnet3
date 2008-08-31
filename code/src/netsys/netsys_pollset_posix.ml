(* $Id$ *)

open Netsys_pollset


let poll_based_pollset minsize : pollset =
  let () =
    if minsize < 1 then invalid_arg "Netsys_pollset.poll_based_pollset";
    () in
object(self)
  val mutable pa = Netsys_posix.create_poll_array minsize
  val mutable free = []
  val mutable ht = Hashtbl.create minsize

  initializer (
    for k = 0 to minsize - 1 do
      free <- k :: free
    done
  )

  method find fd =
    let k = Hashtbl.find ht fd in
    let c = Netsys_posix.get_poll_cell pa k in
    assert(c.Netsys_posix.poll_fd = fd);
    c.Netsys_posix.poll_req_events

  method add fd ev =
    try
      let k = Hashtbl.find ht fd in    (* or Not_found *)
      let c = Netsys_posix.get_poll_cell pa k in
      assert(c.Netsys_posix.poll_fd = fd);
      c.Netsys_posix.poll_req_events <- ev;
      Netsys_posix.set_poll_cell pa k c
    with
	Not_found ->
	  let k =
	    match free with
	      | k :: free' ->
		  free <- free';
		  k
	      | [] ->
		  let l = Netsys_posix.poll_array_length pa in
		  let pa' = Netsys_posix.create_poll_array (2*l) in
		  Netsys_posix.blit_poll_array pa 0 pa' 0 l;
		  pa <- pa';
		  for j = l+1 to 2*l-1 do
		    free <- j :: free
		  done;
		  l
	  in
	  Netsys_posix.set_poll_cell pa k
	    { Netsys_posix.poll_fd = fd;
	      poll_req_events = ev;
	      poll_act_events = Netsys_posix.poll_null_events()
	    };
	  Hashtbl.replace ht fd k

  method remove fd =
    try
      let k = Hashtbl.find ht fd in
      Netsys_posix.set_poll_cell pa k
	{ Netsys_posix.poll_fd = Unix.stdin;
	  poll_req_events = Netsys_posix.poll_req_events false false false;
	  poll_act_events = Netsys_posix.poll_null_events()
	};
      free <- k :: free;
      Hashtbl.remove ht fd;
      let l = Netsys_posix.poll_array_length pa in
      if l > minsize && 2 * (Hashtbl.length ht) < l then
	self # rebuild_array()
    with
	Not_found -> ()


  method private rebuild_array() =
    let n = Hashtbl.length ht in
    let l = max n minsize in
    let pa' = Netsys_posix.create_poll_array l in
    let ht' = Hashtbl.create l in
    let j = ref 0 in
    Hashtbl.iter
      (fun fd k ->
	 let c = Netsys_posix.get_poll_cell pa k in
	 Netsys_posix.set_poll_cell pa' !j c;
	 Hashtbl.replace ht' fd !j;
	 incr j
      )
      ht;
    pa <- pa';
    ht <- ht';
    free <- [];
    for k = n to l-1 do
      free <- k :: free
    done


  method wait tmo =
    let l = Netsys_posix.poll_array_length pa in
    let n = ref(Netsys_posix.poll pa l tmo) in
    let r = ref [] in
    let k = ref 0 in
    while !n > 0 && !k < l do
      let c = Netsys_posix.get_poll_cell pa !k in
      if Netsys_posix.poll_result c.Netsys_posix.poll_act_events then (
	let fd = c.Netsys_posix.poll_fd in
	let c_used =
	  try Hashtbl.find ht fd = !k with Not_found -> false in
	if c_used then
	  r := (fd, 
		c.Netsys_posix.poll_req_events, 
		c.Netsys_posix.poll_act_events) :: !r;
	decr n
      );
      incr k
    done;
    !r
    

  method dispose() = ()


  method cancel_wait _ = assert false (* TODO *)
    

end
