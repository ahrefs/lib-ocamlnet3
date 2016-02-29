(* $Id$ *)

open Netsys_mem

class type mstring =
object
  method length : int
  method blit_to_bytes :  int -> Bytes.t -> int -> int -> unit
  method blit_to_string :  int -> Bytes.t -> int -> int -> unit
  method blit_to_memory : int -> memory -> int -> int -> unit
  method as_bytes : Bytes.t * int
  method as_string : string * int
  method as_memory : memory * int
  method preferred : [ `Memory | `Bytes ]
end

(* This def must be the same as the one in Netsys_types: *)
let _ =
  (fun (ms : mstring ) -> (ms : Netsys_types.mstring))


class type mstring_factory =
object
  method create_from_string : string -> int -> int -> bool -> mstring
  method create_from_bytes : Bytes.t -> int -> int -> bool -> mstring
  method create_from_memory : memory -> int -> int -> bool -> mstring
end

type named_mstring_factories =
    (string, mstring_factory) Hashtbl.t

let bbm s pos len : mstring =
  if len < 0 || pos < 0 || pos > Bytes.length s - len then
    invalid_arg "Netxdr_mstring.bbm";
  ( object(self)
      method length = len
      method blit_to_bytes mpos u upos l =
	if l < 0 then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	if mpos < 0 || mpos > len - l then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	if upos < 0 || upos > Bytes.length u - l then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	Bytes.blit s (pos+mpos) u upos l
      method blit_to_string = self # blit_to_bytes
      method blit_to_memory mpos u upos l =
	if l < 0 then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	if mpos < 0 || mpos > len - l then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	if upos < 0 || upos > Bigarray.Array1.dim u - l then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	Netsys_mem.blit_bytes_to_memory s (pos+mpos) u upos l
      method as_bytes = (s,pos) 
      method as_string = (Bytes.sub_string s pos len,0)
      method as_memory =
	let m = Bigarray.Array1.create Bigarray.char Bigarray.c_layout len in
	Netsys_mem.blit_bytes_to_memory s pos m 0 len;
	(m,0)
      method preferred = `Bytes
    end
  )


let mbm m pos len : mstring =
  if len < 0 || pos < 0 || pos > Bigarray.Array1.dim m - len then
    invalid_arg "Netxdr_mstring.mbm";
  ( object(self)
      method length = len
      method blit_to_bytes mpos u upos l =
	if l < 0 then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	if mpos < 0 || mpos > len - l then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	if upos < 0 || upos > Bytes.length u - l then
	  invalid_arg "Netxdr_mstring#blit_to_bytes";
	Netsys_mem.blit_memory_to_bytes m (pos+mpos) u upos l
      method blit_to_string = self # blit_to_bytes
      method blit_to_memory mpos u upos l =
	if l < 0 then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	if mpos < 0 || mpos > len - l then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	if upos < 0 || upos > Bigarray.Array1.dim u - l then
	  invalid_arg "Netxdr_mstring#blit_to_memory";
	Bigarray.Array1.blit
	  (Bigarray.Array1.sub m (pos+mpos) l)
	  (Bigarray.Array1.sub u upos l)
      method as_bytes =
	let s = Bytes.create len in
	Netsys_mem.blit_memory_to_bytes m pos s 0 len;
	(s,0)
      method as_string =
        let (b,p) = self # as_bytes in
        (Bytes.unsafe_to_string b,p)
      method as_memory = (m,pos)
      method preferred = `Memory
    end
  )


let bytes_based_mstrings : mstring_factory =
  ( object
      method create_from_string s pos len must_copy =
        let b = Bytes.create len in
        Bytes.blit_string s pos b 0 len;
	bbm b 0 len
      method create_from_bytes s pos len must_copy =
        if must_copy then
          bbm (Bytes.sub s pos len) 0 len
        else
          bbm s pos len
      method create_from_memory m pos len must_copy =
	let s = Bytes.create len in
	Netsys_mem.blit_memory_to_bytes m pos s 0 len;
	bbm s 0 len
    end
  )

let string_based_mstrings =
  bytes_based_mstrings


let string_to_mstring ?(pos=0) ?len s =
  let s_len = String.length s in
  let len = match len with Some n -> n | None -> s_len - pos in
  bytes_based_mstrings # create_from_string s pos len false


let bytes_to_mstring ?(pos=0) ?len s =
  let s_len = Bytes.length s in
  let len = match len with Some n -> n | None -> s_len - pos in
  bytes_based_mstrings # create_from_bytes s pos len false
	  

let memory_based_mstrings_1 create : mstring_factory =
  ( object
      method create_from_string s pos len must_copy =
	let m = create len in
	Netsys_mem.blit_string_to_memory s pos m 0 len;
	mbm m 0 len
      method create_from_bytes s pos len must_copy =
	let m = create len in
	Netsys_mem.blit_bytes_to_memory s pos m 0 len;
	mbm m 0 len
      method create_from_memory m pos len must_copy =
	if must_copy then (
	  let m' = create len in
	  Bigarray.Array1.blit
	    (Bigarray.Array1.sub m pos len)
	    (Bigarray.Array1.sub m' 0 len);
	  mbm m' 0 len
	)
	else
	  mbm m pos len
    end
  )

let memory_based_mstrings =
  memory_based_mstrings_1  
    (Bigarray.Array1.create Bigarray.char Bigarray.c_layout)

let memory_to_mstring ?(pos=0) ?len m =
  let m_len = Bigarray.Array1.dim m in
  let len = match len with Some n -> n | None -> m_len - pos in
  memory_based_mstrings # create_from_memory m pos len false
	  

let paligned_memory_based_mstrings =
  memory_based_mstrings_1
    (fun n ->
       Netsys_mem.alloc_memory_pages n
    )

let memory_pool_based_mstrings pool =
  memory_based_mstrings_1
    (fun n ->
       if n <= Netsys_mem.pool_block_size pool then
	 Netsys_mem.pool_alloc_memory pool
       else
	 failwith "memory_pool_based_mstrings: string too large for pool"
    )


let length_mstrings mstrings =
  List.fold_left (fun acc ms -> acc + ms#length) 0 mstrings

let concat_mstrings_bytes (mstrings : mstring list) =
  match mstrings with
    | [] -> Bytes.create 0
    | _ ->
	let length = length_mstrings mstrings in
	let s = Bytes.create length in
	let p = ref 0 in
	List.iter
	  (fun ms ->
	     let l = ms#length in
	     ms # blit_to_bytes 0 s !p l;
	     p := !p + l
	  )
	  mstrings;
	s

let concat_mstrings mstrings =
  Bytes.unsafe_to_string (concat_mstrings_bytes mstrings)


let prefix_mstrings_bytes mstrings n =
  let length = length_mstrings mstrings in
  if n < 0 || n > length then failwith "prefix_mstrings";
  let s = Bytes.create n in
  let p = ref 0 in
  ( try
      List.iter
	(fun ms ->
	   if !p >= n then raise Exit;
	   let l = ms#length in
	   let l' = min l (n - !p) in
	   ms # blit_to_bytes 0 s !p l';
	   p := !p + l'
	)
	mstrings
    with Exit -> ()
  );
  s

let prefix_mstrings mstrings n =
  Bytes.unsafe_to_string (prefix_mstrings_bytes mstrings n)

let blit_mstrings_to_memory mstrings mem =
  let length = length_mstrings mstrings in
  if length > Bigarray.Array1.dim mem then
    failwith "blit_mstrings_to_memory";
  let p = ref 0 in
  List.iter
    (fun ms ->
       let l = ms#length in
       ms # blit_to_memory 0 mem !p l;
       p := !p + l
    )
    mstrings


let shared_sub_mstring (ms : mstring)
                       sub_pos sub_len : mstring =
  (* Returns an mstring that accesses the substring of ms at sub_pos
     with length sub_len. The returned mstring shares the representation
     with ms
   *)
  let ms_len = ms#length in
  if sub_len < 0 || sub_pos < 0 || sub_pos > ms_len - sub_len then
    invalid_arg "Netxdr_mstring.shared_sub_mstring";
  ( object(self)
      method length = sub_len
      method blit_to_bytes mpos s spos len =
        ms#blit_to_bytes (sub_pos+mpos) s spos len
      method blit_to_string = self#blit_to_bytes
      method blit_to_memory mpos mem mempos len =
        ms#blit_to_memory (sub_pos+mpos) mem mempos len
      method as_bytes =
        let (s,pos) = ms#as_bytes in
        (s,pos+sub_pos)
      method as_string =
        let (s,pos) = ms#as_string in
        (s,pos+sub_pos)
      method as_memory =
        let (m,pos) = ms#as_memory in
        (m,pos+sub_pos)
      method preferred =
        ms#preferred
    end
  )

let shared_sub_mstrings l sub_pos sub_len =
  let l_len = length_mstrings l in
  if sub_len < 0 || sub_pos < 0 || sub_pos > l_len - sub_len then
    invalid_arg "Netxdr_mstring.shared_sub_mstrings";
  let sub_pos' = sub_pos + sub_len in
  let rec map l pos =
    match l with
      | ms :: l' ->
	  let len = ms#length in
	  let pos' = pos+len in
	  let cond1 = pos' > sub_pos in
	  let cond2 = pos < sub_pos' in
	  if cond1 && cond2 && len > 0 then (
	    let ms' =
	      if pos < sub_pos then
		let q = min (pos' - sub_pos) sub_len in
		shared_sub_mstring ms (sub_pos - pos) q
	      else
		if pos' > sub_pos' then
		  shared_sub_mstring ms 0 (sub_pos' - pos)
		else
		  ms
	    in
	    ms' :: map l' pos'
	  )
	  else
	    map l' pos'
      | [] -> []
  in
  map l 0


let copy_mstring ms =
  let len = ms#length in
  match ms#preferred with
    | `Bytes ->
	let (s, pos) = ms#as_string in
	string_based_mstrings#create_from_string s pos len true
    | `Memory ->
	let (m, pos) = ms#as_memory in
	memory_based_mstrings#create_from_memory m pos len true


let copy_mstrings l =
  List.map copy_mstring l


let in_channel_of_mstrings ms_list =
  let ms_list = ref ms_list in
  let ms_pos = ref 0 in
  let in_pos = ref 0 in
  ( object(self)
      inherit Netchannels.augment_raw_in_channel

      method input s pos len =
        match !ms_list with
          | [] ->
              raise End_of_file
          | ms :: ms_list' ->
              let ms_len = ms#length in
              if !ms_pos >= ms_len then (
                ms_list := ms_list';
                ms_pos := 0;
                self # input s pos len
              )
              else (
                match ms#preferred with
	          | `Bytes ->
                      let (u,start) = ms#as_string in
                      let n = min len ms_len in
                      String.blit u start s pos n;
                      ms_pos := !ms_pos + n;
                      in_pos := !in_pos + n;
                      n
                  | `Memory ->
                      let (m,start) = ms#as_memory in
                      let n = min len ms_len in
                      Netsys_mem.blit_memory_to_bytes m start s pos n;
                      ms_pos := !ms_pos + n;
                      in_pos := !in_pos + n;
                      n
              )

      method close_in() = ()
      method pos_in = !in_pos
    end
  )


let mstrings_of_in_channel ch =
  let len = 1024 in
  let acc = ref [] in
  let buf = ref (Bytes.create len) in
  let pos = ref 0 in
  let rec loop() : unit =
    let n = ch # input !buf !pos (len - !pos) in (* or End_of_file *)
    pos := !pos + n;
    if !pos < len then 
      loop()
    else (
      acc := bytes_to_mstring !buf :: !acc;
      buf := Bytes.create len;
      pos := 0;
      loop()
    ) in
  try loop(); assert false
  with End_of_file ->
    if !pos > 0 then
      acc := bytes_to_mstring ~pos:0 ~len:!pos !buf :: !acc;
    List.rev !acc
