(* $Id$ *)

open Printf

type verbosity =
    [ `Name_only | `Name_abbrev_args | `Name_full_args ]

module StrMap = Map.Make(String)

(* The map functions are like those in Netxdr, but the type is a
   xdr_type_term, not an xdr_type
 *)

let rec get_enum t =
  match t with
    | Netxdr.X_enum enum -> enum
    | Netxdr.X_direct(t1,_,_,_,_) -> get_enum t1
    | _ -> failwith "Rpc_util.get_enum"

let fail_map_xv_enum_fast () =
  failwith "Rpc_util.map_xv_enum_fast"

let rec map_xv_enum_fast t v =
  match t with
    | Netxdr.X_enum l ->
	let l = Array.of_list l in
	let m = Array.length l in
	( match v with
	    | Netxdr.XV_enum_fast k ->
		if k >= 0 && k < m then
		  snd(l.(k))
		else
		  fail_map_xv_enum_fast()
	    | Netxdr.XV_enum name ->
		let k = ref 0 in
		while !k < m && (fst l.( !k ) <> name) do
		  incr k
		done;
		if !k >= m then
		  fail_map_xv_enum_fast();
		snd(l.( !k ))
            | Netxdr.XV_direct(exn,_,f) ->
                map_xv_enum_fast t (f exn)
	    | _ ->
		fail_map_xv_enum_fast()
	)
    | _ ->
	fail_map_xv_enum_fast()


let fail_map_xv_struct_fast () =
  failwith "Rpc_util.map_xv_struct_fast"

let rec map_xv_struct_fast t v =
  match t with
    | Netxdr.X_struct decl ->
	let decl = Array.of_list decl in
	let m = Array.length decl in
	( match v with
	    | Netxdr.XV_struct_fast x ->
		let k = Array.length x in
		if k = m then
		  x
		else
		  fail_map_xv_struct_fast()
	    | Netxdr.XV_struct l ->
		( try
		    Array.map
		      (fun (name,y) -> List.assoc name l)
		      decl
		  with
		      Not_found -> fail_map_xv_struct_fast()
		)
            | Netxdr.XV_direct(exn,_,f) ->
                map_xv_struct_fast t (f exn)
	    | _ ->
		fail_map_xv_struct_fast()
	)
    | _ ->
	fail_map_xv_struct_fast()


let fail_map_xv_union_over_enum_fast () =
  failwith "Rpc_util.map_xv_union_over_enum_fast"

let rec map_xv_union_over_enum_fast t v =
  match t with
    | Netxdr.X_union_over_enum(enum_t, u, u_dfl ) ->
	let e = Array.of_list (get_enum enum_t) in
	let u = Array.of_list u in
	let m = Array.length e in
	assert( m = Array.length u );
	( match v with
	    | Netxdr.XV_union_over_enum_fast(k, x) ->
		if k >= 0 && k < m then
		  (k, (snd e.(k)), x)
		else
		  fail_map_xv_union_over_enum_fast()
	    | Netxdr.XV_union_over_enum(name, x) ->
		let k = ref 0 in
		while !k < m && fst(e.( !k )) <> name do
		  incr k
		done;
		if !k >= m then
		  fail_map_xv_union_over_enum_fast();
		(!k, (snd e.(!k)), x)
            | Netxdr.XV_direct(exn,_,f) ->
                map_xv_union_over_enum_fast t (f exn)
	    | _ ->
		fail_map_xv_union_over_enum_fast()
	)
    | _ ->
	fail_map_xv_union_over_enum_fast()


let string_of_opaque s l =
  let b = Buffer.create 32 in
  for k = 0 to l - 1 do
    Buffer.add_string b (sprintf "%02x" (Char.code s.[k]))
  done;
  Buffer.contents b


let string_of_struct print_elem t v =
  let tl = 
    match t with
      | Netxdr.X_struct tl -> Array.of_list tl
      | _ -> assert false in
  let vl = map_xv_struct_fast t v in
  "{" ^ 
    String.concat ";"
    (Array.to_list
       (Array.mapi
	  (fun k (elem_name, elem_t) ->
	     let elem_v = vl.(k) in
	     sprintf "%s=%s" elem_name (print_elem elem_t elem_v)
	  )
	  tl
       )
    ) ^ "}"


let rec dest_xv_array v =
  match v with
    | Netxdr.XV_array x ->
        x
    | Netxdr.XV_array_of_string_fast x ->
        Array.map (fun s -> Netxdr.XV_string s) x
    | Netxdr.XV_direct(exn,_,f) ->
        dest_xv_array (f exn)
    | _ ->
        raise Netxdr.Dest_failure;;


let string_of_array print_elem t v =
  let elem_t =
    match t with 
      | Netxdr.X_array_fixed(u,_)
      | Netxdr.X_array(u,_) ->
	  u
      | _ -> 
	  assert false in
  let vl =
    dest_xv_array v in
  "[" ^ 
    String.concat ";"
    (Array.to_list
       (Array.map
	  (fun elem_v -> print_elem elem_t elem_v)
	  vl)) ^ "]"


let string_of_union print_elem t v =
  let elem_t, elem_v, case =
    match t with
      | Netxdr.X_union_over_int(l, default) ->
	  let (n, elem_v) = Netxdr.dest_xv_union_over_int v in
	  let elem_t =
	    try List.assoc n l
	    with Not_found ->
	      ( match default with
		  | None -> assert false
		  | Some d -> d
	      ) in
	  (elem_t, elem_v, sprintf "%ld" (Netnumber.int32_of_int4 n))
      | Netxdr.X_union_over_uint(l, default) ->
	  let (n, elem_v) = Netxdr.dest_xv_union_over_uint v in
	  let elem_t =
	    try List.assoc n l
	    with Not_found ->
	      ( match default with
		  | None -> assert false
		  | Some d -> d
	      ) in
	  (elem_t, elem_v, sprintf "%lu" (Netnumber.logical_int32_of_uint4 n))
      | Netxdr.X_union_over_enum(enum_t, l, default) ->
	  let (k,_,elem_v) = map_xv_union_over_enum_fast t v in
	  let enum = get_enum enum_t in
	  let case, _ = List.nth enum k in
	  let elem_t =
	    try List.assoc case l
	    with Not_found ->
	      ( match default with
		  | None -> assert false
		  | Some d -> d
	      ) in
	  (elem_t, elem_v, case) 
      | _ -> assert false
  in
  sprintf
    "union<case=%s %s>"
    case
    (print_elem elem_t elem_v)


let rec string_of_abbrev_arg t v =
  match t with
    | Netxdr.X_int
    | Netxdr.X_uint
    | Netxdr.X_hyper
    | Netxdr.X_uhyper
    | Netxdr.X_enum _
    | Netxdr.X_float
    | Netxdr.X_double
    | Netxdr.X_void ->
	string_of_full_arg t v

    | Netxdr.X_opaque_fixed _
    | Netxdr.X_opaque _ ->
	let s = Netxdr.dest_xv_opaque v in
	let l = min 16 (String.length s) in
	let suffix = if l < String.length s then "..." else "" in
	string_of_opaque s l ^ suffix

    | Netxdr.X_string _ ->
	let s = Netxdr.dest_xv_string v in
	let l = min 16 (String.length s) in
	let suffix = if l < String.length s then "..." else "" in
	"\"" ^ (String.escaped (String.sub s 0 l)) ^ "\"" ^ suffix

    | Netxdr.X_mstring (_,_) ->
	let ms = Netxdr.dest_xv_mstring v in
	let (s,p) = ms#as_string in
	let l = min 16 ms#length in
	let suffix = if l < ms#length then "..." else "" in
	"\"" ^ (String.escaped (String.sub s p l)) ^ "\"" ^ suffix

    | Netxdr.X_array_fixed _
    | Netxdr.X_array _ ->
	let a = Netxdr.dest_xv_array v in
	"array<" ^ string_of_int (Array.length a) ^ ">"

    | Netxdr.X_struct _ ->
	"struct"

    | Netxdr.X_union_over_int(_,_) ->
	let (n,_) = Netxdr.dest_xv_union_over_int v in
	sprintf "union<case=%ld>" (Netnumber.int32_of_int4 n)

    | Netxdr.X_union_over_uint(_,_) ->
	let (n,_) = Netxdr.dest_xv_union_over_uint v in
	sprintf "union<case=%lu>" (Netnumber.logical_int32_of_uint4 n)

    | Netxdr.X_union_over_enum(enum_t,_,_) ->
	let e = get_enum enum_t in
	let (k,_,_) = map_xv_union_over_enum_fast t v in
	let (n,_) = List.nth e k in
	sprintf "union<case=%s>" n

    | Netxdr.X_direct(t1, _,_,_,_) ->
	string_of_abbrev_arg t1 v

    | Netxdr.X_refer _
    | Netxdr.X_type _
    | Netxdr.X_param _ -> 
	assert false

    | Netxdr.X_rec(_,t') ->
	string_of_abbrev_arg t' v


and string_of_rec_arg recdefs t v =
  match t with
    | Netxdr.X_int ->
	sprintf "%ld" 
	  (Netnumber.int32_of_int4 (Netxdr.dest_xv_int v))
    | Netxdr.X_uint ->
	sprintf "%lu" 
	  (Netnumber.logical_int32_of_uint4 (Netxdr.dest_xv_uint v))
    | Netxdr.X_hyper ->
	sprintf "%Ld" 
	  (Netnumber.int64_of_int8 (Netxdr.dest_xv_hyper v))
    | Netxdr.X_uhyper ->
	sprintf "%Lu" 
	  (Netnumber.logical_int64_of_uint8 (Netxdr.dest_xv_uhyper v))
    | Netxdr.X_enum enum ->
	( match v with
	    | Netxdr.XV_enum case ->
		case
	    | Netxdr.XV_enum_fast n ->
		fst(List.nth enum n)
	    | _ -> assert false
	)
    | Netxdr.X_float ->
	string_of_float
	  (Netnumber.float_of_fp4 (Netxdr.dest_xv_float v))
    | Netxdr.X_double ->
	string_of_float
	  (Netnumber.float_of_fp8 (Netxdr.dest_xv_double v))
    | Netxdr.X_opaque_fixed _
    | Netxdr.X_opaque _ ->
	let s = Netxdr.dest_xv_opaque v in
	string_of_opaque s (String.length s)
    | Netxdr.X_string _ ->
	let s = Netxdr.dest_xv_string v in
	"\"" ^ String.escaped s ^ "\""
    | Netxdr.X_mstring(_, _) ->
	let ms = Netxdr.dest_xv_mstring v in
	let (s,p) = ms#as_string in
	"\"" ^ String.escaped (String.sub s p (ms#length-p)) ^ "\""
    | Netxdr.X_array_fixed _
    | Netxdr.X_array _ ->
	string_of_array
	  (string_of_rec_arg recdefs)
	  t
	  v
    | Netxdr.X_struct _ ->
	string_of_struct
	  (string_of_rec_arg recdefs)
	  t
	  v
    | Netxdr.X_union_over_int _
    | Netxdr.X_union_over_uint _
    | Netxdr.X_union_over_enum _ ->
	string_of_union
	  (string_of_rec_arg recdefs)
	  t
	  v
    | Netxdr.X_void ->
	"void"
    | Netxdr.X_rec (n, u) ->
	let recdefs' = StrMap.add n u recdefs in
	string_of_rec_arg recdefs' u v

    | Netxdr.X_refer n ->
	let u =
	  try StrMap.find n recdefs
	  with Not_found -> assert false in
	string_of_rec_arg recdefs u v

    | Netxdr.X_direct(t1, _, _, _, _) ->
	string_of_rec_arg recdefs t1 v

    | Netxdr.X_type _
    | Netxdr.X_param _ ->
	assert false


and string_of_full_arg t v =
  string_of_rec_arg StrMap.empty t v


let rec string_of_abbrev_args t v =
  match t with
    | Netxdr.X_void ->
	""
    | Netxdr.X_struct _ ->
	string_of_struct
	  string_of_abbrev_arg
	  t
	  v

    | Netxdr.X_direct(t1,_,_,_,_) ->
	string_of_abbrev_args t1 v

    | _ ->
	string_of_abbrev_arg t v


let rec string_of_full_args t v =
  match t with
    | Netxdr.X_void ->
	""
    | Netxdr.X_struct _ ->
	string_of_struct
	  string_of_full_arg
	  t
	  v

    | Netxdr.X_direct(t1,_,_,_,_) ->
	string_of_full_args t1 v

    | _ ->
	string_of_full_arg t v



let string_of_request v prog procname args =
  try
    let prognr = Rpc_program.program_number prog in
    let versnr = Rpc_program.version_number prog in
    let (procnr, in_t, _) = Rpc_program.signature prog procname in
    let in_t = Netxdr.xdr_type_term in_t in
    let s_args =
      match v with
	| `Name_only -> ""
	| `Name_abbrev_args -> string_of_abbrev_args in_t args
	| `Name_full_args -> string_of_full_args in_t args in
    sprintf
      "%s[0x%lx,0x%lx,0x%lx](%s)"
      procname
      (Netnumber.logical_int32_of_uint4 prognr)
      (Netnumber.logical_int32_of_uint4 versnr)
      (Netnumber.logical_int32_of_uint4 procnr)
      s_args
  with
    | e ->
	sprintf "[Exception in string_of_request: %s]"
	  (Netexn.to_string e)


let string_of_response v prog procname rv =
  try
    let prognr = Rpc_program.program_number prog in
    let versnr = Rpc_program.version_number prog in
    let (procnr, _, out_t) = Rpc_program.signature prog procname in
    let out_t = Netxdr.xdr_type_term out_t in
    let s_rv =
      match v with
	| `Name_only -> ""
	| `Name_abbrev_args -> string_of_abbrev_arg out_t rv
	| `Name_full_args -> string_of_full_arg out_t rv in
    sprintf
      "%s[0x%lx,0x%lx,0x%lx] returns %s"
      procname
      (Netnumber.logical_int32_of_uint4 prognr)
      (Netnumber.logical_int32_of_uint4 versnr)
      (Netnumber.logical_int32_of_uint4 procnr)
      s_rv
  with
    | e ->
        let bt = Printexc.get_backtrace() in
	sprintf "[Exception in string_of_response: %s, backtrace: %s]"
	  (Netexn.to_string e) bt


let string_of_value t xv =
  string_of_full_arg t xv

let hex_dump_m m pos len =
  Netencoding.to_hex ~lc:true
    Netstring_tstring.(memory_ops.substring m pos len)

let hex_dump_b s pos len =
  Netencoding.to_hex ~lc:true (Bytes.sub_string s pos len)
