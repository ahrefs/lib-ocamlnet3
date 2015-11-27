(* $Id$ *)

(* NOTE: Parts of this implementation depend very much of representation
 * details of O'Caml 3.xx. It is not guaranteed that this works in future
 * versions of O'Caml as well.
 *)

(* representation types *)

#ifdef WORDSIZE_64
type int4 = int   (* faster on 64 bit platforms! *)
type uint4 = int
  (* Note that values >= 0x8000_0000 are represented as negative ints, i.e.
     the bits 32-62 are all set to 1.
   *)
#else
type int4 = int32
type uint4 = int32
#endif

type int8 = int64
type uint8 = int64

type fp4 = int32 (* string;; *)    (* IEEE representation of fp numbers *)
type fp8 = int64

exception Cannot_represent of string
(* raised if numbers are too big to map them to other type *)

exception Out_of_range

module type ENCDEC = sig
  val read_int4 : Bytes.t -> int -> int4
  val read_int8 : Bytes.t -> int -> int8
  val read_uint4 : Bytes.t -> int -> uint4
  val read_uint8 : Bytes.t -> int -> uint8

  val read_int4_unsafe : Bytes.t -> int -> int4
  val read_int8_unsafe : Bytes.t -> int -> int8
  val read_uint4_unsafe : Bytes.t -> int -> uint4
  val read_uint8_unsafe : Bytes.t -> int -> uint8

  val read_string_int4 : string -> int -> int4
  val read_string_int8 : string -> int -> int8
  val read_string_uint4 : string -> int -> uint4
  val read_string_uint8 : string -> int -> uint8

  val read_string_int4_unsafe : string -> int -> int4
  val read_string_int8_unsafe : string -> int -> int8
  val read_string_uint4_unsafe : string -> int -> uint4
  val read_string_uint8_unsafe : string -> int -> uint8

  val write_int4 : Bytes.t -> int -> int4 -> unit
  val write_int8 : Bytes.t -> int -> int8 -> unit
  val write_uint4 : Bytes.t -> int -> uint4 -> unit
  val write_uint8 : Bytes.t -> int -> uint8 -> unit

  val write_int4_unsafe : Bytes.t -> int -> int4 -> unit
  val write_int8_unsafe : Bytes.t -> int -> int8 -> unit
  val write_uint4_unsafe : Bytes.t -> int -> uint4 -> unit
  val write_uint8_unsafe : Bytes.t -> int -> uint8 -> unit

  val int4_as_bytes : int4 -> Bytes.t
  val int8_as_bytes : int8 -> Bytes.t
  val uint4_as_bytes : uint4 -> Bytes.t
  val uint8_as_bytes : uint8 -> Bytes.t

  val int4_as_string : int4 -> string
  val int8_as_string : int8 -> string
  val uint4_as_string : uint4 -> string
  val uint8_as_string : uint8 -> string

  val write_fp4 : Bytes.t -> int -> fp4 -> unit
  val write_fp8 : Bytes.t -> int -> fp8 -> unit

  val fp4_as_string : fp4 -> string
  val fp8_as_string : fp8 -> string

  val fp4_as_bytes : fp4 -> Bytes.t
  val fp8_as_bytes : fp8 -> Bytes.t

  val read_fp4 : Bytes.t -> int -> fp4
  val read_fp8 : Bytes.t -> int -> fp8
  val read_string_fp4 : string -> int -> fp4
  val read_string_fp8 : string -> int -> fp8
end


let rec cannot_represent s = 
  (* "rec" because this prevents this function from being inlined *)
  raise (Cannot_represent s)


(**********************************************************************)
(* cmp                                                                *)
(**********************************************************************)

#ifdef WORDSIZE_64
let lt_uint4 x y =
  if x < y then x >= 0 || y < 0 else x >= 0 && y < 0
#else
let lt_uint4 x y =
  if x < y then 
    x >= 0l
      (* because:
         - if x < 0  && y < 0   ==> x >u y
         - if x < 0  && y >= 0  ==> x >u y
         - if x >= 0 && y => 0  ==> x <u y
       *)
  else (* ==>  y <= x *) 
    y < x && y < 0l
      (* because:
         - if y < 0  && x < 0  ==> x <u y
         - if y < 0  && x >= 0 ==> x <u y
         - if y >= 0 && x >= 0 ==> x >u y
       *)
#endif

let le_uint4 x y = not(lt_uint4 y x)
let gt_uint4 x y = lt_uint4 y x
let ge_uint4 x y = not(lt_uint4 x y)


let lt_uint8 x y =
  if x < y then x >= 0L || y <= 0L else x >= 0L && y < 0L

let le_uint8 x y = not(lt_uint8 y x)
let gt_uint8 x y = lt_uint8 y x
let ge_uint8 x y = not(lt_uint8 x y)


(**********************************************************************)
(* mk_[u]intn                                                         *)
(**********************************************************************)

(* compatibility interface *)

#ifdef WORDSIZE_64
let mk_int4 (c3,c2,c1,c0) =
  let n3 = (Char.code c3) in
  let n2 = (Char.code c2) in
  let n1 = (Char.code c1) in
  let n0 = (Char.code c0) in
  (* be careful to set the sign correctly: *)
  ((n3 lsl 55) asr 31) lor (n2 lsl 16) lor (n1 lsl 8) lor n0
#else
let mk_int4 (c3,c2,c1,c0) =
  let n3 = Int32.of_int (Char.code c3) in
  let n2 = Int32.of_int (Char.code c2) in
  let n1 = Int32.of_int (Char.code c1) in
  let n0 = Int32.of_int (Char.code c0) in
  Int32.logor
    (Int32.shift_left n3 24)
    (Int32.logor
       (Int32.shift_left n2 16)
       (Int32.logor
	  (Int32.shift_left n1 8)
	  n0))
#endif


let mk_int8 (c7,c6,c5,c4,c3,c2,c1,c0) =
  let n7 = Int64.of_int (Char.code c7) in
  let n6 = Int64.of_int (Char.code c6) in
  let n5 = Int64.of_int (Char.code c5) in
  let n4 = Int64.of_int (Char.code c4) in
  let n3 = Int64.of_int (Char.code c3) in
  let n2 = Int64.of_int (Char.code c2) in
  let n1 = Int64.of_int (Char.code c1) in
  let n0 = Int64.of_int (Char.code c0) in

  Int64.logor
    (Int64.shift_left n7 56)
    (Int64.logor
       (Int64.shift_left n6 48)
       (Int64.logor
	  (Int64.shift_left n5 40)
	  (Int64.logor
	     (Int64.shift_left n4 32)
	     (Int64.logor
		(Int64.shift_left n3 24)
		(Int64.logor
		   (Int64.shift_left n2 16)
		   (Int64.logor
		      (Int64.shift_left n1 8)
		      n0))))))


let mk_uint4 = mk_int4
let mk_uint8 = mk_int8

(**********************************************************************)
(* dest_[u]intn                                                       *)
(**********************************************************************)

(* compatibility interface *)

#ifdef WORDSIZE_64
let dest_int4 x =
  let n3 = (x lsr 24) land 0xff in
  let n2 = (x lsr 16) land 0xff in
  let n1 = (x lsr 8) land 0xff in
  let n0 = x land 0xff in
  (Char.chr n3, Char.chr n2, Char.chr n1, Char.chr n0)
#else
let dest_int4 x =
  let n3 = Int32.to_int (Int32.shift_right_logical x 24) land 0xff in
  let n2 = Int32.to_int (Int32.shift_right_logical x 16) land 0xff in
  let n1 = Int32.to_int (Int32.shift_right_logical x 8) land 0xff in
  let n0 = Int32.to_int (Int32.logand x 0xffl) in
  (Char.chr n3, Char.chr n2, Char.chr n1, Char.chr n0)
#endif

let dest_int8 x =
  let n7 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 56)
			   0xffL) in
  let n6 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 48)
			   0xffL) in
  let n5 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 40)
			   0xffL) in
  let n4 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 32)
			   0xffL) in
  let n3 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 24)
			   0xffL) in
  let n2 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 16)
			   0xffL) in
  let n1 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 8)
			   0xffL) in
  let n0 = Int64.to_int (Int64.logand x 0xffL) in
  (Char.chr n7, Char.chr n6, Char.chr n5, Char.chr n4,
   Char.chr n3, Char.chr n2, Char.chr n1, Char.chr n0)



let dest_uint4 = dest_int4
let dest_uint8 = dest_int8

(**********************************************************************)
(* int_of_[u]intn                                                     *)
(**********************************************************************)

let c_max_int_64 = Int64.of_int max_int
let c_min_int_64 = Int64.of_int min_int


let name_int_of_int4 = "int_of_int4"

#ifdef WORDSIZE_64
let int_of_int4 x = x
#else
let int_of_int4 x =
  if x < (-0x4000_0000l) || x > 0x3fff_ffffl then
    cannot_represent name_int_of_int4;
  Int32.to_int x
#endif


let name_int_of_uint4 = "int_of_uint4"

#ifdef WORDSIZE_64
let int_of_uint4 x =
  (* x land 0xffff_ffff - "Integer literal exceeds the range..." grrrmpf *)
  (x lsl 31) lsr 31
#else
let int_of_uint4 x =
  if x >= 0l && x <= 0x3fff_ffffl then
    Int32.to_int x
  else
    cannot_represent name_int_of_uint4
#endif


let name_int_of_int8 = "int_of_int8"

let int_of_int8 x =
  if x >= c_min_int_64 && x <= c_max_int_64 then
    Int64.to_int x
  else
    cannot_represent name_int_of_int8



let name_int_of_uint8 = "int_of_uint8"

let int_of_uint8 x =
  if x >= Int64.zero && x <= c_max_int_64 then
    Int64.to_int x
  else
    cannot_represent name_int_of_uint8


(**********************************************************************)
(* intn_of_int                                                        *)
(**********************************************************************)

let name_int4_of_int = "int4_of_int"

#ifdef WORDSIZE_64
let int4_of_int i =
  let j = i asr 31 in
  if j = 0 || j = (-1) then 
    i
  else
    cannot_represent name_int4_of_int
#else
let int4_of_int i =
  Int32.of_int i
#endif


let name_uint4_of_int = "uint4_of_int"

#ifdef WORDSIZE_64
let uint4_of_int i =
  let j = i asr 32 in
  if j = 0 then
    (i lsl 31) asr 31  (* fix sign *)
  else
    cannot_represent name_uint4_of_int
#else
let uint4_of_int i =
  if i >= 0 then
    Int32.of_int i
  else
    cannot_represent name_uint4_of_int
#endif


let int8_of_int = Int64.of_int 


let name_uint8_of_int = "uint8_of_int"

let uint8_of_int i =
  if i >= 0 then
    Int64.of_int i
  else
    cannot_represent name_uint8_of_int



(**********************************************************************)
(* Int32 and Int64 support: int[32|64]_of_[u]intn                     *)
(**********************************************************************)

#ifdef WORDSIZE_64
let int32_of_int4 x = Int32.of_int x 
#else
let int32_of_int4 x = x 
#endif

let name_int32_of_uint4 = "int32_of_uint4"

#ifdef WORDSIZE_64
let int32_of_uint4 x =
  if x >= 0 then
    Int32.of_int x
  else
    cannot_represent name_int32_of_uint4
#else
let int32_of_uint4 x =
  if x >= 0l then
    x
  else
    cannot_represent name_int32_of_uint4
#endif


let c_int32_min_int_64 = Int64.of_int32 Int32.min_int 
let c_int32_max_int_64 = Int64.of_int32 Int32.max_int 

let name_int32_of_int8 = "int32_of_int8"

let int32_of_int8 x =
  if x >= (-0x8000_0000L) && x <= 0x7fff_0000L then
    Int64.to_int32 x
  else
    cannot_represent name_int32_of_int8



let name_int32_of_uint8 = "int32_of_uint8"

let int32_of_uint8 x =
  if x >= 0L && x <= 0x7fff_0000L then
    Int64.to_int32 x
  else
    cannot_represent name_int32_of_uint8


#ifdef WORDSIZE_64
let int64_of_int4 = Int64.of_int
#else
let int64_of_int4 = Int64.of_int32 
#endif


#ifdef WORDSIZE_64
let int64_of_uint4 x =
if x >= 0 then
    Int64.of_int x
  else
    Int64.add (Int64.of_int x) 0x1_0000_0000L
#else
let int64_of_uint4 x =
  if x >= 0l then
    Int64.of_int32 x
  else
    Int64.add (Int64.of_int32 x) 0x1_0000_0000L
#endif


let int64_of_int8 x = x 

let name_int64_of_uint8 = "int64_of_uint8"

let int64_of_uint8 x =
  if x >= 0L then
    x
  else
    cannot_represent name_int64_of_uint8



(**********************************************************************)
(* Int32 and Int64 support: [u]intn_of_int[32|64]                     *)
(**********************************************************************)

#ifdef WORDSIZE_64
let int4_of_int32 = Int32.to_int
#else
let int4_of_int32 x = x
#endif


let name_uint4_of_int32 = "uint4_of_int32"

let uint4_of_int32 i =
  if i < 0l then
    cannot_represent name_uint4_of_int32;
  int4_of_int32 i


let int8_of_int32 =
  Int64.of_int32


let name_uint8_of_int32 = "uint8_of_int32"

let uint8_of_int32 i =
  if i < 0l then
    cannot_represent name_uint8_of_int32;
  Int64.of_int32 i


let name_int4_of_int64 = "int4_of_int64"

#ifdef WORDSIZE_64
let int4_of_int64 i =
  if i >= (-0x8000_0000L) && i <= 0x7fff_ffffL then
    Int64.to_int i
  else cannot_represent name_int4_of_int64
#else
let int4_of_int64 i =
  if i >= (-0x8000_0000L) && i <= 0x7fff_ffffL then
    Int64.to_int32 i
  else cannot_represent name_int4_of_int64
#endif

let name_uint4_of_int64 = "uint4_of_int64"

let uint4_of_int64 i =
  if i < 0L || i > 0xffff_ffffL then
    cannot_represent name_uint4_of_int64;
#ifdef WORDSIZE_64
  Int64.to_int(Int64.shift_right (Int64.shift_left i 32) 32)  (* sign! *)
#else
  Int64.to_int32 i
#endif


let int8_of_int64 i = i 

let name_uint8_of_int64 = "uint8_of_int64"

let uint8_of_int64 i =
  if i < 0L then
    cannot_represent name_uint8_of_int64;
  i


(**********************************************************************)
(* logical_xxx_of_xxx                                                 *)
(**********************************************************************)

#ifdef WORDSIZE_64
let logical_uint4_of_int32 x = Int32.to_int x
let logical_int32_of_uint4 x = Int32.of_int x
#else
let logical_uint4_of_int32 x = x
let logical_int32_of_uint4 x = x
#endif

let logical_uint8_of_int64 x = x
let logical_int64_of_uint8 x = x

(**********************************************************************)
(* min/max                                                            *)
(**********************************************************************)

let min_int4 = int4_of_int32 Int32.min_int
let min_uint4 = uint4_of_int 0
let min_int8 = int8_of_int64 Int64.min_int
let min_uint8 = uint8_of_int 0

let max_int4 = int4_of_int32 Int32.max_int
let max_uint4 = logical_uint4_of_int32 (-1l)
let max_int8 = int8_of_int64 Int64.max_int
let max_uint8 = logical_uint8_of_int64 (-1L)


(**********************************************************************)
(* floating point                                                     *)
(**********************************************************************)

let fp8_of_fp4 x =
  (* Requires O'Caml >= 3.08 *)
  Int64.bits_of_float (Int32.float_of_bits x)

let fp4_of_fp8 x =
  (* Requires O'Caml >= 3.08 *)
  Int32.bits_of_float (Int64.float_of_bits x)

let float_of_fp8 x =
  (* Requires O'Caml >= 3.01 *)
  Int64.float_of_bits x



let float_of_fp4 x =
  (* Requires O'Caml >= 3.08 *)
  Int32.float_of_bits x
  (* Old:
   *  float_of_fp8 (fp8_of_fp4 x)
   *)



let fp8_of_float x =
  (* Requires O'Caml >= 3.01 *)
  Int64.bits_of_float x



let fp4_of_float x =
  (* Requires O'Caml >= 3.08 *)
  Int32.bits_of_float x
  (* Old:
   * fp4_of_fp8 (fp8_of_float x)
   *)


let mk_fp4 x = int32_of_int4 (mk_int4 x)
let mk_fp8 = mk_int8
let dest_fp4 x = dest_int4 (int4_of_int32 x)
let dest_fp8 = dest_int8


module BE : ENCDEC = struct
  (**********************************************************************)
  (* read_[u]intn                                                       *)
  (**********************************************************************)
  
  #ifdef WORDSIZE_64
    #ifdef USE_NETSYS_XDR
  let read_int4_unsafe =
    Netsys_xdr.s_read_int4_64_unsafe
    #else
  let read_int4_unsafe s pos =
    let n3 = Char.code (Bytes.unsafe_get s pos) in
    let x = (n3 lsl 55) asr 31 in  (* sign! *)
    let n2 = Char.code (Bytes.unsafe_get s (pos+1)) in
    let x = x lor (n2 lsl 16) in
    let n1 = Char.code (Bytes.unsafe_get s (pos+2)) in
    let x = x lor (n1 lsl 8) in
    let n0 = Char.code (Bytes.unsafe_get s (pos+3)) in
    x lor n0
    #endif
   #else
  let read_int4_unsafe s pos =
    let n3 = Int32.of_int (Char.code (Bytes.unsafe_get s pos)) in
    let x = Int32.shift_left n3 24 in
    let n2 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+1))) in
    let x = Int32.logor x (Int32.shift_left n2 16) in
    let n1 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+2))) in
    let x = Int32.logor x (Int32.shift_left n1 8) in
    let n0 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+3))) in
    Int32.logor x n0
   #endif
(*
  seems to be slightly better than

  Int32.logor
    (Int32.shift_left n3 24)
    (Int32.logor
       (Int32.shift_left n2 16)
       (Int32.logor
	  (Int32.shift_left n1 8)
	  n0))
*)


  let read_int4 s pos =
    if pos < 0 || pos + 4 > Bytes.length s then
      raise Out_of_range;
    read_int4_unsafe s pos
      

  #ifdef WORDSIZE_64
    #ifdef USE_NETSYS_XDR
      #define FAST_READ_INT8 defined
    #endif
  #endif

  #ifdef FAST_READ_INT8
  let read_int8_unsafe s pos =
    let x1 = Netsys_xdr.s_read_int4_64_unsafe s pos in
    let x0 = Netsys_xdr.s_read_int4_64_unsafe s (pos+4) in
    Int64.logor
      (Int64.logand (Int64.of_int x0) 0xFFFF_FFFFL)
      (Int64.shift_left (Int64.of_int x1) 32)
  #else
  let read_int8_unsafe s pos =
    let n7 = Int64.of_int (Char.code (Bytes.unsafe_get s pos)) in
    let x = Int64.shift_left n7 56 in
    
    let n6 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+1))) in
    let x = Int64.logor x (Int64.shift_left n6 48) in
    
    let n5 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+2))) in
    let x = Int64.logor x (Int64.shift_left n5 40) in
    
    let n4 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+3))) in
    let x = Int64.logor x (Int64.shift_left n4 32) in
    
    let n3 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+4))) in
    let x = Int64.logor x (Int64.shift_left n3 24) in
    
    let n2 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+5))) in
    let x = Int64.logor x (Int64.shift_left n2 16) in
    
    let n1 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+6))) in
    let x = Int64.logor x (Int64.shift_left n1 8) in
    
    let n0 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+7))) in
    Int64.logor x n0
  #endif      


  let read_int8 s pos =
    if pos < 0 || pos + 8 > Bytes.length s then
      raise Out_of_range;
    read_int8_unsafe s pos
      

  let read_uint4 = read_int4
  let read_uint8 = read_int8
  let read_uint4_unsafe = read_int4_unsafe
  let read_uint8_unsafe = read_int8_unsafe;;
    
  let read_string_int4 s p = read_int4 (Bytes.unsafe_of_string s) p
  let read_string_int8 s p = read_int8 (Bytes.unsafe_of_string s) p
  let read_string_uint4 s p = read_uint4 (Bytes.unsafe_of_string s) p
  let read_string_uint8 s p = read_uint8 (Bytes.unsafe_of_string s) p

  let read_string_int4_unsafe s p =
    read_int4_unsafe (Bytes.unsafe_of_string s) p
  let read_string_int8_unsafe s p =
    read_int8_unsafe (Bytes.unsafe_of_string s) p
  let read_string_uint4_unsafe s p =
    read_uint4_unsafe (Bytes.unsafe_of_string s) p
  let read_string_uint8_unsafe s p =
    read_uint8_unsafe (Bytes.unsafe_of_string s) p


  (**********************************************************************)
  (* write_[u]intn                                                      *)
  (**********************************************************************)

  #ifdef WORDSIZE_64
    #ifdef USE_NETSYS_XDR
  let write_int4_unsafe =
    Netsys_xdr.s_write_int4_64_unsafe
    #else
  let write_int4_unsafe s pos x =
    let n3 = (x lsr 24) land 0xff in
    Bytes.unsafe_set s pos (Char.unsafe_chr n3);
    let n2 = (x lsr 16) land 0xff in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n2);
    let n1 = (x lsr 8) land 0xff in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n1);
    let n0 = x land 0xff in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n0);
    ()
    #endif
  #else
  let write_int4_unsafe s pos x =
    let n3 = Int32.to_int (Int32.shift_right_logical x 24) land 0xff in
    Bytes.unsafe_set s pos (Char.unsafe_chr n3);
    let n2 = Int32.to_int (Int32.shift_right_logical x 16) land 0xff in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n2);
    let n1 = Int32.to_int (Int32.shift_right_logical x 8) land 0xff in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n1);
    let n0 = Int32.to_int (Int32.logand x 0xffl) in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n0);
    ()
   #endif
   ;;


  let write_int4 s pos x =
    if pos < 0 || pos + 4 > Bytes.length s then
      raise Out_of_range;
    write_int4_unsafe s pos x

  #ifdef WORDSIZE_64
    #ifdef USE_NETSYS_XDR
      #define FAST_WRITE_INT8 defined
    #endif
  #endif

  #ifdef FAST_WRITE_INT8
  let write_int8_unsafe s pos x =
    Netsys_xdr.s_write_int4_64_unsafe s pos
      (Int64.to_int (Int64.shift_right x 32));
    Netsys_xdr.s_write_int4_64_unsafe s (pos+4)
      (Int64.to_int (Int64.logand x 0xFFFF_FFFFL))
  #else
  let write_int8_unsafe s pos x =
    let n7 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 56)
			     0xffL) in
    Bytes.unsafe_set s pos (Char.unsafe_chr n7);
    
    let n6 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 48)
			     0xffL) in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n6);
    
    let n5 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 40)
			     0xffL) in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n5);
    
    let n4 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 32)
			     0xffL) in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n4);
    
    let n3 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 24)
			     0xffL) in
    Bytes.unsafe_set s (pos+4) (Char.unsafe_chr n3);
    
    let n2 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 16)
			     0xffL) in
    Bytes.unsafe_set s (pos+5) (Char.unsafe_chr n2);
    
    let n1 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 8)
			     0xffL) in
    Bytes.unsafe_set s (pos+6) (Char.unsafe_chr n1);
    
    let n0 = Int64.to_int (Int64.logand x 0xffL) in
    Bytes.unsafe_set s (pos+7) (Char.unsafe_chr n0);
    ()
  #endif


  let write_int8 s pos x =
    if pos < 0 || pos + 8 > Bytes.length s then
      raise Out_of_range;
    write_int8_unsafe s pos x
      


  let write_uint4 = write_int4
  let write_uint8 = write_int8
  let write_uint4_unsafe = write_int4_unsafe
  let write_uint8_unsafe = write_int8_unsafe
    
  (**********************************************************************)
  (* [u]intn_as_string                                                  *)
  (**********************************************************************)
    
  let int4_as_bytes x =
    let s = Bytes.create 4 in
    write_int4 s 0 x;
    s


  let uint4_as_bytes x =
    let s = Bytes.create 4 in
    write_uint4 s 0 x;
    s


  let int8_as_bytes x =
    let s = Bytes.create 8 in
    write_int8 s 0 x;
    s


  let uint8_as_bytes x =
    let s = Bytes.create 8 in
    write_int8 s 0 x;
    s

  let int4_as_string x = Bytes.unsafe_to_string(int4_as_bytes x)
  let int8_as_string x = Bytes.unsafe_to_string(int8_as_bytes x)
  let uint4_as_string x = Bytes.unsafe_to_string(uint4_as_bytes x)
  let uint8_as_string x = Bytes.unsafe_to_string(uint8_as_bytes x)


  (**********************************************************************)
  (* floating-point numbers                                             *)
  (**********************************************************************)
      
  let fp4_as_string x = int4_as_string (int4_of_int32 x)
  let fp8_as_string x = int8_as_string (int8_of_int64 x)
  let fp4_as_bytes x = int4_as_bytes (int4_of_int32 x)
  let fp8_as_bytes x = int8_as_bytes (int8_of_int64 x)
    
  let read_fp4 s pos =
    int32_of_int4(read_int4 s pos)

  let read_string_fp4 s pos =
    int32_of_int4(read_string_int4 s pos)

  let read_fp8 s pos =
    int64_of_int8(read_int8 s pos)

  let read_string_fp8 s pos =
    int64_of_int8(read_string_int8 s pos)

  let write_fp4 s pos x =
    write_int4 s pos (int4_of_int32 x)

  let write_fp8 s pos x =
    write_int8 s pos (int8_of_int64 x)
end


module LE : ENCDEC = struct
  (**********************************************************************)
  (* read_[u]intn                                                       *)
  (**********************************************************************)
  
  #ifdef WORDSIZE_64
(*
    IFDEF USE_NETSYS_XDR THEN
  let read_int4_unsafe =
    Netsys_xdr.s_read_int4_64_unsafe  (* FIXME *)
    ELSE
 *)
  let read_int4_unsafe s pos =
    let n3 = Char.code (Bytes.unsafe_get s (pos+3)) in
    let x = (n3 lsl 55) asr 31 in  (* sign! *)
    let n2 = Char.code (Bytes.unsafe_get s (pos+2)) in
    let x = x lor (n2 lsl 16) in
    let n1 = Char.code (Bytes.unsafe_get s (pos+1)) in
    let x = x lor (n1 lsl 8) in
    let n0 = Char.code (Bytes.unsafe_get s pos) in
    x lor n0
    (* END *)
   #else
  let read_int4_unsafe s pos =
    let n3 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+3))) in
    let x = Int32.shift_left n3 24 in
    let n2 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+2))) in
    let x = Int32.logor x (Int32.shift_left n2 16) in
    let n1 = Int32.of_int (Char.code (Bytes.unsafe_get s (pos+1))) in
    let x = Int32.logor x (Int32.shift_left n1 8) in
    let n0 = Int32.of_int (Char.code (Bytes.unsafe_get s pos)) in
    Int32.logor x n0
   #endif

  let read_int4 s pos =
    if pos < 0 || pos + 4 > Bytes.length s then
      raise Out_of_range;
    read_int4_unsafe s pos
      


  let read_int8_unsafe s pos =
    let n7 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+7))) in
    let x = Int64.shift_left n7 56 in
    
    let n6 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+6))) in
    let x = Int64.logor x (Int64.shift_left n6 48) in
    
    let n5 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+5))) in
    let x = Int64.logor x (Int64.shift_left n5 40) in
    
    let n4 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+4))) in
    let x = Int64.logor x (Int64.shift_left n4 32) in
    
    let n3 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+3))) in
    let x = Int64.logor x (Int64.shift_left n3 24) in
    
    let n2 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+2))) in
    let x = Int64.logor x (Int64.shift_left n2 16) in
    
    let n1 = Int64.of_int (Char.code (Bytes.unsafe_get s (pos+1))) in
    let x = Int64.logor x (Int64.shift_left n1 8) in
    
    let n0 = Int64.of_int (Char.code (Bytes.unsafe_get s pos)) in
    Int64.logor x n0
      


  let read_int8 s pos =
    if pos < 0 || pos + 8 > Bytes.length s then
      raise Out_of_range;
    read_int8_unsafe s pos
      

  let read_uint4 = read_int4
  let read_uint8 = read_int8
  let read_uint4_unsafe = read_int4_unsafe
  let read_uint8_unsafe = read_int8_unsafe;;
    
  let read_string_int4 s p = read_int4 (Bytes.unsafe_of_string s) p
  let read_string_int8 s p = read_int8 (Bytes.unsafe_of_string s) p
  let read_string_uint4 s p = read_uint4 (Bytes.unsafe_of_string s) p
  let read_string_uint8 s p = read_uint8 (Bytes.unsafe_of_string s) p

  let read_string_int4_unsafe s p =
    read_int4_unsafe (Bytes.unsafe_of_string s) p
  let read_string_int8_unsafe s p =
    read_int8_unsafe (Bytes.unsafe_of_string s) p
  let read_string_uint4_unsafe s p =
    read_uint4_unsafe (Bytes.unsafe_of_string s) p
  let read_string_uint8_unsafe s p =
    read_uint8_unsafe (Bytes.unsafe_of_string s) p

  (**********************************************************************)
  (* write_[u]intn                                                      *)
  (**********************************************************************)

  #ifdef WORDSIZE_64
(*
    IFDEF USE_NETSYS_XDR THEN
  let write_int4_unsafe =
    Netsys_xdr.s_write_int4_64_unsafe
    ELSE
 *)
  let write_int4_unsafe s pos x =
    let n3 = (x lsr 24) land 0xff in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n3);
    let n2 = (x lsr 16) land 0xff in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n2);
    let n1 = (x lsr 8) land 0xff in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n1);
    let n0 = x land 0xff in
    Bytes.unsafe_set s pos (Char.unsafe_chr n0);
    ()
   (* END *)
  #else
  let write_int4_unsafe s pos x =
    let n3 = Int32.to_int (Int32.shift_right_logical x 24) land 0xff in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n3);
    let n2 = Int32.to_int (Int32.shift_right_logical x 16) land 0xff in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n2);
    let n1 = Int32.to_int (Int32.shift_right_logical x 8) land 0xff in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n1);
    let n0 = Int32.to_int (Int32.logand x 0xffl) in
    Bytes.unsafe_set s pos (Char.unsafe_chr n0);
    ()
   #endif
    ;;


  let write_int4 s pos x =
    if pos < 0 || pos + 4 > Bytes.length s then
      raise Out_of_range;
    write_int4_unsafe s pos x



  let write_int8_unsafe s pos x =
    let n7 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 56)
			     0xffL) in
    Bytes.unsafe_set s (pos+7) (Char.unsafe_chr n7);
    
    let n6 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 48)
			     0xffL) in
    Bytes.unsafe_set s (pos+6) (Char.unsafe_chr n6);
    
    let n5 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 40)
			     0xffL) in
    Bytes.unsafe_set s (pos+5) (Char.unsafe_chr n5);
    
    let n4 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 32)
			     0xffL) in
    Bytes.unsafe_set s (pos+4) (Char.unsafe_chr n4);
    
    let n3 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 24)
			     0xffL) in
    Bytes.unsafe_set s (pos+3) (Char.unsafe_chr n3);
    
    let n2 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 16)
			     0xffL) in
    Bytes.unsafe_set s (pos+2) (Char.unsafe_chr n2);
    
    let n1 = Int64.to_int (Int64.logand (Int64.shift_right_logical x 8)
			     0xffL) in
    Bytes.unsafe_set s (pos+1) (Char.unsafe_chr n1);
    
    let n0 = Int64.to_int (Int64.logand x 0xffL) in
    Bytes.unsafe_set s pos (Char.unsafe_chr n0);
    ()



  let write_int8 s pos x =
    if pos < 0 || pos + 8 > Bytes.length s then
      raise Out_of_range;
    write_int8_unsafe s pos x
      


  let write_uint4 = write_int4
  let write_uint8 = write_int8
  let write_uint4_unsafe = write_int4_unsafe
  let write_uint8_unsafe = write_int8_unsafe
    
  (**********************************************************************)
  (* [u]intn_as_string                                                  *)
  (**********************************************************************)
    
  let int4_as_bytes x =
    let s = Bytes.create 4 in
    write_int4 s 0 x;
    s


  let uint4_as_bytes x =
    let s = Bytes.create 4 in
    write_uint4 s 0 x;
    s


  let int8_as_bytes x =
    let s = Bytes.create 8 in
    write_int8 s 0 x;
    s


  let uint8_as_bytes x =
    let s = Bytes.create 8 in
    write_int8 s 0 x;
    s

  let int4_as_string x = Bytes.unsafe_to_string(int4_as_bytes x)
  let int8_as_string x = Bytes.unsafe_to_string(int8_as_bytes x)
  let uint4_as_string x = Bytes.unsafe_to_string(uint4_as_bytes x)
  let uint8_as_string x = Bytes.unsafe_to_string(uint8_as_bytes x)


  (**********************************************************************)
  (* floating-point numbers                                             *)
  (**********************************************************************)
      
  let fp4_as_string x = int4_as_string (int4_of_int32 x)
  let fp8_as_string x = int8_as_string (int8_of_int64 x)
  let fp4_as_bytes x = int4_as_bytes (int4_of_int32 x)
  let fp8_as_bytes x = int8_as_bytes (int8_of_int64 x)
    
  let read_fp4 s pos =
    int32_of_int4(read_int4 s pos)

  let read_string_fp4 s pos =
    int32_of_int4(read_string_int4 s pos)

  let read_fp8 s pos =
    int64_of_int8(read_int8 s pos)

  let read_string_fp8 s pos =
    int64_of_int8(read_string_int8 s pos)

  let write_fp4 s pos x =
    write_int4 s pos (int4_of_int32 x)

  let write_fp8 s pos x =
    write_int8 s pos (int8_of_int64 x)
end


#ifdef HOST_IS_BIG_ENDIAN
module HO = BE
#else
module HO = LE
#endif
;;
