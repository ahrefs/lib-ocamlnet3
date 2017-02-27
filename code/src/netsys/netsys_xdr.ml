(* $Id$ *)

external s_read_int4_64_unsafe : Bytes.t -> int -> int
  = "netsys_s_read_int4_64" NOALLOC

external s_write_int4_64_unsafe : Bytes.t -> int -> int -> unit
  = "netsys_s_write_int4_64" NOALLOC

external s_read_string_array_unsafe : 
  Bytes.t -> int -> int -> int32 -> string array -> int
  = "netsys_s_read_string_array"
