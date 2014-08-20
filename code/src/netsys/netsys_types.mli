(* $Id$ *)

(** Types for all Netsys modules *)

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t
  (** We consider 1-dimensional bigarrays of chars as memory buffers.
      They have the useful property that the garbage collector cannot
      relocate them, i.e. the address is fixed. Also, one can mmap
      a file, and connect the bigarray with shared memory.
   *)


(** See {!Xdr_mstring.mstring} for documentation *)
class type mstring =
object
  method length : int
  method blit_to_string :  int -> string -> int -> int -> unit
  method blit_to_memory : int -> memory -> int -> int -> unit
  method as_string : string * int
  method as_memory : memory * int
  method preferred : [ `Memory | `String ]
end



exception EAGAIN_RD
exception EAGAIN_WR
  (** A read or write cannot be done because the descriptor is in
      non-blocking mode and would block. This corresponds to the
      [Unix.EAGAIN] error but includes whether it was a read or write.

      When the read or write is possible, the interrupted function should
      simply be again called.

      These two exceptions are preferred by TLS providers.
   *)

exception TLS_switch_request
  (** The server requested a rehandshake (this exception is thrown
      in the client)
   *)

exception TLS_switch_response of bool
      (** The client accepted or denied a rehandshake (this exception is thrown
          in the server). [true] means acceptance.
       *)

exception TLS_error of string
      (** A fatal error occurred (i.e. the session needs to be terminated).
          The string is a symbol identifying the error.
       *)

exception TLS_warning of string
      (** A non-fatal error occurred. The interrupted function should be
          called again.
          The string is a symbol identifying the warning.
       *)
