(* $Id$ *)

(** Types for all Netsys modules *)

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t
  (** We consider 1-dimensional bigarrays of chars as memory buffers.
      They have the useful property that the garbage collector cannot
      relocate them, i.e. the address is fixed. Also, one can mmap
      a file, and connect the bigarray with shared memory.
   *)


exception EAGAIN_RD
exception EAGAIN_WR
  (** A read or write cannot be done because the descriptor is in
      non-blocking mode and would block. This corresponds to the
      [Unix.EAGAIN] error but includes whether it was a read or write.

      When the read or write is possible, the interrupted function should
      simply be again called.

      These two exceptions are preferred by TLS providers.
   *)

