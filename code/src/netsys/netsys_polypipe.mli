(* $Id$ *)

(** Polymorphic message pipes *)

(** These pipes are restricted to a single process, and can be used
    to send messages of any types between threads.
 *)

type 'a polypipe

val create : int -> bool -> 'a polypipe
  (** Create a new polypipe with an internal buffer of n messages.
      The bool says whether the pipe is non-blocking.
   *)

val length : 'a polypipe -> int
  (** return the number of messages in the buffer *)

val eof : 'a polypipe -> bool
  (** whether the eof signal was sent. Note that there may still be messages
      in the buffer
   *)

val read : 'a polypipe -> 'a option
  (** read a message. [None] means EOF. Possible [Unix.unix_error] codes:
       - [EAGAIN]: the pipe is non-blocking, and there is no message in the
         buffer
       - [EINTR]: a signal arrived
   *)

val write : 'a polypipe -> 'a option -> unit
  (** write a message, or mark the end of the stream ([None]).
      Possible [Unix.unix_error] codes:
       - [EAGAIN]: the pipe is non-blocking, and there is no message in the
         buffer
       - [EINTR]: a signal arrived
       - [EPIPE]: it was tried to send a message after sending [None].

      Unlike OS pipes, polypipes become writable after signaling EOF.
   *)

val close : 'a polypipe -> unit
  (** Close the pipe. Reading and writing will be immediately impossible *)

val read_descr : 'a polypipe -> Unix.file_descr
  (** Returns a descriptor that can be used for polling. When the descriptor
      is readable there is a message in the buffer. If called several times,
      always the same descriptor is returned.

      The caller has to close the descriptor after use.
   *)

val write_descr : 'a polypipe -> Unix.file_descr
  (** Returns a descriptor that can be used for polling. When the descriptor
      is readable (sic) there is space in the buffer for another message.
      If called several times, always the same descriptor is returned.

      The caller has to close the descriptor after use.
   *)
