(* $Id$ *)

(** The SASLprep algorithm (RFC 4013) *)

(** This module implements the SASLprep string preparation algorithm,
    often used for normalizing passwords.

    Note that SASLprep is SLOOOOOOW, and should really only be used on short
    strings like passwords.

    This version of SASLprep doesn't check for unassigned codepoints.
 *)

exception SASLprepError
  (** Raised when a string cannot be transformed *)

val saslprep_a : int array -> int array
  (** Transform a string given as array of Unicode code points *)

val saslprep : string -> string
  (** Transform a string given as UTF-8 string *)

