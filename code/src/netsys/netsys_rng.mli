(* $Id$ *)

(** Random-number generator *)

(** This is an interface to an OS-provided RNG that is fast and nevertheless
    secure enough for creating session keys. Note that it should not be used
    for creating long-term keys.

    On Unix, the [/dev/urandom] device is used. If it is not available, the
    functions fail.

    On Win32, an RNG is obtained using [CryptAcquireContext].
 *)

val set_rng : (Bytes.t -> unit) -> unit
  (** Sets the globally used RNG *)

val fill_random : Bytes.t -> unit
  (** Fills this string with random bytes *)

