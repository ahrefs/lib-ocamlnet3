(* $Id$ *)

(** Cryptographic digests (hashes) *)

class type digest_ctx =
object
  method add_memory : Netsys_types.memory -> unit
    (** Add data *)

  method add_substring : string -> int -> int -> unit
    (** Add data *)

  method finish : unit -> string
    (** Finish digestion, and return the digest *)
end


class type digest =
object
  method name : string
    (** The name conventionally follows the [<uppercasestring>-<size>] format,
        e.g. "MD5-128", "SHA1-160", or "SHA2-256".
     *)
  method size : int
    (** The size of the digest string in bytes *)

  method create : unit -> digest_ctx
    (** Start digestion *)
end


(** The following functions use the current digest module (as retrieved by
    {!Netsys_crypto.current_digests}), unless the [impl] argument is
    passed.
 *)

val digests : ?impl:(module Netsys_crypto_types.DIGESTS) ->
              unit -> digest list
    (** List of supported digests *)

val find : ?impl:(module Netsys_crypto_types.DIGESTS) ->
           string ->
           digest
    (** [find name]: get the digest [name].

        The name conventionally follows the [<uppercasestring>-<size>] format,
        e.g. "MD5-128", "SHA1-160", or "SHA2-256".
     *)
