(* $Id$ *)

(** Cryptographic digests (hashes) *)

open Netsys_types

type iana_hash_fn =
  [ `MD2 | `MD5 | `SHA_1 | `SHA_224 | `SHA_256 | `SHA_384 | `SHA_512 ]
  (** The hash functions contained in the IANA registry
      (http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml).
   *)

class type digest_ctx =
object
  method add_memory : Netsys_types.memory -> unit
    (** Add data *)

  method add_subbytes : Bytes.t -> int -> int -> unit
    (** Add data *)

  method add_substring : string -> int -> int -> unit
    (** Add data *)

  method add_tstring : tstring -> int -> int -> unit
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

  method iana_hash_fn : iana_hash_fn option
    (** Whether registered at IANA, and if so, which ID we use here *)

  method iana_name : string option
    (** The name as registered by IANA (if registered) *)

  method oid : int array option
    (** The OID (if registered) *)

  method size : int
    (** The size of the digest string in bytes *)

  method block_length : int
    (** The block length of the hash function (for HMAC) in bytes *)

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

val digest_tstring : digest -> tstring -> string
  (** Digest a string *)

val digest_bytes : digest -> Bytes.t -> string
  (** Digest a string *)

val digest_string : digest -> string -> string
  (** Digest a string *)

val digest_mstrings : digest -> Netsys_types.mstring list -> string
  (** Digest a sequence of mstrings *)


val hmac : digest -> string -> digest
    (** [hmac dg key]: returns the digest context computing the HMAC
        construction (RFC-2104).

        The key must not be longer than dg#block_length.
     *)

val iana_find : ?impl:(module Netsys_crypto_types.DIGESTS) ->
                iana_hash_fn ->
                digest
    (** [iana_find name]: get the digest [name] *)

val iana_alist : (string * iana_hash_fn) list
  (** maps the IANA name to the hash function id *)

val iana_rev_alist : (iana_hash_fn * string) list
  (** the reverse *)

val oid_alist : (int array * iana_hash_fn) list
  (** maps the OID to the hash function id *)

val oid_rev_alist : (iana_hash_fn * int array) list
  (** the reverse *)

val name_alist : (string * iana_hash_fn) list
  (** maps the OCamlnet name to the hash function id *)

val name_rev_alist : (iana_hash_fn * string) list
  (** the reverse *)

