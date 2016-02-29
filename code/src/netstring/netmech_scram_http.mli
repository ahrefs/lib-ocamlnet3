(** SCRAM for HTTP (prerelease) *)

(** Implements SCRAM-SHA-256 and SCRAM-SHA-1 as described in
    https://tools.ietf.org/html/draft-ietf-httpauth-scram-auth-15

    Restarts are not yet covered.

    As long as the RFC isn't released yet, this should be considered as
    experimental work.
 *)

module type PROFILE =
  sig
    val mutual : bool
    val hash_function : Netsys_digests.iana_hash_fn
    val test_nonce : string option
  end

module Make_SCRAM(P:PROFILE) : Nethttp.HTTP_CLIENT_MECHANISM
