(** SCRAM for HTTP (prerelease) *)

(** Implements SCRAM-SHA-256 and SCRAM-SHA-1 as described in
    https://tools.ietf.org/html/draft-ietf-httpauth-scram-auth-15

    Restarts are not yet covered.

    As long as the RFC isn't released yet, this should be considered as
    experimental work.

    {[
module SCRAM = Netmech_scram_http.Make_SCRAM(Netmech_scram_http.SHA_256)
let h = new Nethttp_client.generic_auth_handlers keys [ (module SCRAM) ]
let p = new Nethttp_client.pipeline
p # add_auth_handler h
    ]}
 *)

module type PROFILE =
  sig
    val mutual : bool
    val hash_function : Netsys_digests.iana_hash_fn
    val test_nonce : string option
  end

module Make_SCRAM(P:PROFILE) : Nethttp.HTTP_CLIENT_MECHANISM

module SHA_256 : PROFILE
(** SCRAM-SHA-256 where only the server authenticates the client *)

module SHA_256_mutual : PROFILE
(** SCRAM-SHA-256 where additionally also the client checks that the
    server knows the credentials.
 *)
