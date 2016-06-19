(* $Id$ *)

(** GnuTLS *)

(**
{b OPAM users}: Note that the OPAM package for OCamlnet does not
build with GnuTLS support by default. The trigger for this is the presence
of the [conf-gnutls] OPAM package, i.e. do [opam install conf-gnutls]
to include the [nettls-gnutls] library in a rebuild.
 *)


module type GNUTLS_PROVIDER =
  sig
    include Netsys_crypto_types.TLS_PROVIDER

    val gnutls_session : endpoint -> Nettls_gnutls_bindings.gnutls_session_t
      (** Get the [gnutls_session] of the endpoint *)

    val gnutls_credentials : credentials -> 
                               Nettls_gnutls_bindings.gnutls_credentials
      (** Get the [gnutls_credentials] of the generic credentials *)
  end


module type GNUTLS_ENDPOINT =
  sig
    module TLS : GNUTLS_PROVIDER
    val endpoint : TLS.endpoint
  end


val make_tls : (module Netsys_crypto_types.TLS_EXCEPTIONS) ->
               (module GNUTLS_PROVIDER)
  (** The implementation of TLS backed by GnuTLS, here for an arbitrary
      TLS_EXCEPTIONS module
   *)

module GNUTLS : GNUTLS_PROVIDER
  (** The implementation of TLS backed by GnuTLS, here using {!Netsys_types}
      as TLS_EXCEPTIONS module
   *)

module TLS : Netsys_crypto_types.TLS_PROVIDER
  (** Same as [GNUTLS], but without the extra [gnutls_*] functions *)


val gnutls : (module GNUTLS_PROVIDER)
  (** The implementation of TLS backed by GnuTLS, as value *)

val tls : (module Netsys_crypto_types.TLS_PROVIDER)
  (** The implementation of TLS backed by GnuTLS, as value *)

val endpoint : GNUTLS.endpoint -> (module GNUTLS_ENDPOINT)
  (** Wraps an endpoint *)

val downcast : (module Netsys_crypto_types.TLS_PROVIDER) -> 
                 (module GNUTLS_PROVIDER)
  (** Attempts a downcast, or raises [Not_found] *)

val downcast_endpoint : (module Netsys_crypto_types.TLS_ENDPOINT) -> 
                        (module GNUTLS_ENDPOINT)
  (** Attempts a downcast, or raises [Not_found] *)

module Symmetric_crypto : Netsys_crypto_types.SYMMETRIC_CRYPTO
  (** Symmetric cryptography as provided by GnuTLS and its helper library
      Nettle
   *)

module Digests : Netsys_crypto_types.DIGESTS
  (** Cryptographic digests *)

val init : unit -> unit
  (** Ensure that GnuTLS is initialized *)
