(* $Id$ *)

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


module Make_TLS (Exc:Netsys_crypto_types.TLS_EXCEPTIONS) : GNUTLS_PROVIDER
  (** The implementation of TLS backed by GnuTLS, here for an arbitrary
      TLS_EXCEPTIONS module
   *)

module TLS : GNUTLS_PROVIDER
  (** The implementation of TLS backed by GnuTLS, here using {!Netsys_types}
      as TLS_EXCEPTIONS module
   *)

val tls : (module GNUTLS_PROVIDER)
  (** The implementation of TLS backed by GnuTLS, as value *)

val endpoint : TLS.endpoint -> (module GNUTLS_ENDPOINT)
  (** Wraps an endpoint *)

val downcast : (module Netsys_crypto_types.TLS_PROVIDER) -> 
                 (module GNUTLS_PROVIDER)
  (** Attempts a downcast, or raises [Not_found] *)

val init : unit -> unit
  (** Ensure that GnuTLS is initialized *)
