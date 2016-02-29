(* $Id$ *)

(** Cryptographic providers *)

(** Users should not call functions of the providers directly. Instead, use:
     - {!Netsys_tls} for using TLS
     - {!Netsys_ciphers} for using (symmetric) ciphers
     - {!Netsys_digests} for using digests
     - {!Netx509_pubkey} and {!Netx509_pubkey_crypto} for using public-key
       ciphers
 *)

val current_tls : unit -> (module Netsys_crypto_types.TLS_PROVIDER)
  (** Return the current TLS provider. Only available if such a provider
      is linked into the executable. Do this by calling the [init] function
      of the provider, e.g. {!Nettls_gnutls.init}.
   *)

val current_tls_opt : unit -> (module Netsys_crypto_types.TLS_PROVIDER) option
  (** Same as [current_tls] but it returns [None] if TLS is unavailable *)

val current_symmetric_crypto : unit ->
                               (module Netsys_crypto_types.SYMMETRIC_CRYPTO)
  (** Returns the current provider for symmetric cryptography. This provider
      is always available, but may be empty (not implementing any ciphers).
   *)

val current_pubkey_crypto : unit ->
                            (module Netsys_crypto_types.PUBKEY_CRYPTO)
  (** Returns the current provider for public key cryptography. This provider
      is always available, but may be empty (not implementing any ciphers).
   *)

val current_digests : unit ->
                      (module Netsys_crypto_types.DIGESTS)
  (** Returns the current provider for cryptographic digests. This provider
      is always available, but may be empty (not implementing any digest).
   *)


(**/**)

(* Hidden API for providers: *)

val set_current_tls : (module Netsys_crypto_types.TLS_PROVIDER) -> unit
  (* Sets [current_tls] *)

val set_current_symmetric_crypto : (module Netsys_crypto_types.SYMMETRIC_CRYPTO)
                                     -> unit

val set_current_digests : (module Netsys_crypto_types.DIGESTS) -> unit

val set_current_pubkey_crypto : (module Netsys_crypto_types.PUBKEY_CRYPTO) ->
                                unit
