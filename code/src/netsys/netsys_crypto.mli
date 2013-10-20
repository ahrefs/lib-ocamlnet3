(* $Id$ *)

(** Cryptographic providers *)

val current_tls : unit -> (module Netsys_crypto_types.TLS_PROVIDER)
  (** Return the current TLS provider. Only available if such a provider
      is linked into the executable. Do this by calling the [init] function
      of the provider, e.g. {!Nettls_gnutls.init}.
   *)



(**/**)

(* Hidden API for providers: *)

val set_current_tls : (module Netsys_crypto_types.TLS_PROVIDER) -> unit
  (* Sets [current_tls] *)
