(* This file is included into nettls_gnutls_bindings.ml *)

exception Null_pointer
exception Error of error_code

type gnutls_credentials =
    [ `Certificate of gnutls_certificate_credentials_t
    | `Srp_client of gnutls_srp_client_credentials_t
    | `Srp_server of gnutls_srp_server_credentials_t
    | `Psk_client of gnutls_psk_client_credentials_t
    | `Psk_server of gnutls_psk_server_credentials_t
    | `Anon_client of gnutls_anon_client_credentials_t
    | `Anon_server of gnutls_anon_server_credentials_t
    ]

external gnutls_credentials_set : gnutls_session_t -> gnutls_credentials -> unit
  = "net_gnutls_credentials_set" "net_gnutls_credentials_set"

let () =
  Callback.register_exception
    "Nettls_gnutls_bindings.Null_pointer"
    Null_pointer;
  Callback.register_exception
    "Nettls_gnutls_bindings.Error"
    (Error `Success)


