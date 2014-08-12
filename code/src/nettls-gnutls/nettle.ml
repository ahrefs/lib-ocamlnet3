(* This file is included into nettls_nettle_bindings.ml *)

exception Null_pointer = Nettls_gnutls_bindings.Null_pointer

let () =
  Callback.register_exception
    "Nettls_nettle_bindings.Null_pointer"
    Null_pointer
