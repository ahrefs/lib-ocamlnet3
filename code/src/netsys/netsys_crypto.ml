(* $Id$ *)

let tls = ref None

let current_tls() =
  match !tls with
    | None ->
         failwith "Netsys_crypto.current_tls: No TLS provider is set"
    | Some p ->
         p

let current_tls_opt() = !tls

let set_current_tls p =
  tls := Some p
