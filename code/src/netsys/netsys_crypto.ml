(* $Id$ *)

let tls = ref None

let current_tls() =
  match !tls with
    | None ->
         failwith "Netsys_crypto.current_tls: No TLS provider is set"
    | Some p ->
         p

let set_current_tls p =
  tls := Some p
