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


module Empty_symmetric_crypto : Netsys_crypto_types.SYMMETRIC_CRYPTO = struct
  type scipher = unit
  type scipher_ctx = unit
  let ciphers = []
  let find _ = raise Not_found
  let unavailable() = assert false
  let name _ = unavailable()
  let mode _ = unavailable()
  let key_lengths _ = unavailable()
  let iv_lengths _ = unavailable()
  let data_constraint _ = unavailable()
  let supports_aead _ = unavailable()
  let create _ _ = unavailable()
  let set_iv _ _ = unavailable()
  let set_header _ _ = unavailable()
  let encrypt _ _ _ = unavailable()
  let decrypt _ _ _ = unavailable()
  let mac _ = unavailable()
end


let symmetric_crypto =
  ref (module Empty_symmetric_crypto : Netsys_crypto_types.SYMMETRIC_CRYPTO)
let current_symmetric_crypto() = !symmetric_crypto
let set_current_symmetric_crypto p = symmetric_crypto := p


module Empty_digests : Netsys_crypto_types.DIGESTS = struct
  type digest = unit
  let unavailable() = assert false
  let digests = [ ]
  let name _ = unavailable()
  let size _ = unavailable()
  type digest_ctx = unit
  let create _ = unavailable()
  let add _ _ = unavailable()
  let finish _ = unavailable()
end

let digests = ref (module Empty_digests : Netsys_crypto_types.DIGESTS)
let current_digests() = !digests
let set_current_digests p = digests := p
