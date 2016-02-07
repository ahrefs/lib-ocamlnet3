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
  let block_constraint _ = unavailable()
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
  let find _ = raise Not_found
  let name _ = unavailable()
  let size _ = unavailable()
  let block_length _ = unavailable()
  type digest_ctx = unit
  let create _ = unavailable()
  let add _ _ = unavailable()
  let finish _ = unavailable()
end

let digests = ref (module Empty_digests : Netsys_crypto_types.DIGESTS)
let current_digests() = !digests
let set_current_digests p = digests := p


module Empty_pubkey_crypto : Netsys_crypto_types.PUBKEY_CRYPTO = struct
  type public_key = unit
  type private_key = unit
  type pin_callback = unit
  type algorithm = unit
  type x509_private_key = string * string

  let unavailable() = failwith "No registered provider for pubkey crypto"
  let supported_x509 = []
  let algorithm_x509 _ _ = unavailable()
  let import_public_key_x509 _ = unavailable()
  let import_public_key_uri _ = unavailable()
  let import_public_key_uri_with_pin _ _ = unavailable()
  let import_private_key_x509 _ = unavailable()
  let import_private_key_uri _ = unavailable()
  let import_private_key_uri_with_pin _ _ = unavailable()
  let import_public_key_from_private _ = unavailable()
  let simple_pin_callback _ = ()
  let encrypt _ _ _ = unavailable()
  let decrypt _ _ _ = unavailable()
  let verify _ _ _ _ = false
  let sign _ _ _ = unavailable()
end

let pubkey_crypto =
  ref (module Empty_pubkey_crypto : Netsys_crypto_types.PUBKEY_CRYPTO)
let current_pubkey_crypto() = !pubkey_crypto
let set_current_pubkey_crypto p = pubkey_crypto := p
