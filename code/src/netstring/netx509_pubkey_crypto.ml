open Netx509_pubkey
open Printf

exception Unsupported_algorithm of Netoid.t

let is_encryption_supported (Encrypt oid) =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  List.mem oid PK.supported_x509

let is_signing_supported (Sign oid) =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  List.mem oid PK.supported_x509

let encode_alg_params_to_der pubkey =
  let Pubkey(_, params) = pubkey.pubkey_type in
  match params with
    | None -> None
    | Some v ->
        let b = Netbuffer.create 80 in
        ignore(Netasn1_encode.encode_ber b v);
        Some(Netbuffer.contents b)

let encrypt (Encrypt oid) pubkey data =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  let Pubkey(puboid,pubparams) = pubkey.pubkey_type in
  let expected_puboid = Encryption.pubkey_oid_of_encrypt_alg (Encrypt oid) in
  if expected_puboid <> puboid then
    failwith
      "Netx509_pubkey_crypto.encrypt: the algorithm is incompatible \
       with the public key";
  let params_der =
    encode_alg_params_to_der pubkey in
  let pk_alg =
    PK.algorithm_x509 oid params_der in
  let pk_pubkey =
    PK.import_public_key_x509 (Netx509_pubkey.encode_pubkey_to_der pubkey) in
  PK.encrypt pk_alg pk_pubkey data

let decrypt (Encrypt oid) pubkey privkey data =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  let Pubkey(puboid,pubparams) = pubkey.pubkey_type in
  let Privkey(privformat,privdata) = privkey in
  let expected_puboid = Encryption.pubkey_oid_of_encrypt_alg (Encrypt oid) in
  if expected_puboid <> puboid then
    failwith
      "Netx509_pubkey_crypto.decrypt: the algorithm is incompatible \
       with the public key";
  let expected_privformat = Key.private_key_format_of_key puboid in
  if expected_privformat <> privformat then
    failwith
      "Netx509_pubkey_crypto.decrypt: the private key is incompatible \
       with the public key";
  let params_der =
    encode_alg_params_to_der pubkey in
  let pk_alg =
    PK.algorithm_x509 oid params_der in
  let pk_privkey =
    PK.import_private_key_x509 (privformat,privdata) in
  PK.decrypt pk_alg pk_privkey data

let verify (Sign oid) pubkey plaintext signature =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  let Pubkey(puboid,pubparams) = pubkey.pubkey_type in
  let expected_puboid = Signing.pubkey_oid_of_sign_alg (Sign oid) in
  if expected_puboid <> puboid then
    failwith
      "Netx509_pubkey_crypto.verify: the algorithm is incompatible \
       with the public key";
  let params_der =
    encode_alg_params_to_der pubkey in
  let pk_alg =
    PK.algorithm_x509 oid params_der in
  let pk_pubkey =
    PK.import_public_key_x509 (Netx509_pubkey.encode_pubkey_to_der pubkey) in
  PK.verify pk_alg pk_pubkey plaintext signature

let sign (Sign oid) pubkey privkey plaintext =
  let module PK = (val Netsys_crypto.current_pubkey_crypto()) in
  let Pubkey(puboid,pubparams) = pubkey.pubkey_type in
  let Privkey(privformat,privdata) = privkey in
  let expected_puboid = Signing.pubkey_oid_of_sign_alg (Sign oid) in
  if expected_puboid <> puboid then
    failwith
      "Netx509_pubkey_crypto.sign: the algorithm is incompatible \
       with the public key";
  let expected_privformat = Key.private_key_format_of_key puboid in
  if expected_privformat <> privformat then
    failwith
      "Netx509_pubkey_crypto.sign: the private key is incompatible \
       with the public key";
  let params_der =
    encode_alg_params_to_der pubkey in
  let pk_alg =
    PK.algorithm_x509 oid params_der in
  let pk_privkey =
    PK.import_private_key_x509 (privformat,privdata) in
  PK.sign pk_alg pk_privkey plaintext
