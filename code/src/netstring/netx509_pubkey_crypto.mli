(** X.509 public key cryptography - wrappers *)

(** This module uses the current cryptography provider to actually
    run operations.

    Note that typically not all encryption and signing schemes are implemented.
    For instance, GnuTLS only provides those schemes that are needed for TLS
    (so far RSA for encryption, and RSA/DSA/ECDSA for signing). Also note
    that we require GnuTLS-3.0 or newer for public key cryptography.
 *)

exception Unsupported_algorithm of Netoid.t
  (** Raises if the crypto backend does not support an algorithm *)

val is_encryption_supported : Netx509_pubkey.encrypt_alg -> bool
  (** Whether this algorithm is supported *)

val is_signing_supported : Netx509_pubkey.sign_alg -> bool
  (** Whether this algorithm is supported *)

val encrypt : Netx509_pubkey.encrypt_alg ->
              Netx509_pubkey.pubkey ->
              string -> string
  (** Encrypt the string.

      Note that length restrictions apply, depending on the algorithm and
      the bit size of the key. For instance, with a 2048-bit RSA key you
      can at most encrypt 245 bytes.
   *)

val decrypt : Netx509_pubkey.encrypt_alg ->
              Netx509_pubkey.privkey ->
              string -> string
  (** Decrypt the string *)

val verify : Netx509_pubkey.sign_alg ->
             Netx509_pubkey.pubkey ->
             string -> string -> bool
  (** [verify alg key plaintext signature]: Checks the signature, and returns
      [true] on success.
   *)

val sign : Netx509_pubkey.sign_alg ->
           Netx509_pubkey.privkey ->
           string -> string
  (** [let signature = sign alg key plaintext]: Creates a signature.

      Unlike for encryption there is no length restriction.
   *)


(** Example: Using RSA for encryption

    First create RSA keys:

{[
openssl genrsa -out rsa.key 2048
openssl rsa -in rsa.key -pubout -out rsa.pub
]}

    Read the keys in:

{[
let priv_ch = Netchannels.input_channel(open_in "rsa.key")
let priv = Netx509_pubkey.read_privkey_from_pem priv_ch
let () = priv_ch#close_in()

let pub_ch = Netchannels.input_channel(open_in "rsa.pub")
let pub = Netx509_pubkey.read_pubkey_from_pem pub_ch
let () = pub_ch#close_in()
]}

   Encrypt something:

{[
let () = Nettls_gnutls.init()
let e = encrypt Netx509_pubkey.Encryption.rsa pub "secret"
]}

   Decrypt:

{[
let d = decrypt Netx509_pubkey.Encryption.rsa priv e
]}

Note that encryption with public keys is restricted to very short
messages (e.g. 245 bytes for a 2048 bits RSA key). Typically,
only a random second key is encrypted, and the second key is
used with a symmetric cipher.
 *)
