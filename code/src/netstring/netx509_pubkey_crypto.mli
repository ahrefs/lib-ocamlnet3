(** X.509 public key cryptography - wrappers *)

(** This module uses the current cryptography provider to actually
    run operations.

    Note that typically not all encryption and signing schemes are implemented.
    For instance, GnuTLS only provides those schemes that are needed for TLS.
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
