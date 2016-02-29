(** X.509 public key cryptography - keys and naming *)

(** Support for reading in public keys and retrieving the type of the key.
    This module is mostly about naming key types and algorithms.

    In the X.509 standard a public key is often part of a certificate
    and there stored in the [subjectPublicKeyInfo] field. However, "raw"
    public keys (i.e. outside certificates) are also known. In this case,
    the same representation as for [subjectPublicKeyInfo] field is chosen
    and just stored separately in a file.

    Like certificates, public keys are described by an ASN.1 syntax
    and are normally stored by applying the DER encoding rules. If
    stored in files, PEM headers for the DER encoding are common. Such
    files have a PEM header of "BEGIN PUBLIC KEY". Note that the
    header - unlike for private keys - does not indicate the type of
    key. The type is already a member of the [subjectPublicKeyInfo]
    field.

    A public key consists of three parts:
     - the OID of the type of the key
     - the parameters of the algorithm
     - the key data

    A certain type of public key can only be used with certain algorithms.
    Often, the OID for the type of the key is simply set to the OID for the
    simplest algorithm that can be used with the key. For example, RSA keys
    have the OID of the PKCS-1 encryption algorithm. However, you can use
    the same keys also with the slightly more complicated PKCS-1 signing
    algorithms.

    It depends on the algorithm whether the parameters can be changed while
    keeping the key data.

    See {!Netx509_pubkey_crypto} for functions that actually encrypt or
    sign data with the current crypto provider.
 *)

type oid = Netoid.t
  (** OIDs are just integer sequences *)

(* TODO: type pubkey_params = Pubkey_params of Netasn1.Value.value option *)

type alg_id = Alg_id of oid * Netasn1.Value.value option
    (** Algorithms are identified by an OID and OID-specific parameters.
     *)

type pubkey =
  { pubkey_type : alg_id;
    pubkey_data : Netasn1.Value.bitstring_value;
  }
  (** Public key info: the key as such plus the algorithm. This combination
      is stored in PEM files tagged with "PUBLIC KEY", and also part of X.509
      certificates.
   *)

type hash_function = [ `SHA_1 | `SHA_224 | `SHA_256 | `SHA_384 | `SHA_512 ]
type maskgen_function = [ `MGF1 of hash_function ]

#ifdef HAVE_EXTENSIVE_VARIANTS
type alg_param = ..
type alg_param +=
#else
type alg_param =
#endif
| P_PSS of hash_function * maskgen_function * int
| P_OAEP of hash_function * maskgen_function * string


type encrypt_alg = Encrypt of oid * alg_param option
  (** An algorithm that can be used for encryption. Same format as [Alg_id]
   *)

type sign_alg = Sign of oid * alg_param option
  (** An algorithm that can be used for signing. Same format as [Alg_id]
   *)

type kex_alg = Kex of oid * alg_param option
  (** An algorithm that can be used for key agreement. Same format as 
      [Alg_id]

      Remember that you can use any key agreement protocol also as public
      key mechanism: if Alice sends Bob message A based on a secret a, and Bob
      replies with message B based on a secret b, and both agree on a 
      key K=f(a,b), you can consider A as the public key and Alices's secret
      a as the private key. The message B is a parameter of
      the ciphertext (comparable to the IV in symmetric cryptography), and K
      is used as transport key (for a symmetric cipher). That's
      why the key agreement algorithms appear here.
   *)

val decode_pubkey_from_der : string -> pubkey
  (** Decodes a DER-encoded public key info structure. Note that this function
      performs only a partial check on the integrity of the data.
   *)

val encode_pubkey_to_der : pubkey -> string
  (** Encodes a public key info structure as DER *)

val read_pubkey_from_pem : Netchannels.in_obj_channel -> pubkey
  (** Reads a PEM file tagged as "PUBLIC KEY". Note that this function
      performs only a partial check on the integrity of the data. *)

type privkey = Privkey of string * string
  (** [(format,data)], using the formats: "RSA", "DSA", "DH", "EC". The
      [data] string is for the mentioned formats DER-encoded.
   *)

val read_privkey_from_pem : Netchannels.in_obj_channel -> privkey
  (** Reads a PEM file tagged as "... PRIVATE KEY". This function cannot handle
      encrypted private keys. Note that this function
      performs only a partial check on the integrity of the data.
   *)

module Key : 
sig
  (** These OIDs are used when storing public keys *)

  val rsa_key : oid            (** alias PKCS-1. RFC-3279, RFC-3447 *)
  val rsassa_pss_key : oid     (** RSASSA-PSS. RFC-4055, RFC-3447 *)
  val rsaes_oaep_key : oid     (** RSAES-OAEP. RFC-4055, RFC-3447 *)
  val dsa_key : oid            (** DSA. RFC-3279 *)
  val dh_key : oid             (** DH. RFC-3279 *)
  val ec_key : oid             (** All EC variants (ECDSA, ECDH, ECMQV). RFC-3279 *)
  val ecdh_key : oid           (** EC restricted to ECDH (RFC-5480) *)
  val ecmqv_key : oid          (** EC restricted to ECMQV (RFC-5480) *)
  val kea_key : oid            (** KEA. RFC-3279 *)
  val eddsa_key : oid          (** EDDSA. draft-josefsson-pkix-eddsa *)
                     
  val catalog : (string * string list * string * oid) list
  (** [(name, aliases, privkey_name, oid)] *)

  val private_key_format_of_key : oid -> string
    (** Get the type of private key for a public key OID *)

  (** It is possible to derive public keys from [rsa_key] format so that they
      can be used with the RSASSA-PSS and RSAES-OAEP algorithms:
   *)

  val create_rsassa_pss_alg_id : 
        hash_function:hash_function ->
        maskgen_function:maskgen_function ->
        salt_length:int ->
        unit ->
          alg_id
    (** [create_rsassa_pss_alg_id ... ]: Creates an algorithm identifier
        for RSASSA-PSS.
     *)

  val create_rsassa_pss_key : 
        hash_function:hash_function ->
        maskgen_function:maskgen_function ->
        salt_length:int ->
        pubkey ->
          pubkey
    (** Derives a public key that is specific for RSASSA-PSS from an RSA
        public key.
     *)

  val create_rsaes_oaep_alg_id :
        hash_function:hash_function ->
        maskgen_function:maskgen_function ->
        psource_function:string ->
        unit ->
          alg_id
    (** [create_rsaep_oaep_alg_id ... ]: Creates an algorithm identifier
        for RSAES-OAEP.
     *)

  val create_rsaes_oaep_key :
        hash_function:hash_function ->
        maskgen_function:maskgen_function ->
        psource_function:string ->
        pubkey ->
          pubkey
    (** Derives a public key that is specific for RSAES-OAEP from an RSA
        public key.
     *)
end


module Encryption :
sig
  (** These algorithms are used for encryption/decryption *)

  val rsa : encrypt_alg               (** alias RSAES-PKCS1-v1_5 *)
  val rsaes_oaep : hash_function:hash_function ->
                   maskgen_function:maskgen_function ->
                   psource_function:string ->
                   encrypt_alg        (** RSAES-OAEP *)

  val catalog : (string * string list * encrypt_alg * oid) list
    (** [(name, aliases, oid, pubkey_oid)] *) 

  val encrypt_alg_of_pubkey : pubkey -> encrypt_alg
    (** Normally use the algorithm that is present in the public key *)

  val alg_id_of_encrypt_alg : encrypt_alg -> alg_id
    (** Get the alg_id of an encryption alg *)

  val key_oid_of_encrypt_alg : encrypt_alg -> oid
    (** The OID public keys need to have *)
end


module Keyagreement :
sig
  val dh : kex_alg                (** DH *)
  val ec : kex_alg                (** ECDH using unrestricted keys *)
  val ecdh : kex_alg              (** ECDH *)
  val ecmqv : kex_alg             (** ECMQV *)
  val kea : kex_alg               (** KEA *)

  val catalog : (string * string list * kex_alg * oid) list
    (** [(name, aliases, oid, pubkey_oid)] *) 

  val alg_id_of_kex_alg : kex_alg -> alg_id
    (** Get the alg_id of a key agreement alg *)

  val key_oid_of_kex_alg : kex_alg -> oid
    (** The OID public keys need to have *)
end


module Signing :
sig
  (** These algorithms are used for signing *)
  val rsa_with_sha1 : sign_alg       (** RSASSA-PKCS1-v1_5 *)
  val rsa_with_sha224 : sign_alg
  val rsa_with_sha256 : sign_alg
  val rsa_with_sha384 : sign_alg
  val rsa_with_sha512 : sign_alg
  val rsassa_pss: hash_function:hash_function ->
                  maskgen_function:maskgen_function ->
                  salt_length:int ->
                  sign_alg           (** RSASSA-PSS *)
  val dsa_with_sha1 : sign_alg       (** DSA *)
  val dsa_with_sha224 : sign_alg
  val dsa_with_sha256 : sign_alg
  val ecdsa_with_sha1 : sign_alg     (** ECDSA *)
  val ecdsa_with_sha224 : sign_alg
  val ecdsa_with_sha256 : sign_alg
  val ecdsa_with_sha384 : sign_alg
  val ecdsa_with_sha512 : sign_alg
  val eddsa : sign_alg               (** EDDSA. draft-josefsson-pkix-eddsa *)

  val catalog : (string * string list * sign_alg * oid) list
    (** [(name, aliases, oid, container_oid)] *) 

  val alg_id_of_sign_alg : sign_alg -> alg_id
    (** Get the alg_id of a sign alg *)

  val key_oid_of_sign_alg : sign_alg -> oid
    (** The OID public keys need to have *)
end
