(* $Id$ *)

(** X509 certificates *)

type oid = Netoid.t
  (** OIDs are just integer sequences *)

class type distinguished_name =
object
  method name : (oid * Netasn1.Value.value) list list
    (** This is the raw version of the DN: a sequence of relative DNs,
        and a relative DN is a set of (type,value) pairs. The types are
        things like cn, country, organization, ...
     *)
  method eq_name : (oid * Netasn1.Value.value) list list
    (** The name normalized for equality comparisons. In particular,
        PrintableString values are converted to uppercase, as well
        as emailAddress attributes. Also, the inner list is sorted by
        [oid].
     *)
  method string : string
    (** The DN as string (RFC 4514) *)
  method eq_string : string
    (** The [eq_name] converted to string *)
end



class type x509_certificate =
object
  method subject : distinguished_name
    (** The DN of the subject *)
  method subject_unique_id : Netasn1.Value.bitstring_value option
    (** The unique ID of the subject *)
  method issuer : distinguished_name
    (** The DN of the issuer *)
  method issuer_unique_id : Netasn1.Value.bitstring_value option
    (** The unique ID of the issuer *)
  method version : int
    (** The "version" field, 1 to 3 *)
  method serialNumber : string
    (** The "serialNumber" field *)
  method valid_not_before : float
    (** Activation time as seconds since the epoch ("notBefore" field) *)
  method valid_not_after : float
    (** Expiration time as seconds since the epoch ("notAfter" field) *)
  method signature : string
    (** The signature *)
  method signature_algorithm : oid * Netasn1.Value.value
    (** The algorithm of the signature (OID, and algorithm-specific parameters)
     *)
  method public_key : Netasn1.Value.bitstring_value
    (** The subject's public key *)
  method public_key_algorithm : oid  * Netasn1.Value.value
    (** The algorithm of the public key (OID, and algorithm-specific
         parameters)
     *)
  method extensions : (oid * string * bool) list
    (** Extensions (version 3 certificates) as triples [(oid, data, critical)].
        OIDs can occur several times.
     *)
end

(** OIDs for DN attribute types *)

module DN_attributes : sig
  (** Object identifiers used in distinguished names *)

  (** This module is an implementation of {!Netdn.AT_LOOKUP}, and can be
      used with the parser/printer in {!Netdn}.
   *)

  (** Attibute types *)

  val at_name : oid
  val at_surname : oid
  val at_givenName : oid
  val at_initials : oid
  val at_generationQualifier : oid
  val at_commonName : oid
  val at_localityName : oid
  val at_stateOrProvinceName : oid
  val at_organizationName : oid
  val at_organizationalUnitName : oid
  val at_title : oid
  val at_dnQualifier : oid
  val at_countryName : oid
  val at_serialNumber : oid
  val at_pseudonym : oid
  val at_domainComponent : oid
  val at_emailAddress : oid

  val attribute_types : (oid * string * string list) list
    (** The above types in the format [(oid, full_name, short_names)] *)

  val lookup_attribute_type_by_oid : oid -> string * string list
    (** Looks the OID up, and returns [(full_name, short_names)].
        May raise [Not_found].
     *)

  val lookup_attribute_type_by_name : string -> oid * string * string list
    (** Looks the name up, which can either be a full name or a short name.
        Returns the whole triple [(oid, full_name, short_names)], or
        raises [Not_found].
     *)
end

(** Parsers *)

class x509_dn_from_ASN1 : Netasn1.Value.value -> distinguished_name
  (** Returns the DN object for a [Name] entity *)

class x509_dn_from_string : string -> distinguished_name
  (** Returns the DN object for an RFC 4514-encoded string *)

class x509_certificate_from_ASN1 : Netasn1.Value.value -> x509_certificate
  (** Parses the passed ASN.1 value and returns the certificate object *)

class x509_certificate_from_DER : string -> x509_certificate
  (** Parses the passed DER string and returns the certificate object *)

(*
(** Helpers for X.509 certificates *)

type key_usage_flag =
  [ `Digital_signature
  | `Non_repudiation
  | `Key_encipherment
  | `Data_encipherment
  | `Key_agreement
  | `Key_cert_sign
  | `Crl_sign
  | `Encipher_only
  | `Decipher_only
  ]

val parse_key_usage : string -> key_usage_flag list

val get_key_usage : Netsys_crypto_types.x509_certificate -> key_usage_flag list
  (** Parses the "key_usage" extension as a list of flags. If there is no
      such field in the certificate, the empty list is returned.
   *)

type general_name =
  [ `Other_name
  | `Rfc822_name
  | `DNS_name
  | `X400_address
  | `Directory_name
  | `Edi_party_name
  | `Uniform_resource_identifier
  | `IP_address
  | `Registered_ID
  ]

val parse_alt_name : string -> general_name * string

val get_subject_alt_names :
      Netsys_crypto_types.x509_certificate ->
        (general_name * string * bool) list
  (** Parses the "Subject alternative name" extensions as triples
      [(name_type, name, critical)].
   *)

val get_issuer_alt_names :
      Netsys_crypto_types.x509_certificate ->
        (general_name * string) list
  (** Parses the "Issuer alternative name" extensions *)

val get_basic_constraint : 
      Netsys_crypto_types.x509_certificate -> bool * int option * bool
  (** Parses the "basic constraint" extension as [(ca, path_len, critical)] *)

type ext_key_usage =
    [ `Server_auth | `Client_auth | `Code_signing | `Email_protection
      | `Time_stamping ]

val parse_ext_key_usage : string -> ext_key_usage_flag list

val get_ext_key_usage :
  Netsys_crypto_types.x509_certificate -> ext_key_usage_flag list
 *)
