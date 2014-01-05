(* $Id$ *)

(** X.509 certificates *)

(** This module defines a parser for X.509 certificates in Internet
    context (RFC 5280). The basic structure is implemented, and there
    are also parsers for the most needed extensions.

    There are several involved formats:
     - [ASN.1] is the language in which the certificate format is described.
       When we refer here to ASN.1 we mean tagged values as defined by
       {!Netasn1.Value.value}.
     - [DER] is the common binary encoding for ASN.1 values in this context.
       [DER] is a subset of [BER] (which is implemented by
       {!Netasn1.decode_ber}). The encoding of ASN.1 values in [BER] is
       ambiguous, and [DER] specifies the variant to use in order to get
       a "distinguished" encoding (that's what the "D" stands for), which
       is needed to get unique digital signatures.
     - [PEM] is a set of standards for "privacy enhanced mail". The
       "PEM encoding" of certificates is simply BASE-64 of [DER].
 *)

type oid = Netoid.t
  (** OIDs are just integer sequences *)

(** Directory names are also known as distinguished names. These are
    the o=foo,ou=foounit,c=country strings that are used to name
    certificates.
 *)
class type directory_name =
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


(** An X.509 certificate in decoded form. The is only the public part, i.e.
    it includes only the various descriptive fields, the public key, and
    the signature by the issuer.
 *)
class type x509_certificate =
object
  method subject : directory_name
    (** The DN of the subject *)
  method subject_unique_id : Netasn1.Value.bitstring_value option
    (** The unique ID of the subject *)
  method issuer : directory_name
    (** The DN of the issuer *)
  method issuer_unique_id : Netasn1.Value.bitstring_value option
    (** The unique ID of the issuer *)
  method version : int
    (** The "version" field, 1 to 3 *)
  method serial_number : string
    (** The "serialNumber" field *)
  method valid_not_before : float
    (** Activation time as seconds since the epoch ("notBefore" field) *)
  method valid_not_after : float
    (** Expiration time as seconds since the epoch ("notAfter" field) *)
  method signature : Netasn1.Value.bitstring_value
    (** The signature *)
  method signature_algorithm : oid * Netasn1.Value.value option
    (** The algorithm of the signature (OID, and algorithm-specific parameters)
     *)
  method public_key : Netasn1.Value.bitstring_value
    (** The subject's public key *)
  method public_key_algorithm : oid  * Netasn1.Value.value option
    (** The algorithm of the public key (OID, and algorithm-specific
         parameters)
     *)
  method extensions : (oid * string * bool) list
    (** Extensions (version 3 certificates) as triples [(oid, data, critical)].
        OIDs can occur several times.
     *)
end

(** {2 OIDs for DN attribute types} *)

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
  val at_uid : oid

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


(** {2 Distinguished names} *)

module X509_DN_string : Netdn.DN_string
  (** Parser/printer for distnguished names as they may occur in X.509
      certificates
   *)
 
val lookup_dn_ava : directory_name -> oid -> Netasn1.Value.value
  (** Find the first relative DN setting this OID (or [Not_found]) *)

val lookup_dn_ava_utf8 : directory_name -> oid -> string
  (** Same as [lookup_dn_ava], but additionally converts the value to UTF-8 *)


(** {2 Parsers} *)

class x509_dn_from_ASN1 : Netasn1.Value.value -> directory_name
  (** Returns the DN object for a [Name] entity *)

class x509_dn_from_string : string -> directory_name
  (** Returns the DN object for an RFC 4514-encoded string *)

class x509_certificate_from_ASN1 : Netasn1.Value.value -> x509_certificate
  (** Parses the passed ASN.1 value and returns the certificate object *)

class x509_certificate_from_DER : string -> x509_certificate
  (** Parses the passed DER string and returns the certificate object *)


(** {2 Extensions} *)

(** Extensions are identified by an OID (found in the following [CE]
    module), and the value is a DER-encoded ASN.1 value. The parse_*
    functions take this DER-encoded value and decode them. E.g. get
    the "authority key identifier":

 {[
  let _, aki_der, _ = 
    List.find
      (fun (oid,_,_) -> oid = CE.ce_authority_key_identifier) 
      cert#extensions in
  let aki =
    parse_authority_key_identifier aki_der
 ]}

   Or use [find_extension], as defined below.

   Note that we don't have parsers for all extensions.
 *)

module CE : sig
  (** The OIDs of the extensions in RFC 5280 *)

  val ce_authority_key_identifier : oid
  val ce_subject_key_identifier : oid
  val ce_key_usage : oid
  val ce_certificate_policies : oid
  val ce_any_policy : oid
  val ce_policy_mappings : oid
  val ce_subject_alt_name : oid
  val ce_issuer_alt_name : oid
  val ce_subject_directory_attributes : oid
  val ce_basic_constraints : oid
  val ce_name_constraints : oid
  val ce_policy_constraints : oid
  val ce_ext_key_usage : oid
  val ce_crl_distribution_points : oid
  val ce_inhibit_any_policy : oid
  val ce_freshest_crl : oid
  val ce_authority_info_access : oid
  val ce_subject_info_access : oid

  val certificate_extensions : (oid * string) list
   (** All the above listed OIDs with their string names (useful for
       displaying extension types)
    *)
 end


exception Extension_not_found of oid


val find_extension :
       oid ->
       (oid * string * bool) list ->
         string * bool
  (** [find_extension] is designed to be applied to the result of the
      [extensions] method of {!Netx509.x509_certificate}:

      {[
  let (data, critical) =
    find_extension CE.ce:authority_key_identifier cert#extensions
      ]}

      It returns the undecoded data string, and the critical flag.

      Raises [Extension_not_found] if there is no such extension.
   *)

val check_critical_exts :
      oid list ->
      (oid * string * bool) list ->
        bool
  (** [check_critical_exts list exts]: When an extension is flagged
      as critical, it must be processed by the communication endpoint.
      If there is a critical extension that cannot be processed, this is
      an error. This function checks whether there are any critical
      extensions in [exts] beyond those in [list], and returns [true]
      in this case.

      Use this in software as:
  {[
  let unprocessed_critical =
    check_critical_exts
       [ CE.ce_basic_constraints ]
       cert#extensions
  ]}

     and pass the list of all extension OIDs you actually process. 
     You should raise an error if [unprocessed_critical] is true.
   *)


type general_name =
  [ `Other_name of oid * Netasn1.Value.value
  | `Rfc822_name of string
  | `DNS_name of string
  | `X400_address of Netasn1.Value.value
  | `Directory_name of directory_name
  | `Edi_party_name of string option * string
  | `Uniform_resource_identifier of string 
  | `IP_address of Unix.socket_domain * Unix.inet_addr * Unix.inet_addr
  | `Registered_ID of oid
  ]
  (** General names:
      - [`Other_name(oid, value)]: the [oid] determines the extension name
        format
      - [`Rfc822_name n]: an email address [n] (ASCII encoded)
      - [`DNS_name n]: an Internet domain [n] (ASCII encoded - no
        internationalization)
      - [`X400_address v]: an X.400 address, which is not decoded here and
        just given as unparsed ASN.1 value [v]
      - [`Directory_name n]: a directory name [n] (i.e. a name using the
        syntax of distinguished names)
      - [`Edi_party_name(assigner,party)], both names as UTF-8
      - [`Uniform_resource_identifier uri]: this [uri] (ASCII-encoded,
        no internationalization)
      - [`IP_address(dom,addr,mask)]: the address with mask
      - [`Registered oid]: a symbolical pre-registered name known under [oid]
   *)

type authority_key_identifier =
    { aki_key_identifier : string option;
      aki_authority_cert_issuer : general_name list;
      aki_authority_cert_serial_number : string option;
    }

val parse_authority_key_identifier : string -> authority_key_identifier

val parse_subject_key_identifier : string -> string
  (** Returns the key identifier directly *)

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

val parse_subject_alt_name : string -> general_name list

val parse_issuer_alt_name : string -> general_name list

val parse_subject_directory_attributes : string -> 
                                         (oid * Netasn1.Value.value list) list

val parse_basic_constraints : string -> bool * int option

type ext_key_usage_flag =
    [ `Server_auth
    | `Client_auth
    | `Code_signing
    | `Email_protection
    | `Time_stamping
    | `OCSP_signing
    | `Unknown
    ]
val parse_ext_key_usage : string -> (oid * ext_key_usage_flag) list
  (** Returns the OID as array, and as decoded flag *)

(** Key purpose IDs as returned by [parse_ext_key_usage] *)
module KP : sig
  val kp_server_auth : oid
  val kp_client_auth : oid
  val kp_code_signing : oid
  val kp_email_protection : oid
  val kp_time_stamping : oid
  val kp_ocsp_signing : oid

  val ext_key_purposes : (oid * ext_key_usage_flag * string) list
end

type authority_access_description_flag =
  [ `CA_issuers
  | `OCSP
  | `Unknown
  ]

type subject_access_description_flag =
  [ `CA_repository
  | `Time_stamping
  | `Unknown
  ]

type access_description_flag =
  [ authority_access_description_flag | subject_access_description_flag ]

val parse_authority_info_access : string -> 
                (oid * authority_access_description_flag * general_name) list
val parse_subject_info_access : string -> 
                (oid * subject_access_description_flag * general_name) list

module AD : sig
  val ad_ca_issuers : oid
  val ad_ocsp : oid
  val ad_ca_repository : oid
  val ad_time_stamping : oid

  val access_descriptions : (oid * access_description_flag * string) list
end


(** Generic parsers *)

val general_name_from_ASN1 : Netasn1.Value.value -> general_name
  (** Parses the general_name structure *)

val general_names_from_ASN1 : Netasn1.Value.value -> general_name list
  (** Parse a sequence of general names *)

val directory_string_from_ASN1 : Netasn1.Value.value -> string
  (** Returns the directory_string as UTF-8 *)

val attribute_from_ASN1 : Netasn1.Value.value -> oid * Netasn1.Value.value list
  (** Parses an attribute *)

val attributes_from_ASN1 : Netasn1.Value.value -> 
                             (oid * Netasn1.Value.value list) list
  (** Parses a sequence of attributes *)
