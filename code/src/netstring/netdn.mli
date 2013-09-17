(* $Id$ *)

(** X.500 distinguished names *)

type oid = Netoid.t

type dn = (oid * Netasn1.Value.value) list list
  (** This is the raw version of the DN: a sequence of relative DNs,
      and a relative DN is a set of (type,value) pairs. The types are
      things like cn, country, organization, ...
   *)


module type AT_LOOKUP = sig
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


module type DN_string = sig
  (** For a given attribute lookup module [L] this module provides parser
      and printer for distinguished names in string format (RFC 4514).

      This implementation is restricted to attributes using the ASN.1
      types [PrintableString], [TeletexString], [IA5String],
      [UniversalString], [BMPString], and [UTF8String]. It is not
      possible to parse hexencoded strings ('#' notation).

      (NB. We'd need a generic BER printer for supporting this.)
   *)

  val parse : string -> dn
    (** Parses the string (or fails). The string must use UTF-8 encoding. *)

  val print : dn -> string
    (** Prints the DN (cannot fail), using UTF-8 encoding *)
  end


module DN_string_generic (L : AT_LOOKUP) : DN_string
  (** For a given attribute lookup module [L] this module provides parser
      and printer for distinguished names in string format (RFC 4514).
   *)


(**/**)

val directory_string_from_ASN1 : Netasn1.Value.value -> string
  (* See Netx509, where this function is exported officially *)
