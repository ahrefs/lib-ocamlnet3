(* $Id$ *)

(** ASN.1 support functions *)

exception Out_of_range
exception Parse_error of int (** Byte position in string *)

module Type_name : sig
  type type_name =
    | Bool
    | Integer
    | Enum
    | Real
    | Bitstring
    | Octetstring
    | Null
    | Seq
    | Set
    | OID
    | ROID
    | ObjectDescriptor
    | External
    | Embedded_PDV
    | NumericString
    | PrintableString
    | TeletexString
    | VideotexString
    | VisibleString
    | IA5String
    | GraphicString
    | GeneralString
    | UniversalString
    | BMPString
    | UTF8String
    | CharString
    | UTCTime
    | GeneralizedTime
end

module Value : sig
  type pc = Primitive | Constructed


  type value =
    | Bool of bool
    | Integer of int_value
    | Enum of int_value
    | Real of real_value
    | Bitstring of bitstring_value
    | Octetstring of string
    | Null
    | Seq of value list
    | Set of value list
    | Tagptr of tag_class * int * pc * string * int * int
    | Tag of tag_class * int * pc * value
    | OID of int array
    | ROID of int array
    | ObjectDescriptor of string
    | External of value list
    | Embedded_PDV of value list
    | NumericString of string
    | PrintableString of string
    | TeletexString of string
    | VideotexString of string
    | VisibleString of string
    | IA5String of string
    | GraphicString of string
    | GeneralString of string
    | UniversalString of string
    | BMPString of string
    | UTF8String of string
    | CharString of string
    | UTCTime of time_value
    | GeneralizedTime of time_value

   and tag_class =
     | Universal | Application | Context | Private

   and int_value
   and real_value
   and bitstring_value
   and time_value

  val get_int_str : int_value -> string
    (** Get an integer as bytes *)
  val get_int_b256 : int_value -> int array
    (** Get an integer in base 256 notation, big endian. Negative values are
        represented using two's complement (i.e. the first array element is
        >= 128). The empty array means 0.
     *)
  val get_int : int_value -> int
    (** Get an integer as [int] if representable, or raise [Out_of_range] *)
  val get_int32 : int_value -> int32
    (** Get an integer as [int32] if representable, or raise [Out_of_range] *)
  val get_int64 : int_value -> int64
    (** Get an integer as [int64] if representable, or raise [Out_of_range] *)

  val get_real_str : real_value -> string
    (** Get the byte representation of the real *)

  val get_bitstring_size : bitstring_value -> int
    (** Get the number of bits *)
  val get_bitstring_data : bitstring_value -> string
    (** Get the data. The last byte may be partial. The order of the bits
        in every byte: bit 7 (MSB) contains the first bit
     *)
  val get_bitstring_bits : bitstring_value -> bool array
    (** Get the bitstring as bool array *)

  val get_time_str : time_value -> string
    (** Get the raw time string *)
  val get_time : time_value -> Netdate.t
    (** Get the time. Notes:

        - UTCTime years are two-digit years, and
          interpreted so that 0-49 is understood as 2000-2049, and 50-99 
          is understood as 1950-1999 (as required by X.509).
        - [get_time_nsec] returns the fractional part as nanoseconds. Higher
          resolutions than that are truncated.
        - This function is restricted to the time formats occurring in DER
     *)

  val equal : value -> value -> bool
    (** Checks for equality. Notes:

          - [Tag] and [Tagptr] are considered different
          - [Tagptr] is checked by comparing the equality of the substring
          - [Set] is so far not compared as set, but as sequence (i.e. order
            matters)
     *)
end


val decode_ber :
      ?pos:int ->
      ?len:int ->
      string ->
        int * Value.value
  (** Decodes a BER-encoded ASN.1 value. Note that DER is a subset of BER,
      and can also be decoded.

      [pos] and [len] may select a substring for the decoder. By default,
      [pos=0], and [len] as large as necessary to reach to the end of the
      string.

      The function returns the number of interpreted bytes, and the value.
      It is not considered as an error if less than [len] bytes are consumed.

      The returned value represents implicitly tagged values as
      [Tagptr(class,tag,pc,pos,len)]. [pos] and [len] denote the substring
      containting the contents. Use {!Netasn1.decode_ber_contents} to
      further decode the value. You can use [Tag] to put the
      decoded value back into the tree.
   *)

val decode_ber_contents :
      ?pos:int ->
      ?len:int ->
      ?indefinite:bool ->
      string ->
      Value.pc ->
      Type_name.type_name ->
        int * Value.value
  (** Decodes the BER-encoded contents of a data field. The contents are
      assumed to have the type denoted by [type_name].

      [pos] and [len] may select a substring for the decoder. By default,
      [pos=0], and [len] as large as necessary to reach to the end of the
      string.

      If [indefinite], the extent of the contents region is considered as
      indefinite, and the special end marker is required. This is only
      allowed when [pc = Constructed].

      The function returns the number of interpreted bytes, and the value.
      It is not considered as an error if less than [len] bytes are consumed.

      You need to use this function to recursively decode tagged values.
      If you get a [Tagptr(class,tag,pc,s,pos,len)] value, it depends on the
      kind of the tag how to proceed:

      - For explicit tags just invoke {!Netasn1.decode_ber} again with
        the given [pos] and [len] parameters.
      - For implicit tags you need to know the type of the field. Now
        call {!Netasn1.decode_ber_contents} with the right type name.

      The BER encoding doesn't include whether the tag is implicit or
      explicit, so the decode cannot do by itself the right thing here.
   *)

      
val decode_ber_length : ?pos:int -> ?len:int -> string -> int
  (** Like [decode_ber], but returns only the length.

      This function skips many consistency checks.
   *)

val decode_ber_header : ?pos:int -> ?len:int -> ?skip_length_check:bool ->
                        string -> 
                        (int * Value.tag_class * Value.pc * int * int option)
  (** [let (hdr_len, tc, pc, tag, len_opt) = decode_ber_header s]:
      Decodes only the header:
       - [hdr_len] will be the length of the header in bytes
       - [tc] is the tag class
       - [pc] whether primitive or constructed
       - [tag] is the numeric tag value
       - [len_opt] is the length field, or [None] if the header selects
         indefinite length

      If [skip_length_check] is set, the function does not check whether
      the string is long enough to hold the whole data part.
   *)
