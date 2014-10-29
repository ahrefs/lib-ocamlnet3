(* $Id$ *)

(** Support functions for GSS-API *)

open Netsys_gssapi

(** {2 Encodings} *)
val oid_to_der : oid -> string
val der_to_oid : string -> int ref -> oid
  (** Convert OID's to/from DER. [der_to_oid] takes a cursor as second arg.
   *)

val oid_to_der_value : oid -> string
val der_value_to_oid : string -> int ref -> int -> oid
  (** Convert OID's to/from DER. This variant does not include the header
      (hex 06 plus length). [der_value_to_oid] takes a cursor and the length
      in bytes.
   *)


val wire_encode_token : oid -> token -> string
val wire_decode_token : string -> int ref -> oid * token
  (** Encode tokens as described in section 3.1 of RFC 2078. This is usually
      only done for the initiating token.
   *)

val encode_exported_name : oid -> string -> string
val decode_exported_name : string -> int ref -> oid * string
  (** Encode names as described in section 3.2 of RFC 2078 *)

val gs2_encode_saslname : string -> string
val gs2_decode_saslname : string -> string
  (** Encodes "," and "=" characters, and forbids null bytes, and checks
      whether the names are UTF-8-encoded
      (as required for the "saslname" production in section 4 of
      RFC 5801). Fails if something is wrong.
   *)


val parse_kerberos_name : string -> string list * string option
  (** [let (name_components, realm_opt) = parse_kerberos_name s]:
      Returns the slash-separated name components as [name_components],
      and the realm following "@" as [realm_opt].

      Fails on parse error.
   *)

(** {2 Create tokens} *)

(** Format of the tokens: see RFC 4121 *)

val create_mic_token : sent_by_acceptor:bool ->
                       acceptor_subkey:bool ->
                       sequence_number:int64 ->
                       get_mic:(message -> string) ->
                       message:message ->
                         string
  (** Create a MIC token:

      - [sent_by_acceptor]: whether this token comes from the acceptor
      - [acceptor_subkey]: see RFC
      - [sequence_number]: a sequence number
      - [get_mic]: the checksum function
        (e.g. {!Netmech_scram.Cryptosystem.get_mic})
      - [message]: the message to be signed

      The function returns the MIC token
   *)

val parse_mic_token_header : string -> (bool * bool * int64)
  (** Returns the triple
      ([sent_by_acceptor], [acceptor_subkey], [sequence_number]) from
      the header of a MIC token that is passed to this function as
      string. Fails if not parsable 
   *)

val verify_mic_token : get_mic:(message -> string) -> 
                       message:message -> token:string -> bool
  (** Verifies the MIC [token] with [get_mic], and returns true if the
      verification is successful
   *)

val create_wrap_token_conf : sent_by_acceptor:bool ->
                             acceptor_subkey:bool ->
                             sequence_number:int64 ->
                             get_ec:(int -> int) ->
                             encrypt_and_sign:(message -> message) ->
                             message:message ->
                               message
  (** Wraps a [message] so that it is encrypted and signed (confidential).

      - [sent_by_acceptor]: whether this token comes from the acceptor
      - [acceptor_subkey]: see RFC
      - [sequence_number]: a sequence number
      - [get_ec]: This function returns the "extra count" number for
        the size of the plaintext w/o filler (e.g. use
        {!Netmech_scram.Cryptosystem.get_ec}).
      - [encrypt_and_sign]: the encryption function from the cryptosystem.
        The plaintext is passed to this function, and the ciphertext with
        the appended signature must be returned in the string.
      - [message]: the payload message

      The function returns the token wrapping the message.
   *)

val parse_wrap_token_header : 
      message -> (bool * bool * bool * int64)
  (** [let (sent_by_acceptor, sealed, acceptor_subkey, sequence_number) =
      parse_wrap_token_header token]

      Fails if the [token] cannot be parsed.
   *)


val unwrap_wrap_token_conf : decrypt_and_verify:(message -> message) ->
                             token:message ->
                               message
  (** Unwraps the [token] using the decryption function
      [decrypt_and_verify] from the cryptosystem.

      The functions fails if there is a format error, or the integrity
      check fails.

      Non-confidential messages cannot be unwrapped with this function.
   *)


(** Token functions for non-confidential messages are still missing *)
