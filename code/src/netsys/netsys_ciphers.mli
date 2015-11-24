(* $Id$ *)

(** Symmetric cryptographic ciphers *)

type padding =
    [ `None
    | `Length
    | `_8000
    | `CTS
    ]
  (** Padding schemes:

      - [`None]: no padding. The text to encrypt/decrypt must be a multiple
         of [block_constraint] bytes
      - [`Length]: Pad the last block with n bytes of code n
      - [`_8000]: Pad with one byte 0x80 and as many zeros as needed to fill
        the block (this may add one or two blocks)
      - [`CTS]: Use "Ciphertext Stealing". There is a minimum length of the
        message to encrypt of two blocks.
   *)


class type cipher_ctx =
object
  method padding : padding
    (** The padding scheme of the cipher *)

  method block_constraint : int
    (** The buffers used with encrypt/decrypt must have a length that is a
        multiple of this number. (In ECB mode this is the
        block size.)

        This value doesn't take padding into account.
     *)

  method supports_aead : bool
    (** Whether this cipher integrates authentication *)

  method set_iv : string -> unit
    (** Sets the initialization vector (this must be done before starting
        the encryption or decryption).
     *)

  method set_header : string -> unit
    (** Sets the header to authenticate for AEAD (this must be done before
        starting the encryption or decryption).
     *)

  method encrypt : last:bool -> 
                   Netsys_types.memory -> Netsys_types.memory -> int * int
    (** [let n_in, n_out = encrypt ~last inbuf outbuf]: 
        Encrypts the text in [inbuf] and
        writes the result to [outbuf]. The returned numbers indicate how
        much data was processed: the first [n_in] bytes of [inbuf] are
        encrypted, and the first [n_out] bytes of [outbuf] are filled with
        ciphertext.

        This function can be called several
        times to encrypt a larger text. [last] should be set for the last
        call.

        The sizes of [inbuf] and [outbuf] must be at least one block
        in order to produce non-zero ([n_in],[n_out]). (For `CTS only:
        two blocks.)
     *)

  method decrypt : last:bool -> 
                   Netsys_types.memory -> Netsys_types.memory -> int * int
    (** [let n_in, n_out = decrypt ~last inbuf outbuf]:
        Decrypts the text in [inbuf] and
        writes the result to [outbuf]. The returned numbers indicate how
        much data was processed: the first [n_in] bytes of [inbuf] are
        decrypted, and the first [n_out] bytes of [outbuf] are filled with
        plaintext.

        This function can be called several
        times to decrypt a larger text. [last] should be set for the last
        call.

        The sizes of [inbuf] and [outbuf] must be at least one block
        in order to produce non-zero ([n_in],[n_out]). (For `CTS only:
        two blocks.)

        On error, the method fails.
     *)

  method encrypt_bytes : Bytes.t -> Bytes.t
    (** Encrypts this string as a whole *)

  method encrypt_string : string -> string
    (** Encrypts this string as a whole *)

  method decrypt_bytes : Bytes.t -> Bytes.t
    (** Decrypts this string as a whole *)

  method decrypt_string : string -> string
    (** Decrypts this string as a whole *)

  method mac : unit -> string
    (** Returns the MAC for AEAD ciphers. Can first be called after the
        encryption/decryption is complete. This function fails for non-AEAD
        ciphers.
     *)
end



class type cipher =
object
  method name : string
    (** The name of the cipher *)

  method mode : string
    (** The mode of the cipher *)

  method key_lengths : (int * int) list
    (** Supported key lengths as pairs [min,max]. If there is a recommended
         key length, this is the first.
     *)

  method iv_lengths : (int * int) list
    (** Supported iv lengths as pairs [min,max]. If there is a recommended
        iv length, this is the first.
     *)

  method block_constraint : int
    (** The buffers used with encrypt/decrypt must have a length that is a
        multiple of this number. (In ECB mode this is the
        block size.)
     *)

  method supports_aead : bool
     (** Whether this cipher integrates authentication *)

  method create : string -> padding -> cipher_ctx
    (** [create c p key]: create a new cipher context for [key]. If not set,
        the initialization vector is assumed to be zero, and the header the
        empty string.

        The cipher context can be used for either encrypting or decrypting a
        single message.
     *)
end


(** The following functions use the current crypto module (as retrieved by
    {!Netsys_crypto.current_symmetric_crypto}), unless the [impl] argument is
    passed.
 *)

val ciphers : ?impl:(module Netsys_crypto_types.SYMMETRIC_CRYPTO) ->
              unit -> cipher list
    (** List of supported ciphers *)

val find : ?impl:(module Netsys_crypto_types.SYMMETRIC_CRYPTO) ->
           (string * string) ->
           cipher
    (** [find (name,mode)]: get the cipher [name] in the passed [mode].

        The name conventionally follows the [<uppercasestring>-<size>] format,
        e.g. "AES-128" or "TWOFISH-128".

        Modes are "ECB", "CBC", "OFB", "CTR", "STREAM", "GCM". Not every cipher
        is available in every mode.
     *)

val process_subbytes :
     (last:bool -> Netsys_types.memory -> Netsys_types.memory -> int * int) ->
     Bytes.t -> int -> int -> Bytes.t
  (** [process_subbytes p s pos len]: If [p] is [encrypt] or [decrypt] from
      a [cipher_ctx], [p] will be called to submit the data from string [s],
      starting at position [pos] and length [len].

      The encrypted or decrypted string is returned.
   *)

val process_substring :
     (last:bool -> Netsys_types.memory -> Netsys_types.memory -> int * int) ->
     string -> int -> int -> string
  (** [process_substring p s pos len]: Same for immutable strings.
   *)

val process_bytes :
     (last:bool -> Netsys_types.memory -> Netsys_types.memory -> int * int) ->
     Bytes.t -> Bytes.t
  (** [process_bytes p s]: If [p] is [encrypt] or [decrypt] from
      a [cipher_ctx], [p] will be called to submit the data from string [s].

      The encrypted or decrypted string is returned.
   *)

val process_string :
     (last:bool -> Netsys_types.memory -> Netsys_types.memory -> int * int) ->
     string -> string
  (** [process_string p s]: same for immutable strings. *)
