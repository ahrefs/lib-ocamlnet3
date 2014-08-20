(* $Id$ *)

(** Crypto extensions for {!Netchannels} *)

(** {1:tls TLS} *)

(** A TLS channel is a layer on top of a bidirectional channel that adds the TLS
    protocol.
 *)
class type tls_channel = object
  inherit Netchannels.raw_io_channel
  method tls_endpoint : Netsys_crypto_types.tls_endpoint
end

class tls_layer :
  ?start_pos_in:int ->
  ?start_pos_out:int ->
  ?resume:string ->
  role:[ `Client | `Server ] ->
  rd:Netchannels.raw_in_channel ->
  wr:Netchannels.raw_out_channel ->
  peer_name:string option ->
  Netsys_crypto_types.tls_config ->
    tls_channel
  (** Adds TLS security to an already established connection, here made
      available as separate channels for input and output.

      The TLS handshake is done on the first I/O activity (call [flush]
      to enforce it).

      [resume]: see {!Netsys_tls.create_file_endpoint}.
   *)

class tls_endpoint :
  ?start_pos_in:int ->
  ?start_pos_out:int ->
  ?resume:string ->
  role:[ `Client | `Server ] ->
  peer_name:string option ->
  Unix.file_descr ->
  Netsys_crypto_types.tls_config ->
    tls_channel
  (** This class is slightly more efficient than [tls_layer], and to preferred
      if you have direct access to the file descriptors.
   *)


(** {1:symmetric Symmetric Cryptography} *)


(** Encrypt or decrypt data while writing to a channel *)
class type crypto_out_filter = object
  inherit Netchannels.out_obj_channel

  method supports_aead : bool
    (** Whether the cipher supports authentication, and will provide a MAC *)
  method mac : unit -> string
    (** Get the MAC of the processed data *)
end


(** Encrypt or decrypt data while reading from a channel *)
class type crypto_in_filter = object
  inherit Netchannels.in_obj_channel

  method supports_aead : bool
    (** Whether the cipher supports authentication, and will provide a MAC *)
  method mac : unit -> string
    (** Get the MAC of the processed data *)
end


val encrypt_out : Netsys_ciphers.cipher_ctx ->
                  Netchannels.out_obj_channel ->
                    crypto_out_filter
  (** [let ch2 = encrypt_out ctx ch1]: Writing to [ch2] encrypts
      the data and writes the ciphertext to [ch1]. Closing [ch2] will flush
      data and close [ch1].
   *)

val encrypt_in : Netsys_ciphers.cipher_ctx ->
                 Netchannels.in_obj_channel ->
                    crypto_in_filter
  (** [let ch2 = encrypt_in ctx ch1]: Reading from [ch2] encrypts
      the data from [ch1]. Closing [ch2] will close [ch1].
   *)

val decrypt_out : Netsys_ciphers.cipher_ctx ->
                  Netchannels.out_obj_channel ->
                    crypto_out_filter
  (** [let ch2 = decrypt_out ctx ch1]: Writing to [ch2] decrypts
      the data and writes the plaintext to [ch1]. Closing [ch2] will flush
      data and close [ch1].
   *)

val decrypt_in : Netsys_ciphers.cipher_ctx ->
                 Netchannels.in_obj_channel ->
                    crypto_in_filter
  (** [let ch2 = decrypt_in ctx ch1]: Reading from [ch2] decrypts
      the data from [ch1]. Closing [ch2] will close [ch1].
   *)
