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


