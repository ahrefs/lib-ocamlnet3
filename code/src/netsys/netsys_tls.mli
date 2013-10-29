(* $Id$ *)

(** User-level TLS API *)

(** The following functions are a very thin layer on top of
    {!Netsys_crypto_types.TLS_PROVIDER}. The provider is passed
    here as first-class value together with the configuration and
    with the endpoint (socket). In particular, we have

    {[
module type FILE_TLS_ENDPOINT =
  sig
    module TLS : TLS_PROVIDER
    val endpoint : TLS.endpoint
    val rd_file : Unix.file_descr
    val wr_file : Unix.file_descr
  end
    ]}

    (see {!Netsys_crypto_types}). In many cases, you can consider the
    packed modules as opaque values. Sometimes, however, it is
    useful to call functions of the provider directly. You can do this
    as follows, demonstrated by calling the provider function
    [get_peer_crt_list] for [endpoint]:

    {[
let module Endpoint =
  (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
let certificates =
  Endpoint.TLS.get_peer_crt_list Endpoint.endpoint
    ]}

    If you do this, be aware that the inner types of the
    provider are meaningless outside, and you get a compiler error
    "type ... would escape its scope" if you try to export such typed
    values. Exceptions thrown by the provider should be caught and
    translated to [Error] with {!Netsys_tls.translate_exn}.
 *)

exception Error of string * string
  (** [Error(name,message)]: Any TLS error as string. [name] identifies
      the error type in an implementation-defined way.
   *)

type dh_params =
  [ `PKCS3_PEM_file of string
  | `PKCS3_DER of string
  | `Generate of int
  ]
  (** Diffie-Hellman parameters:

           - [`PKCS3_PEM_file name]: points to a PEM-encoded PKCS3-file
             ("BEGIN DH PARAMETERS")
           - [`PKCS3_DER data]: the parameters are in a DER-encoded PKCS3
             structure
           - [`Generate bits]: the parameters are generated with the
             passed number of bits
   *)

type crt_list =
  [`PEM_file of string | `DER of string list]
  (** Certificates are given either as:

          - [`PEM_file name]: The certs are stored in this file, and are
            PEM-encoded.
          - [`DER l]: The certs are given directly in their DER-encoded form
   *)

type crl_list =
  [`PEM_file of string | `DER of string list]
  (** Certificate revocation lists are given either as:

          - [`PEM_file name]: The CRLs are stored in this file, and are
            PEM-encoded.
          - [`DER l]: The CRLs are given directly in their DER-encoded form
   *)

type private_key =
  [ `PEM_file of string 
  | `RSA of string 
  | `DSA of string
  | `EC of string
  | `PKCS8 of string
  | `PKCS8_encrypted of string
  ]
  (** Private keys are given either as:

          - [`PEM_file name]: The key is stored PEM-encoded in this file.
            The PEM header indicates the format.
          - [`RSA data]: The key is a PKCS1 RSA key
          - [`DSA data]: The key is a DSA key
          - [`EC data]: The key is for an elliptic curve
          - [`PKCS8 data]: The key is in a PKCS8 data structure
          - [`PKCS8_encrypted data]: The key is in a PKCS8 data structure,
            and is additionally encrypted.
   *)


val create_x509_config :
      ?algorithms : string ->
      ?dh_params : dh_params ->
      ?verify : ((module Netsys_crypto_types.TLS_ENDPOINT) -> bool) ->
      ?peer_name : string ->
      ?trust : crt_list list ->
      ?revoke : crl_list list ->
      ?keys : (crt_list * private_key * string option) list ->
      peer_auth : [ `None | `Optional | `Required ] ->
      (module Netsys_crypto_types.TLS_PROVIDER) ->
        (module Netsys_crypto_types.TLS_CONFIG)
  (** The configuration includes:

          - [algorithms]: a string specifying which cryptographic algorithms,
            protocols and protocol options
            are enabled, and in which priority they are used in the negotiation.
            (GnuTLS calls this "priority string".) The syntax is
            implementation-defined.
          - [dh_params]: parameters for Diffie-Hellman key exchange (used for
            DH-based authentication, but only on the server side)
          - [peer_name]: The expected name of the peer (i.e. the subject
            of the peer certificate = normally the DNS name). {b This is
            strongly recommended to set for clients!}
          - [peer_auth]: controls whether the peer is requested to authenticate.
            This can be set to [`None] meaning not to request authentication
            and to ignore credentials, or to [`Optional] meaning not to request
            authentication but to check credentials if they are sent 
            nevertheless, or to [`Required] meaning to request and check
            credentials. For "standard clients" you should set this to
            [`Required], and for "standard servers" to [`None] or
            [`Required].
          - [verify] is a function called to verify the peer certificate
            in addition to the actions of [peer_auth]. The function must
            return [true] in order to be successful.
          - [trust] specifies the CAs of peers to trust (default: empty)
          - [revoke] specifies CRLs for revocation of peer certificates
            (default: empty)
          - [keys] are our own certificates, as triples
            [(cert_path, private_key, password)] (default: empty)

          A configuration is read-only once created, and can be used for
          several endpoints. In particular, it does not cache TLS sessions.

          A client should set [trust] to the list of CAs it can accept on
          the server side. It is not required to specify a key.

          A server must specify a key (but can also specify several keys).
          If a server requests authentication from the client, it must also
          set [trust].

          The keys must include the full certificate path [cert_path], starting
          with the endpoint certificate, followed by all middle certificates, and
          ending with the certificate of the CA. The [private_key]
          is the key of the endpoint. If it is password-encrypted, the
          password must be given.
   *)

(* TODO:
   - peer_auth:`None should trust any cert of the peer
   - Clients should fail if peer_auth<>`None and there is no peer_name
 *)


val create_file_endpoint : 
       role : [ `Server | `Client ] ->
       rd:Unix.file_descr ->
       wr:Unix.file_descr ->
       (module Netsys_crypto_types.TLS_CONFIG) ->
         (module Netsys_crypto_types.FILE_TLS_ENDPOINT)
  (** [create_file_endpoint ~role ~rd ~wr tls_config]:
      Creates a new TLS endpoint (encapsulated as module, together with
      the provider) for the case that the data flows over file descriptors.
      [rd] is used for reading data, and [wr] for writing (of
      course, both descriptors may be identical).
   *)


val endpoint : (module Netsys_crypto_types.FILE_TLS_ENDPOINT) ->
               (module Netsys_crypto_types.TLS_ENDPOINT)
  (** Coercion *)


val start_tls : (module Netsys_crypto_types.TLS_ENDPOINT) -> unit
  (** Procedes the TLS protocol until payload data can be exchanged.
      This includes the initial handshake (if not yet done), and the
      verification.
   *)


val recv : (module Netsys_crypto_types.TLS_ENDPOINT) ->
           string -> int -> int -> int
  (** [recv endpoint buffer pos len]: Receives data from [endpoint],
      and puts the received bytes into [buffer] at byte position [pos].
      At most [len] bytes can be received. Returns the actually received
      number of bytes.

      If the TLS protocol is not yet at the stage where data can be
      received, the protocol is proceeded until this point (i.e.
      [start_tls] is "included"). Also, renegotiation alerts are interpreted.
      Both phenomenons can cause that data needs to be written first.

      If interrupted the function can be safely invoked again.

      May raise {!Netsys_types.EAGAIN_RD}, {!Netsys_types.EAGAIN_WR},
      [Unix_error(EINTR,_,_)], and [Error].
   *)


val mem_recv : (module Netsys_crypto_types.TLS_ENDPOINT) ->
               Netsys_types.memory -> int -> int -> int
  (** Same for a memory-backed buffer *)

val send : (module Netsys_crypto_types.TLS_ENDPOINT) ->
           string -> int -> int -> int
  (** [send endpoint buffer pos len]: Sends data via [endpoint],
      and takes the emitted bytes from [buffer] at byte position [pos].
      At most [len] bytes can be sent. Returns the actually sent
      number of bytes.

      If the TLS protocol is not yet at the stage where data can be
      received, the protocol is proceeded until this point (i.e.
      [start_tls] is "included"). Also, renegotiation alerts are interpreted.
      Both phenomenons can cause that data needs to be received as well
      as sent.

      If interrupted the function can be safely invoked again.

      May raise {!Netsys_types.EAGAIN_RD}, {!Netsys_types.EAGAIN_WR},
      [Unix_error(EINTR,_,_)], and [Error].
   *)

val mem_send : (module Netsys_crypto_types.TLS_ENDPOINT) ->
               Netsys_types.memory -> int -> int -> int
  (** Same for a memory-backed buffer *)

val end_tls : (module Netsys_crypto_types.TLS_ENDPOINT) ->
              Unix.shutdown_command -> unit
  (** Ends the TLS encapsulation of data:

      - [SHUTDOWN_SEND]: The payload stream is closed for sending.
      - [SHUTDOWN_ALL]: The payload stream is closed for sending and
        receiving.

      The mode [SHUTDOWN_RECEIVE] is unsupported and silently ignored.

      The function does not shut down or close the underlying file
      descriptors.

      If interrupted the function can be safely invoked again.

      May raise {!Netsys_types.EAGAIN_RD}, {!Netsys_types.EAGAIN_WR},
      [Unix_error(EINTR,_,_)], and [Error].
   *)

val translate_exn : (module Netsys_crypto_types.TLS_ENDPOINT) ->
                    exn -> exn
  (** Translates an internal exception raised by the TLS provider
      into [Error].
   *)

module Debug : sig
  val enable : bool ref
end
