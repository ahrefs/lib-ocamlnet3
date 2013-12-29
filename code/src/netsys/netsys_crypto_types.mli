(* $Id$ *)

(** Types for crypto providers *)


(** The exceptions the TLS provider may use (in addition to OCaml's built-in
    exception). In Ocamlnet, these exceptions are actually defined in 
    {!Netsys_types}.
 *)
module type TLS_EXCEPTIONS =
  sig
    exception EAGAIN_RD
    exception EAGAIN_WR
      (** A read or write cannot be done because the descriptor is in
      non-blocking mode and would block. This corresponds to the
      [Unix.EAGAIN] error but includes whether it was a read or write.

      When the read or write is possible, the interrupted function should
      simply be again called.

      These two exceptions are preferred by TLS providers.
      *)

    exception TLS_switch_request
      (** The server requested a rehandshake (this exception is thrown
          in the client)
       *)

    exception TLS_switch_response of bool
      (** The client accepted or denied a rehandshake (this exception is thrown
          in the server). [true] means acceptance.
       *)

    exception TLS_error of string
      (** A fatal error occurred (i.e. the session needs to be terminated).
          The string is a symbol identifying the error.
       *)

    exception TLS_warning of string
      (** A non-fatal error occurred. The interrupted function should be
          called again.
          The string is a symbol identifying the warning.
       *)
  end

module type TLS_PROVIDER =
  sig
    type config
    type credentials
    type endpoint

    module Exc : TLS_EXCEPTIONS
      (** Access to exceptions *)

    val error_message : string -> string
      (** Returns the message for humans (display, log files etc.) when
          called with an error or warning symbol.
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

    val create_config :
          ?algorithms : string ->
          ?dh_params : dh_params ->
          ?verify : (endpoint -> bool) ->
          ?peer_name_unchecked : bool ->
          peer_auth : [ `None | `Optional | `Required ] ->
          credentials : credentials ->
          unit ->
            config
      (** The configuration includes:

          - [algorithms]: a string specifying which cryptographic algorithms,
            protocols and protocol options
            are enabled, and in which priority they are used in the negotiation.
            (GnuTLS calls this "priority string".) The syntax is
            implementation-defined.
          - [dh_params]: parameters for Diffie-Hellman key exchange (used for
            DH-based authentication, but only on the server side)
          - [peer_name_unchecked]: If you do not want to check the peer name
            although authentication is enabled, you can set this option.
            (Normally, it is an error just to omit [peer_name].)
          - [peer_auth]: controls whether the peer is requested to authenticate.
            This can be set to [`None] meaning not to request authentication
            and to ignore credentials, or to [`Optional] meaning not to request
            authentication but to check credentials if they are sent 
            nevertheless, or to [`Required] meaning to request and check
            credentials. For "standard clients" you should set this to
            [`Required], and for "standard servers" to [`None] or
            [`Required].
          - [credentials] describes our own credentials, and the accepted
            credentials of the peer.
          - [verify] is a function called to verify the peer certificate
            in addition to the actions of [peer_auth]. The function must
            return [true] in order to be successful.

          A configuration is read-only once created, and can be used for
          several endpoints. In particular, it does not cache TLS sessions.
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

    val create_x509_credentials :
          ?trust : crt_list list ->
          ?revoke : crl_list list ->
          ?keys : (crt_list * private_key * string option) list ->
          unit ->
            credentials
      (** Create X.509 credentials from individual objects:
           - [trust] specifies the CAs of peers to trust (default: empty)
           - [revoke] specifies CRLs for revocation of peer certificates
             (default: empty)
           - [keys] are our own certificates, as triples
             [(cert_path, private_key, password)] (default: empty)

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

    val create_endpoint :
          role : [ `Server | `Client ] ->
          recv : (Netsys_types.memory -> int) ->
          send : (Netsys_types.memory -> int -> int) ->
          peer_name : string option ->
          config ->
            endpoint
      (** Creates a new endpoint for this configuration.

          [peer_name] is the expected common name or DNS name of the
          peer.  [peer_name] has an option type as it is not always
          required to pass it. However, keep in mind that clients
          normally authenticate servers ([peer_auth=`Required]). In
          order to do so, they need to check whether the name in the
          server certificate equals the DNS name of the service they
          are connected to. This check is done by comparing [peer_name]
          with the name in the certificate.

          [peer_name] is also used for the SNI extension.

          Servers normally need not to set [peer_name]. You can also omit it
          when there is no name-driven authentication at all.

          The endpoint will use the functions [recv] and [send] for I/O, which
          must be user-supplied. [recv buf] is expected to read data into the
          buffer, and to return the number of bytes, or 0 for EOF. 
          [send buf n] is expected to send the [n] first bytes in [buf].

          Both functions may raise [Unix_error]. The codes [Unix.EAGAIN] and
          [Unix.EINTR] are specially interpreted.
       *)

    val stash_endpoint : endpoint -> exn
      (** The endpoint in "stashed" form, encapsulated as an exception.
          This form is intended for keeping the session alive in RAM, but
          without keeping references to the [recv] and [send] functions.

          The endpoint passed in to [stash_endpoint] must no longer be used!
       *)

    val restore_endpoint : 
          recv : (Netsys_types.memory -> int) ->
          send : (Netsys_types.memory -> int -> int) ->
          exn ->
            endpoint
      (** Reconnect the stashed endpoint with [recv] and [send] functions *)

    val resume_client :
          recv : (Netsys_types.memory -> int) ->
          send : (Netsys_types.memory -> int -> int) ->
          peer_name : string option ->
          config ->
          string ->
            endpoint
      (** Creates a new endpoint that will resume an old session. This implies
          the client role.

          The session data is passed as string, which must have been retrieved
          with [get_session_data].
       *)

    type state =
        [ `Start | `Handshake | `Data_rw | `Data_r | `Data_w | `Data_rs
        | `Switching | `Accepting | `Refusing | `End
        ]
      (** The state of a session:

          - [`Start]: Before the session is started
          - [`Handshake]: The handshake is being done (and [hello] needs to
            be called again)
          - [`Data_rw]: The connection exists, and is read/write
          - [`Data_r]: The connection exists, and is read-only
          - [`Data_w]: The connection exists, and is write-only
          - [`Data_rs]: The connection exists, and data can be read.
            There was a switch request (initiated by us), and a response
            is awaited. No data can be sent in the moment.
          - [`Switching]: A rehandshake is being negotiated (and [switch]
            needs to be called again)
          - [`Accepting]: A rehandshake is being accepted (and [accept_switch]
            needs to be called again)
          - [`Refusing]: A rehandshake is being refused (and [refuse_switch]
            needs to be called again)
          - [`End]: After finishing the session
       *)

    val get_state : endpoint -> state
      (** Return the recorded state *)

    type raw_credentials =
      [ `X509 of string
      | `Anonymous
      ]
      (** The encoded credentials:
           - [`X509 s]: The X509 certificate in DER encoding
           - [`Anonymous]: no certificate or other key is available
       *)

    val at_transport_eof : endpoint -> bool
    (** Whether the underlying transport channel has seen the end of
        input. Use this after [recv] or [mem_recv] returned 0 to
        check whether only the TLS enf-of-input message has been read,
       or the underlying channel (usually the file descriptor) has
        indicated EOF.
     *)

    val hello : endpoint -> unit
      (** Performs the initial handshake (exchanges credentials and establishes
          a session).

          [hello] doesn't verify the peer. Use [verify] for that.

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val bye : endpoint -> Unix.shutdown_command -> unit
      (** Performs the final handshake (exchanges close requests).

          If [SHUTDOWN_SEND] is set, the close request is sent to the peer, and
          the TLS tunnel is considered as closed for writing. The application
          can receive further data until [recv] returns zero bytes meaning
          that the peer responded with another close request.

          If [SHUTDOWN_ALL] is passed, it is additionally waited until the peer
          responds with a close request.

          A simple [SHUTDOWN_RECEIVE] is unimplemented and ignored.

          In no case the underlying transport is closed or shut down!

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val verify : endpoint -> unit
      (** [verify ep peer_name]: Checks that:
           - there is a trust chain for the peer's certificate
           - that [peer_name] is the common name of the certificate subject,
             or an alternate name

          {b These checks are not performed if [peer_auth=`None] is set in the
          configuration!}

          Additionally, the [verify] function in the endpoint configuration
          is called back, and a failure is indicated if this function returns
          [false]. This callback is useful to get the certificate of the peer
          and to perform further checks.

          The [verify] function will raise [Failure] on failed checks
          (and [Error]
          for internal processing errors).
       *)

    val get_config : endpoint -> config
      (** Get the current config (possibly modified because of a rehandshake)
       *)

    val get_endpoint_creds : endpoint -> raw_credentials
      (** Get the credentials that was actually used in the handshake, in raw
          format.
       *)

    val get_peer_creds : endpoint -> raw_credentials
      (** Get the credentials of the peer, in raw format. Raises [Not_found]
          if not applicable/no credentials present.
       *)

    val get_peer_creds_list : endpoint -> raw_credentials list
      (** Get the chain that was actually used in the handshake.
       *)

    val switch : endpoint -> config -> unit
      (** The server can use this to request a rehandshake and to use the
          new configuration for cert verification. This function sends the
          request, and expects a soon response from the client. The
          state enters [`Data_rs] meaning that we can still read data,
          and at some point [recv] will raise [TLS_switch_response].

          On the client side, the request will by returned as exception
          [TLS_switch_request] by [recv]. The client should respond with
          [accept_switch] if it accepts the handshake, or [refuse_switch] if
          not.

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val accept_switch : endpoint -> config -> unit
      (** On the client: Enter another handshake round with new configuration
          data.

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val refuse_switch : endpoint -> unit
      (** On the client: Refuse a handshake

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val send : endpoint -> Netsys_types.memory -> int -> int
      (** [send ep buffer n]: Sends the first [n] bytes in the buffer over
          the endpoint, and returns the actual number of processed bytes.

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].
       *)

    val recv : endpoint -> Netsys_types.memory -> int
      (** [recv ep buffer n]: Receives data, and puts them into the memory
          buffer, and returns the actual number of received bytes. If 0
          is returned, a close request was received by the peer. For closing
          the tunnel properly this request should be responded by another
          close request with [bye] (unless this has already been done).

          May raise [EAGAIN_RD], [EAGAIN_WR],
          [Unix_error(EINTR,_,_)], [Error] or [Warning].

          The exception [TLS_switch_request] can only occur on the client
          side, and should be responded by [accept_switch] or [refuse_switch].

          The exception [TLS_switch_response] can only occur on the server
          side.
       *)

    val recv_will_not_block : endpoint -> bool
      (** If there is still unprocessed data in the endpoint buffer, 
          [recv] is guaranteed not to block or raise [EAGAIN].
       *)

    val get_session_id : endpoint -> string
      (** The (non-printable) session ID *)

    val get_session_data : endpoint -> string
      (** Get the (non-printable) marshalled session data, for later resumption
          with [resume_client]
       *)

    val get_cipher_suite_type : endpoint -> string
      (** The type of the cipher suite:
         - "X509": X509 certificates are used
         - "OPENPGP": OpenPGP certificates are used
         - "ANON": anonymous credentials
         - "SRP": SRP credentials
         - "PSK": PSK credentials
       *)

    (* TODO: get_cipher_suite_id : endpoint -> int * int
       = get the two bytes identifying the cipher suite
     *)

    val get_cipher_algo : endpoint -> string
      (** Get the name of the cipher *)

    val get_kx_algo : endpoint -> string
      (** Get the name of the key exchange method *)

    val get_mac_algo : endpoint -> string
      (** Get the name of the message authentication code *)

    val get_compression_algo : endpoint -> string
      (** Get the name of the record-level compression method *)

    val get_cert_type : endpoint -> string
      (** Get the type of the certificate *)

    val get_protocol : endpoint -> string
      (** Get the name of the tunnel protocol *)

    type server_name = [ `Domain of string ]

    val get_addressed_servers : endpoint -> server_name list
      (** To be used in servers: The client can address one of several virtual
          servers with the SNI extension, and this function returns which
          was requested. Raises
          [Not_found] if there is nothing appropriate. This information is
          only available after a handshake, and if the client submitted it.
       *)

    val set_session_cache : store:(string -> string -> unit) ->
                            remove:(string -> unit) ->
                            retrieve:(string -> string) ->
                            endpoint ->
                            unit
      (** Sets the three callbacks for storing, removing and retrieving
          sessions (on the server side)
       *)

    (* TODO: DTLS *)
    (* TODO: get channel binding token *)

    val implementation_name : string
      (** String name of the implementation. By convention this is the
          full OCaml module path, e.g. "Nettls_gnutls.TLS"
       *)

    val implementation : unit -> exn
      (** Implementation-defined additional functionality *)
  end


module type TLS_CONFIG =
  sig
    module TLS : TLS_PROVIDER
    val config : TLS.config
  end


module type TLS_ENDPOINT =
  sig
    module TLS : TLS_PROVIDER
    val endpoint : TLS.endpoint
  end


module type FILE_TLS_ENDPOINT =
  sig
    module TLS : TLS_PROVIDER
    val endpoint : TLS.endpoint
    val rd_file : Unix.file_descr
    val wr_file : Unix.file_descr
  end


type tls_provider = (module TLS_PROVIDER)
type tls_config = (module TLS_CONFIG)
type tls_endpoint = (module TLS_ENDPOINT)
type file_tls_endpoint = (module FILE_TLS_ENDPOINT)
