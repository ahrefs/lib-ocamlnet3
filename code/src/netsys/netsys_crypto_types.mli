(* $Id$ *)

(** Types for crypto providers *)

module type TLS_PROVIDER =
  sig
    type config
    type credentials
    type endpoint
    type error_code
    type direction = [ `R | `W ]

    exception EAGAIN of direction
      (** A read or write cannot be done because the descriptor is in
          non-blocking mode and would block. This corresponds to the
          [Unix.EAGAIN] error but includes whether it was a read or write.

          When the read or write is possible, the interrupted function should
          simply be again called.
       *)

    exception EINTR
      (** Interrupted system call. Corresponds to [Unix.EINTR]. The interrupted
          function should be again called.
       *)

    exception Switch_request
      (** The server requested a rehandshake *)

    exception Error of error_code
      (** A fatal error occurred (i.e. the session needs to be terminated) *)

    exception Warning of error_code
      (** A non-fatal error occurred. The interrupted function should be
          called again.
       *)

    val error_message : error_code -> string
      (** Returns the message for humans (display, log files etc.) *)

    val error_name : error_code -> string
      (** Returns the name of the code (for programming; this is always
          the same string for the same code w/o localization)
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
          config ->
            endpoint
      (** Creates a new endpoint for this configuration.

          The endpoint will use the functions [recv] and [send] for I/O, which
          must be user-supplied. [recv buf] is expected to read data into the
          buffer, and to return the number of bytes, or 0 for EOF. 
          [send buf n] is expected to send the [n] first bytes in [buf].

          Both functions may raise [Unix_error]. The codes [Unix.EAGAIN] and
          [Unix.EINTR] are specially interpreted.
       *)


    val hello : endpoint -> unit
      (** Performs the initial handshake (exchanges credentials and establishes
          a session).

          [hello] doesn't verify the peer. Use [verify] for that.

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val bye : endpoint -> [`W | `RW] -> unit
      (** Performs the final handshake (exchanges close requests).

          If [`W] is set, the close request is sent to the peer, and
          the TLS tunnel is considered as closed for writing. The application
          can receive further data until [recv] returns zero bytes meaning
          that the peer responded with another close request.

          If [`RW] is passed, it is additionally waited until the peer
          responds with a close request.

          In no case the underlying transport is closed or shut down!

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val verify : endpoint -> string -> unit
      (** [verify ep peer_name]: Checks that:
           - there is a trust chain for the peer's certificate
           - that [peer_name] is the common name of the certificate subject,
             or an alternate name

          {b No checks are performed if [peer_auth=`None] is set in the
          configuration!}

          You can get the certificate of the peer and perform further checks.

          This function will raise [Failure] on failed checks (and [Error]
          for internal processing errors).
       *)

    val get_endpoint_crt : endpoint -> string
      (** Get the cert that was actually used in the handshake, in DER
          format. Raise [Not_found] if not applicable.
       *)

    val get_peer_crt_list : endpoint -> string list
      (** Get the cert chain that was actually used in the handshake, in DER
          format. Raise [Not_found] if not applicable.
       *)

    val switch : endpoint -> config -> bool
      (** The server can use this to request a rehandshake and to use the
          new configuration for cert verification. This function sends the
          request, and expects an immediate response from the client
          (i.e. there must not be any other payload data in between). If
          the function returns [true], the server can go on and call
          [hello] to perform the handshake. If it returns [false], the
          switch was refused by the client. (If payload data is received
          instead of a response the function will raise [Error].)

          On the client side, the request will by returned as exception
          [Switch_request] by [recv]. The client should respond with
          [accept_switch] if it accepts the handshake, or [refuse_switch] if
          not.

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val accept_switch : endpoint -> config -> unit
      (** On the client: Enter another handshake round with new configuration
          data.

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val refuse_switch : endpoint -> unit
      (** On the client: Refuse a handshake

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val send : endpoint -> Netsys_types.memory -> int -> int
      (** [send ep buffer n]: Sends the first [n] bytes in the buffer over
          the endpoint, and returns the actual number of processed bytes.

          May raise [EAGAIN], [EINTR], [Error] or [Warning].
       *)

    val recv : endpoint -> Netsys_types.memory -> int
      (** [recv ep buffer n]: Receives data, and puts them into the memory
          buffer, and returns the actual number of received bytes. If 0
          is returned, a close request was received by the peer. For closing
          the tunnel properly this request should be responded by another
          close request with [bye] (unless this has already been done).

          May raise [EAGAIN], [EINTR], [Error] or [Warning].

          The exception [Switch_request] can only occur on the client
          side, and should be responded by [accept_switch] or [refuse_switch].
       *)

    val recv_will_not_block : endpoint -> bool
      (** If there is still unprocessed data in the endpoint buffer, 
          [recv] is guaranteed not to block or raise [EAGAIN].
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
          servers, and this function returns which was requested. Raises
          [Not_found] if there is nothing appropriate. This information is
          only available after a handshake, and if the client submitted it.
       *)

    val set_addressed_servers : endpoint -> server_name list -> unit
      (** For clients: Set the virtual server to address. This must be done
          before the handshake
       *)

    (* TODO: session resumption *)
    (* TODO: DTLS *)
    (* TODO: get channel binding token *)

    val implementation_name : string
      (** String name of the implementation. By convention this is the
          full OCaml module path, e.g. "Nettls_gnutls.TLS"
       *)

    val implementation : unit -> exn
      (** Implementation-defined additional functionality *)
  end


module type TLS_ENDPOINT =
  sig
    module TLS : TLS_PROVIDER
    val endpoint : TLS.endpoint
  end
