(* SASL provider definition *)

(* TODO: channel binding *)

module type SASL_MECHANISM = 
  sig
    val mechanism_name : string
    val client_first : [`Required | `Optional | `No]
      (** Whether the client sends the first message:
           - [`Required]: always
           - [`Optional]: the client may choose to do so if the protocol
             permits this
           - [`No]: the server sends the first message
       *)
    val server_sends_final_data : bool
      (** Whether final data from the server must be interpreted by the
          mechanism
       *)
    val supports_authz : bool
      (** whether the authorization name can be transmitted *)
    val plus_channel_binding : bool
      (** Whether this is a "PLUS" SASL mechanism (RFC-5801) *)

    type credentials

    val init_credentials :
          (string * string * (string * string)) list ->
            credentials
      (** Supply the mechanism with credentials. These are given as list
          [(type,value,params)]. The mechanism may pick any element
          of this list which are considered as equivalent.

          Types are defined per mechanism. The following types
          are commonly used:

           - "password": The [value] is the password.
           - "salted-password": The [value] is computed as
             [Hi(password,salt,i)] where the Hi function is defined as
             in RFC-5802. It is required that [salt] and [i] are given as
             numeric parameters, and the name of the hash function must be
             set in the parameter [h] (e.g. [h="SHA1"]).
           - "digest-md5": The [value] is computed as
             [MD5(username ^ ":" ^ realm ^ ":" ^ password)]. The
             [realm] must be given as parameter.
       *)

    type server_session

    type server_state =
           [ `Wait | `Emit | `OK | `Auth_error | `Restart of string ]
      (** The state of the server session:
          - [`Wait]: it is waited for the client response.
          - [`Emit]: a new server challenge can be emitted.
          - [`OK]: the authentication protocol succeeded
          - [`Auth_error]: authentication error (it is unspecified which)
          - [`Restart session_id]: this state can be entered after getting
            the first client response. It means that the saved session
            [session_id] may be restarted by calling 
            [server_process_response_restart] with the client response.
       *)

    val server_state : server_session -> server_state

    val create_server_session :
          lookup:(string -> string -> credentials option) ->
          params:(string * string * bool) list -> 
          unit ->
            server_session
      (** Create a new server session. The [lookup] function is used to
          get the credentials for a given user name and a given authorization
          name (which is the empty string if not applicable). If the [lookup]
          function returns [None], the user can either not be found, or the
          user does not have the privileges for the authorization name.

          The parameters are given as list [(name,value,critical)]. 
          Critical parameters must be interpreted by the mechanism, and
          unknown critical parameters must be rejected by a [Failure]
          exception. Non-critical parameters are ignored if they are unknown
          to the mechanism.

          Common parameters include:
           - "realm"
           - "digest-uri"

       *)

    val server_process_response :
          server_session -> string -> unit
      (** Process the response from the client. This function must generally
          only be called when the session state is [`Wait]. As an exception,
          however, this function may also be invoked with the initial client
          response, even if the session state is [`Emit], so far the mechanism
          permits at least optionally that the client starts the protocol.
       *)

    val server_process_response_restart :
          server_session -> string -> unit
      (** Process the response from the client when another session can be
          continued. The string argument is the initial client response.
          This function must only be called when the state reaches
          [`Restart id] after [server_process_response], and in this case
          the old session with [id] can be restarted.
       *)

    val server_emit_challenge :
          server_session -> string
      (** Emit a server challenge. This function must only be called when the
          session state is [`Emit].
       *)

    val server_stash_session :
          server_session -> string
      (** Serializes the session as string *)

    val server_resume_sesson :
          lookup:(string -> string -> credentials option) ->
          string -> 
             server_session
      (** Unserializes the session, and connect with the [lookup] function. *)

    val server_session_id : server_session -> string option
      (** Optionally return a string that can be used to identify the
          server session. Not all mechanisms support this.
       *)

    val server_prop : server_session -> string -> string
      (** Get a mechanism-specific property of the session. E.g. this can
          be the "digest-uri" sent by the client.
       *)

    val server_user : server_session -> string
      (** The name the client has authenticated as (or [Not_found]) *)

    val server_authz : server_session -> string
      (** The name the client authorizes as (or [Not_found]) *)

    type client_session

    type client_state =
           [ `Wait | `Emit | `OK | `Auth_error | `Stale ]
      (** The state of the client session:
          - [`Wait]: it is waited for the server challenge.
          - [`Emit]: a new client response can be emitted.
          - [`OK]: the authentication protocol succeeded
          - [`Auth_error]: authentication error (it is unspecified which)
          - [`Stale]: The client session is refused as too old
       *)

    val client_state : client_session -> client_state

    val create_client_session :
          user:string ->
          authz:string ->
          creds:credentials ->
          params:(string * string * bool) list -> 
          unit ->
            client_session
      (** The new client session authenticate as [user] and authorizes as
          [authz] (empty string if not applicable). The credentials are
          [creds].

          The parameters are given as list [(name,value,critical)]. 
          Critical parameters must be interpreted by the mechanism, and
          unknown critical parameters must be rejected by a [Failure]
          exception. Non-critical parameters are ignored if they are unknown
          to the mechanism.
       *)

    val client_restart : client_session -> unit
      (** Restart the session for another authentication round. The session
          must be in state [`OK].
       *)

    val client_process_challenge :
          client_session -> string -> unit
      (** Process the challenge from the server. The state must be [`Wait].
          As an exception, this function can also be called for the initial
          challenge from the server, even if the state is [`Emit].
       *)

    val client_emit_response :
          client_session -> string
      (** Emit a new response. The state must be [`Emit]. *)

    val client_stash_session :
          client_session -> string
      (** Serializes the session as string *)

    val client_resume_sesson :
          string -> 
             client_session
      (** Unserializes the session *)

    val client_session_id : client_session -> string option
      (** Optionally return a string that can be used to identify the
          client session. Not all mechanisms support this.
       *)

    val client_prop : client_session -> string -> string
      (** Get a mechanism-specific property of the session. E.g. this can
          be the "realm" sent by the server.
       *)


  end
