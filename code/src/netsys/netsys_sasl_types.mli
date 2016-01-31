(* SASL provider definition *)

type cb =
    [ `None
    | `SASL_none_but_advertise
    | `SASL_require of string * string
    | `GSSAPI of string
    ]
  (** Possible channel bindings:
       - [`None]: this is the default
       - [`SASL_none_but_advertise]: the client supports channel binding and
         advertises this. For this time, the SCRAM protocol is run without
         channel binding, though. (Only available in the SASL profile.)
       - [`SASL_require(type,data)]: Require channel binding. E.g. type="tls-unique",
         and [data] is set to the channel identifier (RFC 5929).
         (Only available in the SASL profile.)
       - [`GSSAPI data]: use this channel binding for GSS-API

      This type is shared by SASL and GSSAPI providers.
   *)

type server_state =
  [ `Wait | `Emit | `OK | `Auth_error of string | `Restart of string ]
  (** The state of the server session:
          - [`Wait]: it is waited for the client response.
          - [`Emit]: a new server challenge can be emitted.
          - [`OK]: the authentication protocol succeeded
          - [`Auth_error]: authentication error (it is unspecified which;
            the string may be used for logging)
          - [`Restart session_id]: this state can be entered after getting
            the first client response. It means that the saved session
            [session_id] may be restarted by calling 
            [server_process_response_restart] with the client response.
   *)


type client_state =
  [ `Wait | `Emit | `OK | `Auth_error of string | `Stale ]
      (** The state of the client session:
          - [`Wait]: it is waited for the server challenge.
          - [`Emit]: a new client response can be emitted.
          - [`OK]: the authentication protocol succeeded
          - [`Auth_error]: authentication error (it is unspecified which);
            the string may be used for logging)
          - [`Stale]: The client session is refused as too old. The password,
            though, is correct. Otherwise this is the same as [`Emit], i.e.
            the authentication process can continue.
       *)


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

    val available : unit -> bool
      (** Whether the mechanism is available, in particular whether the
          required crypto support is linked in
       *)
    type credentials

    val init_credentials :
          (string * string * (string * string) list) list ->
            credentials
      (** Supply the mechanism with credentials. These are given as list
          [(type,value,params)]. The mechanism may pick any element
          of this list which are considered as equivalent.

          Types are defined per mechanism. All mechanisms understand the
          "password" type, which is just the cleartext password, e.g.

          {[
            [ "password", "ThE sEcReT", [] ]
          ]}

          Another common type is derived from the LDAP authPassword
          scheme (RFC 3112):

          {[
             [ "authPassword-" ^ scheme, authValue, [ "info", authInfo ] ]
          ]}

          The "info" attribute is optional. For instance, if you want to
          provide MD5-hashed passwords:

          {[
             [ "authPassword-MD5", hashed_password, [ "info", salt ] ]

          ]}


          Another common type is derived from the (older) LDAP userPassword
          scheme (RFC 2307):

         {[
            [ "userPassword-" ^ scheme, value, [] ]
         ]}

         More information can be found here: {!Credentials.sasl}

       *)

    type server_session

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

          User name and authorization name are passed in UTF-8 encoding.

          The parameters are given as list [(name,value,critical)]. 
          Critical parameters must be interpreted by the mechanism, and
          unknown critical parameters must be rejected by a [Failure]
          exception. Non-critical parameters are ignored if they are unknown
          to the mechanism.
       *)

    val server_configure_channel_binding :
          server_session -> (string * string) list -> server_session
      (** Configures acceptable channel bindings wiht a list of pairs
          [(type,data)].
       *)

    val server_process_response :
          server_session -> string -> server_session
      (** Process the response from the client. This function must generally
          only be called when the session state is [`Wait]. As an exception,
          however, this function may also be invoked with the initial client
          response, even if the session state is [`Emit], so far the mechanism
          permits at least optionally that the client starts the protocol.
       *)

    val server_process_response_restart :
          server_session -> string -> bool -> server_session * bool
      (** Process the response from the client when another session can be
          continued. The string argument is the initial client response.
          This function must only be called when the state reaches
          [`Restart id] after [server_process_response], and in this case
          the old session with [id] can be restarted. This function
          should be called with the same message string as
          [server_process_repsonse] was just called with.

          If the bool arg is true, a stale response is created. This is
          a special restart which forces the client to run through the
          authentication process again, although everything else was
          successful. (If the protocol does not support the stale flag, it
          is silently ignored.)

          Returns true if the restart is successful. If not, false is
          returned. In this case, the [server_session] object can (and
          should) still be used, but the caller must treat it as new
          session. In particular, the session ID may change.

          All in all, the idea of this function is best illustrated by
          this authentication snippet how to process responses
          (the session cache functions need to be written by the user
          of this module):

          {[
  let update_cache() =
    match server_session_id session with
      | None -> ()
      | Some id ->
          replace_in_session_cache id (server_stash_session session) in

  let rec check_state_after_response() =
    match server_state session with
      | `Restart id ->
           let old_session_s, time = find_in_session_cache id in
           let old_session = server_resume_session ~lookup old_session_s in
           let set_stale = current_time - time > limit in
           let session, cont =
             server_process_response_restart session msg set_stale in
           if not cont then 
             delete_in_session_cache id;
           (* Now check server_state again, should be `Emit now *)
           check_state_after_response()
      | `Emit ->
           let session, out_msg = server_emit_challenge session in
           update_cache();
           ...
      | ... ->
  in
  server_process_response session msg;

          ]}
       *)

    val server_emit_challenge :
          server_session -> server_session * string
      (** Emit a server challenge. This function must only be called when the
          session state is [`Emit].
       *)

    val server_stash_session :
          server_session -> string
      (** Serializes the session as string *)

    val server_resume_session :
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

    val server_user_name : server_session -> string
      (** The name the client has authenticated as (or [Not_found]) *)

    val server_authz_name : server_session -> string
      (** The name the client authorizes as (or [Not_found]) *)

    val server_channel_binding : server_session -> cb
      (** Whether the client suggests or demands channel binding *)

    val server_gssapi_props : server_session ->
                                Netsys_gssapi.server_props
      (** Return the GSSAPI properties of the server, after the authentication
          is successful (and raises Not_found up to then).
       *)

    type client_session

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

          [user] and [authz] must be encoded in UTF-8.

          The parameters are given as list [(name,value,critical)]. 
          Critical parameters must be interpreted by the mechanism, and
          unknown critical parameters must be rejected by a [Failure]
          exception. Non-critical parameters are ignored if they are unknown
          to the mechanism.
       *)

    val client_configure_channel_binding : client_session -> cb -> client_session
      (** Configure GS2-style channel binding *)

    val client_restart : client_session -> client_session
      (** Restart the session for another authentication round. The session
          must be in state [`OK].
       *)

    val client_process_challenge :
          client_session -> string -> client_session
      (** Process the challenge from the server. The state must be [`Wait].
          As an exception, this function can also be called for the initial
          challenge from the server, even if the state is [`Emit].
       *)

    val client_emit_response :
          client_session -> client_session * string
      (** Emit a new response. The state must be [`Emit]. *)

    val client_channel_binding : client_session -> cb
      (** Whether the client suggests or demands channel binding *)

    val client_user_name : client_session -> string
      (** The user name *)

    val client_authz_name : client_session -> string
      (** The authorization name *)

    val client_stash_session :
          client_session -> string
      (** Serializes the session as string *)

    val client_resume_session :
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

    val client_gssapi_props : client_session ->
                                Netsys_gssapi.client_props
      (** Return the GSSAPI properties of the client, after the authentication
          is successful (and raises Not_found up to then).
       *)

  end
