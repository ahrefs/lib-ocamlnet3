(* $Id$ *)

(** User interface for SASL mechanisms *)

type sasl_mechanism = (module Netsys_sasl_types.SASL_MECHANISM)

type credentials =
    (string * string * (string * string) list) list
  (** Credentials are given as list
      [(type,value,params)]. The mechanism may pick any element
      of this list which are considered as equivalent.

      Types are defined per mechanism. All mechanisms understand the
      "password" type, which is just the cleartext password, e.g.

      {[
        [ "password", "ThE sEcReT", [] ]
      ]}
   *)


module Info : sig
  val mechanism_name : sasl_mechanism -> string
  val client_first : sasl_mechanism -> [`Required | `Optional | `No]
      (** Whether the client sends the first message:
           - [`Required]: always
           - [`Optional]: the client may choose to do so if the protocol
             permits this
           - [`No]: the server sends the first message
       *)
  val server_sends_final_data : sasl_mechanism -> bool
      (** Whether final data from the server must be interpreted by the
          mechanism
       *)
  val supports_authz : sasl_mechanism -> bool
      (** whether the authorization name can be transmitted *)
end


module Client : sig

  type session

  val create_session : 
          mech:sasl_mechanism ->
          user:string ->
          authz:string ->
          creds:credentials ->
          params:(string * string * bool) list -> 
          unit ->
            session
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

  val state : session -> Netsys_sasl_types.client_state
    (** report the state (whether expecting challenges or responding) *)

  val configure_channel_binding : session -> Netsys_sasl_types.cb -> session
    (** Configure GS2-style channel binding *)

  val restart : session -> session
      (** Restart the session for another authentication round. The session
          must be in state [`OK].
       *)

  val process_challenge :
        session -> string -> session
    (** Process the challenge from the server. The state must be [`Wait].
        As an exception, this function can also be called for the initial
        challenge from the server, even if the state is [`Emit].
     *)

  val emit_response :
        session -> session * string
    (** Emit a new response. The state must be [`Emit]. *)

  val channel_binding : session -> Netsys_sasl_types.cb
    (** Whether the client suggests or demands channel binding *)

  val user_name : session -> string
    (** The user name *)

  val authz_name : session -> string
    (** The authorization name *)

  val stash_session :
        session -> string
    (** Serializes the session as string *)

  val resume_session :
        sasl_mechanism -> string -> 
           session
    (** Unserializes the session *)

  val session_id : session -> string option
    (** Optionally return a string that can be used to identify the
        client session. Not all mechanisms support this.
     *)

  val prop : session -> string -> string
    (** Get a mechanism-specific property of the session. E.g. this can
        be the "realm" sent by the server.
     *)

  val gssapi_props : session -> Netsys_gssapi.client_props
    (** Get the GSSAPI props, or raise [Not_found] *)

end


module Server : sig
  type session

  type 'credentials init_credentials =
      (string * string * (string * string) list) list -> 'credentials
    (** A function for preparing credentials, provided by the mechanism.
        The credentials are given as list
        [(type,value,params)]. The mechanism may pick any element
        of this list which are considered as equivalent.

        Types are defined per mechanism. All mechanisms understand the
        "password" type, which is just the cleartext password, e.g.

        {[
          [ "password", "ThE sEcReT", [] ]
        ]}
       *)

  type lookup =
      { lookup : 'c . sasl_mechanism -> 'c init_credentials -> string ->
                 string -> 'c option
      }
    (** see [create_session] *)


  val create_session :
        mech:sasl_mechanism ->
        lookup:lookup ->
        params:(string * string * bool) list -> 
        unit ->
            session
      (** Create a new server session. The [lookup] function is used to
          get the credentials for a given user name and a given authorization
          name (which is the empty string if not applicable). If the [lookup]
          function returns [None], the user can either not be found, or the
          user does not have the privileges for the authorization name.

          [lookup] is called as [lookup.lookup mech init_creds user authz]. You
          need to call [init_creds] back in order to prepare the credentials,
          e.g.

          {[
  let f_lookup : 'c . sasl_mechanism -> 'c init_credentials -> string ->
                string -> 'c option =
    fun mech init_creds user authz =
      try
        let password = ... in
        let creds = init_creds [ ("password", password, []) ] in
        Some creds
      with Not_found -> None

  let lookup = {lookup = f_lookup }
          ]}

          User name and authorization name are passed in UTF-8 encoding.

          The parameters are given as list [(name,value,critical)]. 
          Critical parameters must be interpreted by the mechanism, and
          unknown critical parameters must be rejected by a [Failure]
          exception. Non-critical parameters are ignored if they are unknown
          to the mechanism.
       *)

  val process_response :
        session -> string -> session
    (** Process the response from the client. This function must generally
        only be called when the session state is [`Wait]. As an exception,
        however, this function may also be invoked with the initial client
        response, even if the session state is [`Emit], so far the mechanism
        permits at least optionally that the client starts the protocol.
     *)

  val process_response_restart :
        session -> string -> bool -> session * bool
    (** Process the response from the client when another session can be
        continued. The string argument is the initial client response.
        This function must only be called when the state reaches
        [`Restart id] after [process_response], and in this case
        the old session with [id] can be restarted. This function
        should be called with the same message string as
        [process_repsonse] was just called with.

        If the bool arg is true, a stale response is created. This is
        a special restart which forces the client to run through the
        authentication process again, although everything else was
        successful. (If the protocol does not support the stale flag, it
        is silently ignored.)

        Returns true if the restart is successful. If not, false is
        returned. In this case, the [session] object can (and
        should) still be used, but the caller must treat it as new
        session. In particular, the session ID may change.

        All in all, the idea of this function is best illustrated by
        this authentication snippet how to process responses
        (the session cache functions need to be written by the user
        of this module):

        {[
let update_cache() =
  match session_id session with
    | None -> ()
    | Some id ->
        replace_in_session_cache id (stash_session session) in

let rec check_state_after_response() =
  match state session with
    | `Restart id ->
         let old_session_s, time = find_in_session_cache id in
         let old_session = resume_session ~lookup old_session_s in
         let set_stale = current_time - time > limit in
         let cont = process_response_restart session msg set_stale in
         if not cont then 
           delete_in_session_cache id;
         (* Now check state again, should be `Emit now *)
         check_state_after_response()
    | `Emit ->
         let out_msg = emit_challenge session in
         update_cache();
         ...
    | ... ->
in
process_response session msg;

        ]}
     *)

  val emit_challenge :
        session -> session * string
    (** Emit a server challenge. This function must only be called when the
        session state is [`Emit].
     *)

  val stash_session :
        session -> string
    (** Serializes the session as string *)

  val resume_session :
        mech:sasl_mechanism ->
        lookup:lookup ->
        string -> 
           session
    (** Unserializes the session, and connect with the [lookup] function. *)

  val session_id : session -> string option
    (** Optionally return a string that can be used to identify the
        server session. Not all mechanisms support this.
     *)

  val prop : session -> string -> string
    (** Get a mechanism-specific property of the session. E.g. this can
        be the "digest-uri" sent by the client.
     *)

  val gssapi_props : session -> Netsys_gssapi.server_props
    (** Get the GSSAPI props, or raise [Not_found] *)

  val user_name : session -> string
    (** The name the client has authenticated as (or [Not_found]) *)

  val authz_name : session -> string
    (** The name the client authorizes as (or [Not_found]) *)

  val channel_binding : session -> Netsys_sasl_types.cb
    (** Whether the client suggests or demands channel binding *)

end
