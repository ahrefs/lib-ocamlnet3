(* $Id$ *)

module type SASL_MECHANISM = 
  sig
    val mechanism_name : string
    val client_first : [`Required | `Optional | `No]
    val server_sends_final_data : bool
    val supports_authz : bool
    val plus_channel_binding : bool

    type credentials

    val init_credentials :
          (string * string * (string * string) list) list ->
            credentials

    type server_session
    type server_state =
           [ `Wait | `Emit | `OK | `Auth_error | `Restart of string ]

    val server_state : server_session -> server_state

    val create_server_session :
          lookup:(string -> string -> credentials option) ->
          params:(string * string * bool) list -> 
          unit ->
            server_session

    val server_process_response :
          server_session -> string -> unit
    val server_process_response_restart :
          server_session -> string -> unit
    val server_emit_challenge :
          server_session -> string
    val server_stash_session :
          server_session -> string
    val server_resume_session :
          lookup:(string -> string -> credentials option) ->
          string -> 
             server_session
    val server_session_id : server_session -> string option
    val server_prop : server_session -> string -> string
    val server_user : server_session -> string
    val server_authz : server_session -> string

    type client_session

    type client_state =
           [ `Wait | `Emit | `OK | `Auth_error | `Stale ]
    val client_state : client_session -> client_state

    val create_client_session :
          user:string ->
          authz:string ->
          creds:credentials ->
          params:(string * string * bool) list -> 
          unit ->
            client_session
    val client_restart : client_session -> unit
    val client_process_challenge :
          client_session -> string -> unit
    val client_emit_response :
          client_session -> string
    val client_stash_session :
          client_session -> string
    val client_resume_session :
          string -> 
             client_session
    val client_session_id : client_session -> string option
    val client_prop : client_session -> string -> string
  end
