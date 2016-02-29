(* $Id$ *)

type cb =
    [ `None
    | `SASL_none_but_advertise
    | `SASL_require of string * string
    | `GSSAPI of string
    ]

type server_state =
  [ `Wait | `Emit | `OK | `Auth_error of string | `Restart of string ]

type client_state =
  [ `Wait | `Emit | `OK | `Auth_error of string | `Stale ]


module type SASL_MECHANISM = 
  sig
    val mechanism_name : string
    val client_first : [`Required | `Optional | `No]
    val server_sends_final_data : bool
    val supports_authz : bool
    val available : unit -> bool

    type credentials

    val init_credentials :
          (string * string * (string * string) list) list ->
            credentials

    type server_session

    val server_state : server_session -> server_state

    val create_server_session :
          lookup:(string -> string -> credentials option) ->
          params:(string * string * bool) list -> 
          unit ->
            server_session
    val server_configure_channel_binding :
          server_session -> (string * string) list -> server_session

    val server_process_response :
          server_session -> string -> server_session
    val server_process_response_restart :
          server_session -> string -> bool -> server_session * bool
    val server_emit_challenge :
          server_session -> server_session * string
    val server_stash_session :
          server_session -> string
    val server_resume_session :
          lookup:(string -> string -> credentials option) ->
          string -> 
             server_session
    val server_session_id : server_session -> string option
    val server_prop : server_session -> string -> string
    val server_user_name : server_session -> string
    val server_authz_name : server_session -> string
    val server_channel_binding : server_session -> cb
    val server_gssapi_props : server_session ->
                                Netsys_gssapi.server_props

    type client_session

    val client_state : client_session -> client_state

    val create_client_session :
          user:string ->
          authz:string ->
          creds:credentials ->
          params:(string * string * bool) list -> 
          unit ->
            client_session
    val client_configure_channel_binding : client_session -> cb -> client_session
    val client_restart : client_session -> client_session
    val client_process_challenge :
          client_session -> string -> client_session
    val client_emit_response :
          client_session -> client_session * string
    val client_channel_binding : client_session -> cb
    val client_user_name : client_session -> string
    val client_authz_name : client_session -> string
    val client_stash_session :
          client_session -> string
    val client_resume_session :
          string -> 
             client_session
    val client_session_id : client_session -> string option
    val client_prop : client_session -> string -> string
    val client_gssapi_props : client_session ->
                                Netsys_gssapi.client_props
  end
