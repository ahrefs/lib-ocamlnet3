(* $Id$ *)

(** GSS-API for RPC authentication *)

open Netsys_gssapi

type user_name_format =
    [ `Exported_name
    | `Prefixed_name
    | `Plain_name
    ]
  (** What to return as user name:
      - [`Exported_name]: the exported name in binary format (as described
        in RFC 2078, section 3.2). This format can only be read back by
        the [gss_api] object generating the name.
      - [`Prefixed_name]: the display name in a text format
        "[{<oid>}<namestring>]".
      - [`Plain_name]: the string part of the display name
   *)

val server_auth_method : 
      ?shared_context:bool ->
      ?user_name_format:user_name_format ->
      ?seq_number_window:int ->
      ?max_age:float ->
      (module Netsys_gssapi.GSSAPI) -> 
      Netsys_gssapi.server_config -> Rpc_server.auth_method
  (** Creates an authentication method from a GSS-API interface.

      Options:
      - [shared_context]: Whether this method maintains only one
        security context for all connections. By default,
        each connection has a security context of its own. For UDP,
        this option needs to be set, because each UDP request is
        considered as creating a new connection.
      - [user_name_format]: Defaults to [`Prefixed_name].
      - [seq_number_window]: If set, the server checks for replayed
        requests. The integer is the length of the check window (see
        RFC 2203 section 5.3.3.1). If omitted, no such checks are
        performed (the default). 
      - [max_age]: The maximum lifetime for security contexts (in seconds).
        If not specified, the time is taken from the GSSAPI credential.
   *)

type support_level =
    [ `Required | `If_possible | `None ]

type user_name_interpretation =
    [ `Exported_name
    | `Prefixed_name
    | `Plain_name of oid
    ]

val client_auth_method :
      ?user_name_interpretation:user_name_interpretation ->
      (module Netsys_gssapi.GSSAPI) -> 
      Netsys_gssapi.client_config ->
        Rpc_client.auth_method
  (** Creates an authentication method from a GSS-API interface.

      Options:
      - [user_name_format]: Defaults to [`Prefixed_name].
   *)

module Debug : sig
  val enable : bool ref
end
