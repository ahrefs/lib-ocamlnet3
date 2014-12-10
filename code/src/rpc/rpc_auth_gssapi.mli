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
      ?require_privacy:bool ->
      ?require_integrity:bool ->
      ?shared_context:bool ->
      (* ?acceptor_cred:credential -> *)   (* TODO *)
      ?user_name_format:user_name_format ->
      ?seq_number_window:int ->
      (module Netsys_gssapi.GSSAPI) -> oid -> Rpc_server.auth_method
  (** Creates an authentication method from a GSS-API interface.
      The OID selects the desired authentication method.

      Options:
      - [require_privacy]: Whether the messages must be
        encrypted. If not enabled, the server also accepts non-encrypted
        messages that are authenticated via GSS-API.
      - [require_integrity]: Whether integrity checksums must be
        included. If not enabled, the server also accepts non-signed
        messages that are authenticated via GSS-API.
      - [shared_context]: Whether this method maintains only one
        security context for all connections. By default,
        each connection has a security context of its own. For UDP,
        this option needs to be set, because each UDP request is
        considered as creating a new connection.
      - [acceptor_cred]: Overrides the credentials of the server. By
        default, it is left to [gss_api] which credential is
        assumed.
      - [user_name_format]: Defaults to [`Prefixed_name].
      - [seq_number_window]: If set, the server checks for replayed
        requests. The integer is the length of the check window (see
        RFC 2203 section 5.3.3.1). If omitted, no such checks are
        performed (the default). 
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
