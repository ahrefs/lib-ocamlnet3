(* $Id$ *)

(** The GS2 bridge for using GSSAPI mechanisms as SASL mechanisms *)

module type PROFILE =
  sig
    val mechanism_name : string
      (** The GS2 version of the mechanism name (w/o "-PLUS" suffix) *)

    val announce_channel_binding : bool
      (** Whether to announce the availability of channel binding by
          adding "-PLUS" to the mechanism name, and by offering
          channel bindings in the initial token.
       *)

    val mechanism_oid : Netsys_gssapi.oid
      (** The OID of the mechanism to use *)

    val client_additional_params : string list
      (** Additional parameters understood by [create_client_session] *)

    val server_additional_params : string list
      (** Additional parameters understood by [create_server_session] *)

    val client_map_user_name : 
           params:(string * string) list ->
           string -> 
             string * Netsys_gssapi.oid
      (** For clients: maps user names to a pair [(name_string,name_type)]
          that can be used in the GSSAPI for acquiring a name. 
          If the [name_type] is the empty
          array, no target name is passed to the GSSAPI.

          The [params] are from the [create_client_session] call.
       *)

    val server_map_user_name : 
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) ->
             string
      (** For servers: maps a pair [(name_string,name_type)] coming from the
          GSSAPI to a user name. The
          [params] are from the [create_server_session] call.

          The function may raise [Not_found] in which case the authentication
          will fail.
       *)

    val client_get_target_name :
           params:(string * string) list ->
             (string * Netsys_gssapi.oid)
      (** For clients: get the GSSAPI name of the target to contact as
          [(name_string,name_type)] pair. If the [name_type] is the empty
         array, no target name is passed to the GSSAPI.

          The [params] are from the [create_client_session] call.
       *)


    val server_bind_target_name :
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) option
      (** For servers: optionally bind the GSSAPI name of the server.  The
          [params] are from the [create_server_session] call.
       *)

    val server_check_target_name :
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) ->
             bool
      (** For servers: check whether the GSSAPI name the client sent is the
          right one. This is a more flexible alternative to 
          [server_bind_target_name]: instead of binding to a single name,
          the client may send any target name, and we check now whether
          this name is acceptable.
          [params] are from the [create_server_session] call.
       *)

    val client_flags :
           params:(string * string) list ->
           ( Netsys_gssapi.req_flag * bool ) list
      (** Flags for [init_sec_context]. The bool says whether the flag is
          required (otherwise the feature is only offered). [`Mutual_flag]
          is always required.
       *)

    val server_flags :
           params:(string * string) list ->
           Netsys_gssapi.req_flag list
      (** Required flags for [accept_sec_context]. [`Mutual_flag]
          is always required.
       *)

    val client_credential : exn option
      (** If set, the client will use a certain credential (and not acquire
          one). This is intended for passing in delegated credentials (well,
          not really elegant). This needs to be set to the [Credential]
          exception of the GSSAPI provider.
       *)

  end


module GS2(P:PROFILE)(GSS:Netsys_gssapi.GSSAPI) : 
         Netsys_sasl_types.SASL_MECHANISM
  (** This is an adapter turning any GSSAPI mechanism into
      a SASL mechanism. This is the "GS2" technique as specified in RFC 5801.
      (Note that in particular for Kerberos there is the other specification
      RFC 4752 which is implemented in {!Netmech_krb5_sasl}.)

      Create the final module like
      {[
module P = struct
  let mechanism_name = "FOO"
  let announce_channel_binding = false
  let mechanism_oid = [| 1; ... |]
  let mechanism_acceptable_oid_set = [ [| 1; ... |]; ... ]
  ...
end

module S = Netmech_gs2_sasl.GS2(P)(Netgss.System)
      ]}

      {b Remarks for clients:}

      The profile specifies how user name strings are mapped to GSSAPI
      names. [authz] names are passed to the server as-is.

     {b Remarks for servers:}

     The profile specifies how GSSAPI names are mapped to user name strings.
     The [lookup] callback is then invoked with this user name, and the
     unaltered [authz] name.

     If [lookup] returns [Some c] for any [c] the user is accepted.
     If it returns [None] the user is declined.

    {b Parameters:}

       - The parameter [mutual] is understood but ignored. Mutual authentication
         is always requested from the GSSAPI mechanism.
       - The parameter [secure] is understood but ignored
         (GSSAPI is considered as secure method)

     {b Statefulness:}

     The GSSAPI is stateful. Our SASL interface is stateless. We cannot hide
     the statefulness of the GSSAPI, and because of this old versions of
     sessions are invalidated. E.g. this does not work

      {[
let s1 = S.server_process_response s0 "some message"
let s2 = S.server_process_response s0 "another message"
      ]}

     and the second attempt to continue with the old session [s0] will fail.

   *)
