(* $Id$
 * ----------------------------------------------------------------------
 *)

(**
 * This is an interface for the Post Office Protocol - Version 3
 * (POP3) as specifed by RFC 1939. The protocol is intended to permit
 * a workstation to dynamically access a maildrop on a server host in
 * a useful fashion.
 *)

open Netchannels

type state = 
  [ `Authorization
  | `Transaction
  | `Update
  ]

exception Protocol_error
exception Authentication_error
exception Err_status of string
exception Bad_state

val tcp_port : int
(** Default TCP port for POP version 3 *)

(** The class [client] implements the POP3 protocol. Client objects
 * are created by
 * {[ new client in_ch out_ch ]}
 * where [in_ch] is an input channel representing the input direction of
 * the TCP stream, and where [out_ch] is an output channel representing
 * the output direction of the TCP stream.
 *)
class client : 
  in_obj_channel -> out_obj_channel ->
object

  method state : state
    (** Current state of this session. *)

  method capabilities : (string * string list) list
    (** The result of the last [capa] command *)

  (* General Commands *)

  method capa : unit -> (string * string list) list
    (** Requests a list of capabilities  (RFC 2449). Returns the empty list
        if [capa] is not understood.
     *)

  method quit : unit -> unit
    (** Requests the server to end this session. If the session is 
     * currently in the [`Transaction] state, the server will attempt
     * to remove all messages marked as deleted before closing its 
     * side of the connection.
     *)

  method close : unit -> unit
     (** Closes the file descriptors *)

  (* Authorization Commands *)

  method user : user:string -> unit
    (** Specifies the name of the mailbox the client would like to open
       using plain-text authentication. Normal completion of this function
       should be followed by the [pass] command. *)

  method pass : pass:string -> unit
    (** Authenticates a user with the plain-text password [pass]. *)

  method apop : user:string -> pass:string -> unit
    (** Specifies the user and password using APOP authentication.
     * APOP is a more secure method of authentication than what is
     * provided by the [user]/[pass] command sequence.
     *)

  method auth : Netsys_sasl.sasl_mechanism -> string -> string -> 
                Netsys_sasl.credentials -> (string * string * bool) list -> unit
    (** [auth mech user authz creds params]: 
        Performs a SASL authentication using the AUTH command (RFC 5034). See
        {!Netsys_sasl.Client.create_session} for details about SASL.

        Example:
   {[
client # auth
  (module Netmech_digest_sasl.DIGEST_MD5)
  "user"
  ""
  [ "password", "sEcReT", [] ]
  []
   ]}
     *)

  (* Transaction Commands *)

  method stat : unit -> int * int * string
    (** Returns information about the current mailbox as tuple
     * [(count,size,ext)] where [count] is the number of messages in 
     * the mailbox, [size] is the size of the mailbox in octets, 
     * and [ext] is any server extension data.
     *)

  method list : ?msgno:int -> unit -> (int,int * string) Hashtbl.t
    (** Returns the scan listing for an optional message number or
     * for all messages in the current mailbox. The result is a hash
     * table that maps a message number to a tuple [(size,ext)] where
     * [size] is the size of the message in octets, and [ext] is any 
     * server extension data.
     *)

  method retr : msgno:int -> in_obj_channel
    (** Retrieves a message from the server. *)

  method dele : msgno:int -> unit
    (** Marks the message number of the current mailbox for deletion. *)

  method noop : unit -> unit
    (** Pings the server to keep the session alive. *)

  method rset : unit -> unit
    (** Unmarks any messages that have previously been marked as
     * deleted.
     *)

  method top  : ?lines:int -> msgno:int -> unit -> in_obj_channel
    (** Returns the message header plus a limited number of lines
     * of the message body. The default body length is 0 lines.
     *)

  method uidl : ?msgno:int -> unit -> (int,string) Hashtbl.t
    (** Returns the unique identifier(s) for an optional message number
     * or for all messages in the current mailbox. The result is a
     * hash table that maps a message number to its unique id.
     *)

  method stls : peer_name:string option -> Netsys_crypto_types.tls_config ->
                    unit
    (** Sends STLS (STARTTLS), and negotiates a secure connection.
        Raises [Err_state] if TLS is unavailable on the server.

        STLS is specified in RFC 2595.
     *)

  method tls_endpoint : Netsys_crypto_types.tls_endpoint option
    (** Returns the TLS endpoint (after [STARTTLS]) *)

  method tls_session_props : Nettls_support.tls_session_props option
    (** Returns the TLS session properties (after [STARTTLS]) *)

  method gssapi_props : Netsys_gssapi.client_props option
    (** Returns GSSAPI properties, if available *)
end


class connect : ?proxy:#Uq_engines.client_endpoint_connector ->
                Uq_engines.connect_address ->
                float ->
                  client
  (** [connect addr timeout]: Connects with the server at [addr], and
      configure that I/O operations time out after [timeout] seconds of
      waiting.

      Example:
{[
  let addr =
    `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "www.domain.com", 110),
            Uq_client.default_connect_options) in
  let client =
    new Netpop.connect addr 60.0
]}
   *)


val authenticate : ?tls_config:Netsys_crypto_types.tls_config ->
                   ?tls_required:bool ->
                   ?tls_peer:string ->
                   ?sasl_mechs:Netsys_sasl.sasl_mechanism list ->
                   ?sasl_params:(string * string * bool) list ->
                   ?user:string ->
                   ?authz:string ->
                   ?creds:Netsys_sasl.credentials ->
                   client -> unit
  (** Authenticates the session:

      - requests capabilitlies
      - if the server supports TLS, and [tls_config] is set, the
        TLS session is started, and the capabilities are refreshed.
      - if SASL support is announced by the server, one of the [sasl_mechs]
        is taken and used for authentication. If [sasl_mechs] is empty,
        this authentication step is skipped.

      Options:

      - [tls_config]: if set, TLS is tried on the connection
      - [tls_required]: if set, it is even required that TLS is supported.
        If not, a {!Netsys_types.TLS_error} exception is raised.
      - [tls_peer]: the host name of the server (only needed for TLS, and
        only needed if the TLS configuration authenticates the server, or
        if the SNI extension is active)
      - [sasl_mechs]: available SASL mechanisms (in order of preference).
        If you pass mechanisms, you'll normally also need to pass [user]
        and [creds].
      - [sasl_params]: parameters for SASL. A "digest-uri" parameter is
        always generated, and need not to be set
      - [user]: the user name to authenticate as
      - [authz]: the identity to act as (authorization name)
      - [creds]: credentials

     You can get a simple TLS configuration with:

     {[
let tls_config =
  Netsys_tls.create_x509_config
    ~system_trust:true
    ~peer_auth:`Required
    (Netsys_crypto.current_tls())
     ]}

      SASL example:

{[
Netpop.authenticate
  ~sasl_mechs:[ (module Netmech_scram_sasl.SCRAM_SHA1);
                (module Netmech_digest_sasl.DIGEST_MD5);
              ]
  ~user:"tom"
  ~creds:[ "password", "sEcReT", [] ]
  client
]}
   *)


(** {1 Debugging} *)

module Debug : sig
  val enable : bool ref
    (** Enables {!Netlog}-style debugging of this module  By default,
        the exchanged Telnet commands are logged. This can be extended
        by setting the [verbose_input] and [verbose_output] options.
     *)
end
