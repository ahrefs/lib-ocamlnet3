(* $Id$
 * ----------------------------------------------------------------------
 *)

(**
 * This is an interface for the Simple Mail Tranfer Protocol (SMTP)
 * as specified by RFC 2821.
 *)

open Netchannels

exception Protocol_error
exception Authentication_error
exception Transient_error of int * string
exception Permanent_error of int * string

val tcp_port : int
(** default TCP port for SMTP *)

(** The class [client] implements the SMTP protocol.  Client objects are created
 * by
 * {[ new client in_ch out_ch]}
 * where [in_ch] is an input channel representing the input direction of the
 * TCP stream, and where [out_ch] is an output channel representing the output
 * direction of the TCP stream.
 *)
                               
class client :
  in_obj_channel -> out_obj_channel ->
object

  method helo : ?host:string -> unit -> string list
    (** Sends an EHLO command to the server.  The optional argument [?host]
     * defaults to the default hostname of the machine.  This function returns
     * the ESMTP lines returned by the server.
     *
     * If EHLO is not supported, the method automatically falls back to
     * HELO.
     *
     * EHLO is specified in RFC 1869.
     *)

  method helo_response : string list
    (** The response from the last HELO or EHLO *)

  method auth : Netsys_sasl.sasl_mechanism -> string -> string -> 
                Netsys_sasl.credentials -> (string * string * bool) list -> unit
    (** [auth mech user authz creds params]: 
        Performs a SASL authentication using the AUTH command. See
        {!Netsys_sasl.Client.create_session} for details.

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

  method authenticated : bool
    (** Whether the [auth] command ran successfully *)

  method mail : string -> unit
    (** Performs a MAIL FROM command. The [string] argument is the mail address
     * (without < >) of the sender.
     *)

  method rcpt : string -> unit
    (** Performs a RCPT TO command.  the [string] argument is one of the mail
     * address the mail has to be sent to.  You have to use that function for
     * each recipient of the mail.
     *
     * If the server returns a 551 error (user relocated, see RFC 2821, section
     * 3.4), the relocated adress is silently used, and the error is not raised
     *)

  method data : in_obj_channel -> unit
    (** This method really send the mail.
     * Do not issue that command without having used [mail] once, and at least
     * [rcpt] once too
     *)
  
  method rset : unit -> unit
    (** Reset the current transaction *)

  method expn : string -> string list option
    (** Expand command : [expn list] will try to expand the Mailing list
     * [list].  If the list cannot be Expanded (reply 252) then [None] is
     * returned.
     *)

  method help : unit -> string list
    (** Performs the Help command.  Returns the server multiline answer.  *)

  method noop : unit -> unit
    (** NOOP : does nothing, keeps the connection alive.  *)

  method quit : unit -> unit
    (** Requests the server to end this session. *)

  method close : unit -> unit 
    (** Closes the file descriptors *)

  method starttls : peer_name:string option -> Netsys_crypto_types.tls_config ->
                    unit
    (** Sends STARTTLS, and negotiates a secure connection. This should
        only be done after EHLO, and only if "STARTTLS" is among the returned
        strings.

        STARTTLS is specified in RFC 3207.

        Note that it is meaningful to submit EHLO again after STARTTLS,
        as the server may now enable more options.
     *)

  method command : string -> int * string list
    (** Sends this command, and returns the status code and the status texts.
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
    `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "www.domain.com", 25),
            Uq_client.default_connect_options) in
  let client =
    new Netsmtp.connect addr 60.0
]}
   *)

val auth_mechanisms : string list -> string list
  (** If applied to [helo_response], returns the list of AUTH mechanisms *)

val authenticate : ?host:string ->
                   ?tls_config:Netsys_crypto_types.tls_config ->
                   ?tls_required:bool ->
                   ?tls_peer:string ->
                   ?sasl_mechs:Netsys_sasl.sasl_mechanism list ->
                   ?sasl_params:(string * string * bool) list ->
                   ?user:string ->
                   ?authz:string ->
                   ?creds:Netsys_sasl.credentials ->
                   client -> unit
  (** Authenticates the session:

      - sends the EHLO string
      - if the server supports TLS, and [tls_config] is set, the
        TLS session is started, and EHLO is repeated
      - if AUTH support is announced by the server, one of the [sasl_mechs]
        is taken and used for authentication. If [sasl_mechs] is empty,
        this authentication step is skipped.

      Options:

      - [host]: the host name of the client
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

      Regarding TLS: note that it is uncommon to require the server to be
      authenticated (opportunistic encryption), because servers often do not
      have certficicates from a regular trust center. You can get such a TLS
      config with

      {[
let tls_config =
  Netsys_tls.create_x509_config
     ~peer_auth:`None
     (Netsys_crypto.current_tls())
      ]}

      SASL example:

{[
Netsmtp.authenticate
  ~sasl_mechs:[ (module Netmech_scram_sasl.SCRAM_SHA1);
                (module Netmech_digest_sasl.DIGEST_MD5);
              ]
  ~user:"tom"
  ~creds:[ "password", "sEcReT", [] ]
  client
]}
   *)

val sendmail : client -> Netmime.complex_mime_message -> unit
  (** Sends the email to the receivers in the [to], [cc], and [bcc] headers.
      The SMTP server must support relaying of emails.
      See also {!Netsendmail.sendmail}.
   *)


(** {1 Debugging} *)

module Debug : sig
  val enable : bool ref
    (** Enables {!Netlog}-style debugging of this module  By default,
        the exchanged Telnet commands are logged. This can be extended
        by setting the [verbose_input] and [verbose_output] options.
     *)
end
