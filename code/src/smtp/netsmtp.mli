(* $Id$
 * ----------------------------------------------------------------------
 *)

(**
 * This is an interface for the Simple Mail Tranfer Protocol (SMTP)
 * as specified by RFC 2821.
 *)

open Netchannels

exception Protocol_error
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

  method starttls : Netsys_crypto_types.tls_config -> unit
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
            Uq_engines.default_connect_options) in
  let client =
    new Netsmtp.connect addr 60.0
]}
   *)
