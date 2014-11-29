(* $Id$ *)

(** SPNEGO (GSSAPI) authentication for HTTP *)

(** This module enables the [Negotiate] authentication method for HTTP,
    which is an encapsulation of the SPNEGO protocol. SPNEGO in turn is
    a layer on top of GSSAPI, and adds mechanism negotiation.

    This is the usual way of kerberizing HTTP.

    This implementation of the [Negotiate] method requires a HTTPS connection
    by default. Running it over unencrypted HTTP would be possible, but we
    don't do it because the additional security can be easily lost. In
    particular, a man-in-the-middle could steal credentials, or he could
    run a downgrade attack on the authentication method (replace it by e.g.
    "basic").

    The [Negotiate] authentication method is somewhat special because it
    implicitly authenticates the whole connection, and not only a single
    message. Because of this, we treat it differently: The HTTP client keeps
    separate connections for authenticated SPNEGO in addition to the
    normal unauthenticated connections. When a request is added to the client,
    it is first submitted to the unauthenticated connection. If the server
    requests [Negotiate], the request is resubmitted on the authenticated
    connection. Because of this you normally see two request/response
    cycles for the first message sent to a server.

    The second, authenticated transport carries a transport ID of
    {!Http_client.spnego_trans_id}. Note that you can directly route the
    request to this transport by requesting this ID in the HTTP [call].

    Although GSSAPI mechanisms, and in particular Kerberos often do not
    require a password, you need to set up a "key" object. User and
    password of this key are ignored. The realm, however, must be set to
    the fixed string "SPNEGO" (and {b not] to the Kerberos realm).
    A full example how to use this method:

    {[
module A =
  Netmech_spnego_http.SPNEGO(Netmech_spnego_http.Default)(Netgss.System)

let keys = new Http_client.key_ring ()
let () =
  keys # add_key (key ~user:"" ~password:"" ~realm:"SPNEGO" ~domain:[])
let a = 
  new Http_client.generic_auth_handler
        keys [ (module A : Nethttp.HTTP_MECHANISM) ]
let p = new Http_client.pipeline
let () =
  p # add_auth_handler a
let c = new Http_client.get "https://gps.dynxs.de/krb/"
let () =
  p # add c;
  p # run()
    ]}

 *)


(** Configure {!Netmech_spnego_http} *)
module type PROFILE =
  sig
    val acceptable_transports : Nethttp.transport_layer_id list
      (** Which transport IDs are acceptable for authenticated requests.
          For new requests, the first ID of this list is the preferred ID.
       *)

    val https_required : bool
      (** Whether HTTPS is required *)
  end


(** The default profile for {!Netmech_spnego_http}: Use [spnego_trans_id] for
    the transport, and require HTTPS
 *)
module Default : PROFILE

(** The SPNEGO mechanism for HTTP, see {!Netmech_spnego_http} *)
module SPNEGO(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : Nethttp.HTTP_MECHANISM
