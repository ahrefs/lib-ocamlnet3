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
    run a downgrade attack on the authentication method (and replace it by e.g.
    "basic").

    The [Negotiate] authentication method is somewhat special because it
    implicitly authenticates the whole connection, and not only a single
    message. At least this is what MS Windows implements, the reference
    implementation of this authentication method. Other implementations
    nevertheless require per-message authentication, e.g. Apache's 
    mod_auth_kerb. Both behaviors are basically compatible to each other
    if implemented with some care.

    In order to keep authenticated messages somewhat separate, this client
    only submits requests bearing [Negotiate] headers on TCP connections that
    have been specially created for this purpose. Basically, the authenticated
    communication with the server is seen as a separate transport subsystem.
    The flow of requests/responses is as follows:

     - A fresh HTTP request does not carry any authentication data.
       Because of this, it is sent over the normal transports to the server.
     - The server replies with a 401 response and an SPNEGO token.
     - The client authenticates the request (usually this is a one step
       action)
     - The authenticated request cannot be sent over the existing TCP
       connection. A second connection is created which will be used for
       authenticated requests only.
     - The request is sent over this connection.
     - The server responds with content data

    This way we can be sure that requests are handled normally that either
    need not to be authenticated at all, or that are authenticated with
    different methods.

    Technically, the route of the HTTP request depends on the [transport_layer]
    ID.  As long as the HTTP request has an ID of
    {!Nethttp_client.https_trans_id}, it will go over the normal transports.
    If the ID changes to {!Nethttp_client.spnego_trans_id}, the separate
    transports for SPNEGO are used.

    If it is already known that the HTTP request needs to be authenticated
    with SPNEGO, the authentication protocol can be abbreviated by directly
    switching to {!Nethttp_client.spnego_trans_id}:

    {[
c # set_transport_layer Nethttp_client.spnego_trans_id
    ]}
    
    The effect is that only one request/response cycle is needed to process
    the request [c] (except it is the very first request).

    Although GSSAPI mechanisms, and in particular Kerberos often do not
    require a password, you need to set up a "key" object. User and
    password of this key are ignored. The realm, however, must be set to
    the fixed string "SPNEGO" (and {b not} to the Kerberos realm).
    A full example how to use this method:

    {[
module A =
  Netmech_spnego_http.SPNEGO(Netmech_spnego_http.Default)(Netgss.System)

let keys = new Nethttp_client.key_ring ()
let () =
  keys # add_key (key ~user:"" ~password:"" ~realm:"SPNEGO" ~domain:[])
let a = 
  new Nethttp_client.generic_auth_handler
        keys [ (module A : Nethttp.HTTP_MECHANISM) ]
let p = new Nethttp_client.pipeline
let () =
  p # add_auth_handler a
let c = new Nethttp_client.get "https://gps.dynxs.de/krb/"
let () =
  p # add c;
  p # run()
    ]}

   At the moment, this authentication protocol cannot be configured, so
   you always get the default behaviour of GSSAPI.

     {b Statefulness:}

     The GSSAPI is stateful. Our HTTP authentication interface is stateless.
     We cannot hide
     the statefulness of the GSSAPI, and because of this old versions of
     sessions are invalidated. E.g. this does not work

      {[
let s1 = A.client_emit_resonse s0 m1 uri1 hdr1
let s2 = A.client_emit_resonse s0 m2 uri2 hdr2
      ]}

     and the second attempt to continue with the old session [s0] will fail.
 *)

(** Configure {!Netmech_spnego_http} *)
module type PROFILE =
  sig
    val acceptable_transports_http : Nethttp.transport_layer_id list
      (** Which transport IDs are acceptable for authenticated requests
          on unencrypted connections.
          For new requests, the first ID of this list is the preferred ID.
       *)

    val acceptable_transports_https : Nethttp.transport_layer_id list
      (** Which transport IDs are acceptable for authenticated requests
          on HTTPS-secured connections.
          For new requests, the first ID of this list is the preferred ID.
       *)

    val enable_delegation : bool
      (** Whether to allow delegation of the credentials to the server.
          Enabling this means that the server can impersonate the local
          identity, so use with care. Also, getting tokens carrying the
          delegation information can be time-consuming (and the HTTP
          client will simply block while doing so).
       *)

    val deleg_credential : exn option
      (** If you already have a credential, you can set this value to
          the exception [Credential c] (from the GSSAPI provider).
       *)

  end


(** The default profile for {!Netmech_spnego_http}: Use [spnego_trans_id] for
    the https transport, and reject any unencrypted transport (empty list).
    Delegations are off.
 *)
module Default : PROFILE

(** The SPNEGO mechanism for HTTP, see {!Netmech_spnego_http} *)
module SPNEGO(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : Nethttp.HTTP_CLIENT_MECHANISM
