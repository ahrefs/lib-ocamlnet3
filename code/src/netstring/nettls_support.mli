(* $Id$ *)

(** Support types and functions for TLS *)

type credentials =
  [ `X509 of Netx509.x509_certificate
  | `Anonymous
  ]
  (** The types of credentials *)
  (* Later: `OpenPGP of XXX | `Username of string *)

type raw_credentials =
  [ `X509 of string
  | `Anonymous
  ]
  (** The encoded credentials:
      - [`X509 s]: The X509 certificate in DER encoding
      - [`Anonymous]: no certificate or other key is available
   *)

type cred_type =
  [ `X509
  | `Anonymous
  ]
  (** The type of credential types *)


(** Direct access to TLS properties of a session *)
class type tls_session_props =
object
  method id : string
    (** The ID of the session (non-printable string) *)
  method addressed_server : string option
    (** The name of the server (for name-based virtual servers). This may
        be unavailable, because this information is exchanged via a TLS
        extension.
     *)
  method cipher_suite_type : string
    (** A string describing the authentication and privacy mechanism that
        is in effect:
         - "X509": X509 certificates are used
         - "OPENPGP": OpenPGP certificates are used
         - "ANON": anonymous credentials
         - "SRP": SRP credentials
         - "PSK": PSK credentials
     *)
  method endpoint_credentials : credentials
    (** Returns the decoded credentials of this endpoint *)
  method endpoint_credentials_type : cred_type
    (** The type of credentials *)
  method endpoint_credentials_raw : raw_credentials
    (** Returns the credentials in the raw form. For X509 certicates,
        this is the DER encoding
     *)
  method peer_credentials : credentials
    (** Returns the decoded peer credentials *)
  method peer_credentials_type : cred_type
    (** The type of credentials *)
  method peer_credentials_raw : raw_credentials
    (** Returns the peer credentials in the raw form. For X509 certicates,
        this is the DER encoding
     *)
  method cipher_algo : string
    (** The name of the algorithm for encrypting the data stream, e.g.
        "AES-128-CBC".
     *)
  method kx_algo : string
    (** The name of the key exchange algorithm, e.g. "RSA" *)
  method mac_algo : string
    (** The name of the data integrity algorithm (actually only the
        digest algorithm for HMAC), e.g. "SHA1" *)
  method compression_algo : string
    (** The name of the compression algorithm (or "NULL"), on the TLS layer.
        E.g. "DEFLATE".
     *)
  method protocol : string
    (** The name of the TLS protocol version, e.g. "TLS1.0" *)
end


val get_tls_session_props : Netsys_crypto_types.tls_endpoint -> 
                              tls_session_props
  (** Get the session properties for an endpoint for which the handshake
      is already done
   *)


val get_tls_user_name : tls_session_props -> string
  (** Get the "user name" of client certificates. It is determined as follows:

       - if there is a subjectAltName with an email address (i.e. rfc822
         type), this address is returned
       - if there is a subjectAltName using the directory name format,
         it is checked whether there is a "uid", "email", or "cn"
         name component
       - otherwise, it is checked whether there is a "uid", "email", or "cn"
         name component in the subject

      Raises [Not_found] if nothing approriate is found.
   *)


val squash_file_tls_endpoint :
      (module Netsys_crypto_types.FILE_TLS_ENDPOINT) ->
      (module Netsys_crypto_types.TLS_ENDPOINT)
  (** Coerce a file endpoint to a normal endpoint *)


val is_endpoint_host : string -> tls_session_props -> bool
  (** [is_endpoint_host name props]: checks whether [name] matches
      the certificate of the endpoint in [props].

      In particular, this function checks the DNS alternate name,
      and the common name of the subject. The certificate name can
      use wildcards.

      Returns true if [name] could be verified this way.

      NB. This doesn't check SNI ([addressed_server]), because this is the
      peer's task.
   *)
