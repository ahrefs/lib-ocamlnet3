(* $Id$ *)

(** Digest authentication for HTTP *)

module Digest :  Nethttp.HTTP_MECHANISM
  (** This is the standard HTTP digest authentication mechanism
      (see RFC 2069 and 2617). This version does not include mutual
      authentication, i.e. it does not matter what the server responds
      in the Authentication-Info header.

      There is no support for the "auth-int" level of protection.

      How to use with {!Http_client}: You need the adapter
      {!Http_client.generic_auth_handler}, e.g.

      {[
  let m = ( module Netmech_digest_http.Digest )
  let h = new Http_client.generic_auth_handler key_ring [ m ]
  http_pipeline # add_auth_handler h
      ]}

      Get [key_ring] by instantiating {!Http_client.key_ring}.

      Note that the key ring must use UTF-8 encoding (although the
      Digest protocol might need to recode to ISO-8859-1 - note that
      authentication will fail if this is not possible).
   *)

module Digest_mutual :  Nethttp.HTTP_MECHANISM
  (** This is the standard HTTP digest authentication mechanism
      (see RFC 2069 and 2617). This version also authenticates the server
      by checking the Authentication-Info header which must include the
      correct [rspauth] parameter. This parameter proves that the server
      actually knew the password.

      Note that mutual authentication does generally not prevent that
      request data is sent to the server before the authentication
      succeeds. This includes the header and
      also the request body (for POST and PUT methods). Because of this
      it is recommended to ensure that requests not carrying any sensitive
      data precede those requests that need protection.

      See {!Netmech_digest_http.Digest} for tips how to use this mechanism.
   *)



module type PROFILE =
  sig
    val mutual : bool
      (** If true, the Authentication-Info header is checked. If false,
          this header is ignored.
       *)

    val hash_functions : Netsys_digests.iana_hash_fn list
      (** List of enabled hash functions. The mechanism checks whether the
          function is provided by {!Netsys_digests}, and automatically
          removed unavailable hashes. MD5 is always supported.
       *)
  end


module Make_digest(P:PROFILE) : Nethttp.HTTP_MECHANISM
  (** Create a custom version of the digest mechanism *)
