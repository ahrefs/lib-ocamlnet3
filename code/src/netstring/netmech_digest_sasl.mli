(* $Id$ *)

module DIGEST_MD5 : Netsys_sasl_types.SASL_MECHANISM
  (** The DIGEST-MD5 SASL mechanism (RFC 2831).

      This mechanism is only provided to connect to old services; it shouldn't
      be used otherwise.

      Key facts:
       - The password is not sent in the clear
       - Not only authenticates the client to the server, but the client can
         also find out whether the server knew the password, i.e. the server
         is also authenticated.
       - DIGEST-MD5 is vulnerable to man-in-the-middle attacks.
       - The MD5 hash is broken (too weak)
 
      Only "auth" mode is supported (no integrity or privacy protection).

      This implementation rejects servers that offer multiple realms.

      This implementation supports both [server_session_id] (which is the
      nonce) and the [client_session_id] (the cnonce).

      Parameters:
       - [create_server_session] understands: "realm" (optional), "nonce"
         (optional)
       - [server_prop] will return: "realm" (the realm selected by the client),
         "nonce",
         "digest-uri" (once known), "cnonce" (once known), "nc" (once known).
       - [create_client_session] understands: "realm" (optional), "cnonce"
         (optional),
         "digest-uri" (optional). If the digest-uri is not set, it defaults
         to "generic/generic".
       - [client_prop] will return: "cnonce", "realm" (once known; this is
         always the server realm), "nonce" (once known), "nc" (after sending
         the response).
       - The parameters [mutual] and [secure] are understood but ignored
         (there is mutual authentication anyway, and DIGEST is considered as
         secure method)

    As for all SASL mechanisms in OCamlnet, SASLprep is not automatically
    called. Users of DIGEST-MD5 should pass user names and passwords through
    {!Netsaslprep.saslprep}.

   *)
