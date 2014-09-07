(* $Id$ *)

module CRAM_MD5 : Netsys_sasl_types.SASL_MECHANISM
  (** The CRAM-MD5 SASL mechanism (RFC 2195), which is obsolete and only
      provided for completeness.

      Key facts:
       - The password is checked with a challenge-response mechanism, and
         does not appear in the clear.
       - The mechanism is vulnerable to man-in-the-middle attacks.
       - The client does not authenticate the server in any way.
       - The hash function MD5 counts as broken.
       - There is no support for channel binding within the mechanism.
       - There is no support for authorization names.
       - The mechanism provides at best medium security, and should only
         be used over channels that are otherwise secured.

      This implementation checks whether the server receives user names
      and passwords in UTF-8 encoding. Note that the mechanism predates
      the widespread use of Unicode, so this may cause interoperability
      issues with old implementations.
   *)


(**/**)

val override_challenge : string -> unit (* debug *)
