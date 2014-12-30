(* $Id$ *)

module PLAIN : Netsys_sasl_types.SASL_MECHANISM
  (** The PLAIN SASL mechanism (RFC 4616).

      Key facts:
       - This mechanism sends user name, authorization name and password
         as cleartext
       - There is no support for channel binding within the mechanism.
       - It is insecure, and should only be used over channels that are
         otherwise secured.

      Parameters:
       - Both [create_client_session] and [create_server_session] accept
         the boolean parameter "mutual". If true, however, authentication
         fails immediately, as mutual authentication cannot be supported.
       - The same is true for the boolean parameter "secure", because
         PLAIN is insecure.


    As for all SASL mechanisms in OCamlnet, SASLprep is not automatically
    called. Users of PLAIN should pass user names and passwords through
    {!Netsaslprep.saslprep}.

   *)
