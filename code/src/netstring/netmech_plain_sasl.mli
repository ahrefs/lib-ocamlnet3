(* $Id$ *)

module PLAIN : Netsys_sasl_types.SASL_MECHANISM
  (** The PLAIN SASL mechanism (RFC 4616).

      Key facts:
       - This mechanism sends user name, authorization name and password
         as cleartext
       - There is no support for channel binding within the mechanism.
       - It is insecure, and should only be used over channels that are
         otherwise secured.
   *)
