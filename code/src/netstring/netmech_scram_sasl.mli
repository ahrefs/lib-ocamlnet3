(* $Id$ *)

module type PROFILE = 
  sig
    val hash_function : Netsys_digests.iana_hash_fn
    val return_unknown_user : bool
    val iteration_count_limit : int
  end

module SHA1_permissive : PROFILE
  (** This profile:
        - Servers indicate when users are unknown
        - iteration_count_limit = 100000
   *)

module SHA1_restrictive : PROFILE
  (** This profile:
        - Servers do not indicate when users are unknown, and just claim
          that the password is wrong
        - iteration_count_limit = 100000
   *)

module SCRAM (P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM
