(* $Id$ *)

module type PROFILE = 
  sig
    val hash_function : Netsys_digests.iana_hash_fn
    val iteration_count_limit : int
  end

module SHA1 : PROFILE

module SCRAM (P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM
