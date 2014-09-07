(* $Id$ *)


(** The profile sets some basic parameters. The common profile to use
    is {!Netmech_scram_sasl.SHA1}
 *)
module type PROFILE = 
  sig
    val hash_function : Netsys_digests.iana_hash_fn
      (** The hash function. We only allow functions where IANA registered
          an official name. Note that SCRAM is currently only specified for
          SHA1, although the hash function is easily exchangable.
       *) 
   val iteration_count_limit : int
      (** The maximum iteration count supported *)
   val announce_channel_binding : bool
      (** Whether servers announce the availability of channel binding by
          adding "-PLUS" to the mechanism name.
       *)
  end

module SHA1 : PROFILE
  (** Uses SHA-1 as hash function. The iteration count is limited to 100000.
      The mechanism name is "SCRAM-SHA-1".
   *)

module SHA1_PLUS : PROFILE
  (** Same as {!Netmech_scam_sasl.SHA1}, only that the mechanism name is
      "SCRAM-SHA-1-PLUS"
   *)

module SCRAM (P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM
  (** Create a new SCRAM SASL mechanism for this profile.

      SCRAM is the most recent challenge/response mechanism specified by
      IETF, and should be preferred over others. See {!Netmech_scram} for
      details.

      {b Notes about [init_credentials]:}

      When used in servers, the credentials can be specified in the special
      "SCRAM-salted-password" format, e.g.

      {[
      let h = PROFILE.hash_function
      let salt = Netmech_scram.create_salt()
      let i = 4096
      let salted_pw = Netmech_scram.salt_password h password salt i
      let creds_l =
        [ "SCRAM-salted-password", salted_pw,
           [ "i", string_of_int i;
             "salt", salt;
           ]
        ]
      let creds = SCRAM.init_credentials creds_l
      ]}

      If existing, the "salted-password" entry takes precedence over a
      normal "password" entry. The parameters "i" and "salt" are needed.
      This format is intended to be stored in authentication databases
      instead of the cleartext password.

      {b Notes about [create_server_session]:}

      The implementation understands the parameter "i", which can be set
      to the iteration count. If omitted, an implementation-defined default
      is used.
   *)

module SCRAM_SHA1 : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA1 profile *)

module SCRAM_SHA1_PLUS : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA1_PLUS profile *)
