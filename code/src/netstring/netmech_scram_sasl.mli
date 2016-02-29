(* $Id$ *)

(** SCRAM as SASL mechanism

    {b This module needs the SHA-1 hash function. In order to use it,
    initialize crypto support, e.g. by including the [nettls-gnutls]
    packages and calling {!Nettls_gnutls.init}.}

    As for all SASL mechanisms in OCamlnet, SASLprep is not automatically
    called. Users of SCRAM should pass user names and passwords through
    {!Netsaslprep.saslprep}.
 *)


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
  (** Same as {!Netmech_scram_sasl.SHA1}, only that the mechanism name is
      "SCRAM-SHA-1-PLUS"
   *)

module SHA256 : PROFILE
  (** Uses SHA-256 as hash function. The iteration count is limited to 100000.
      The mechanism name is "SCRAM-SHA-256".
   *)

module SHA256_PLUS : PROFILE
  (** Same as {!Netmech_scram_sasl.SHA256}, only that the mechanism name is
      "SCRAM-SHA-256-PLUS"
   *)

module SCRAM (P:PROFILE) : Netsys_sasl_types.SASL_MECHANISM
  (** Create a new SCRAM SASL mechanism for this profile.

      SCRAM is the most recent challenge/response mechanism specified by
      IETF, and should be preferred over others. See {!Netmech_scram} for
      details.

      {b Notes about [init_credentials]:}

      When used in servers, the credentials can be specified in the special
      "authPassword-SCRAM-SHA-1" format, e.g.

      {[
      let h = SHA1.hash_function
      let salt = Netmech_scram.create_salt()
      let i = 4096
      let (st_key,srv_key) = Netmech_scram.stored_key h password salt i
      let value =
        Netencoding.Base64.encode st_key ^ ":" ^ 
          Netencoding.Base64.encode srv_key in
      let creds_l =
        [ "authpassword-SCRAM-SHA-1", value,
           [ "info", sprintf "%d:%s" i (Netencoding.Base64.encode salt) ]
        ]
      let creds = SCRAM.init_credentials creds_l
      ]}

      If existing, the "authPassword-*" entry takes precedence over a
      normal "password" entry. The parameter "info" is needed.
      This format is intended to be stored in authentication databases
      instead of the cleartext password (compare with RFC-5803; this is
      intentionally derived from the usual LDAP format for SCRAM credentials).

      {b Notes about [create_server_session]:}

      The implementation understands the parameter "i", which can be set
      to the iteration count. If omitted, an implementation-defined default
      is used.

      {b Parameters}

       - The parameters [mutual] and [secure] are understood but ignored
         (there is mutual authentication anyway, and SCRAM is considered as
         secure method)

   *)

module SCRAM_SHA1 : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA1 profile *)

module SCRAM_SHA1_PLUS : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA1_PLUS profile *)

module SCRAM_SHA256 : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA256 profile *)

module SCRAM_SHA256_PLUS : Netsys_sasl_types.SASL_MECHANISM
  (** SCRAM with SHA256_PLUS profile *)
