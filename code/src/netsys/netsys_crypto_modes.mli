(* $Id$ *)

(** Helpers for crypto modes *)

module Symmetric_cipher : sig
  (** Access symmetric ciphers *)

  type sc_ctx =
      { set_iv : string -> unit;
        set_header : string -> unit;
        encrypt : Netsys_types.memory -> Netsys_types.memory -> unit;
        decrypt : Netsys_types.memory -> Netsys_types.memory -> bool;
        mac : unit -> string;
      }
      
  type sc =
      { name : string;
        mode : string;
        key_lengths : (int * int) list;
        iv_lengths : (int * int) list;
        block_constraint : int;
        supports_aead : bool;
        create : string -> sc_ctx;
      }

  val extract : 
    (module Netsys_crypto_types.SYMMETRIC_CRYPTO) ->
    (string * string) ->
      sc
    (** [extract scrypto (name,mode)]: returns the cipher called
        [name] in [mode] as [scipher], or raises [Not_found]
     *)

  val extract_all : 
    (module Netsys_crypto_types.SYMMETRIC_CRYPTO) ->
      sc list
    (** Extracts all ciphers *)

  val cbc_of_ecb : sc -> sc
    (** For a given cipher in ECB mode, a new cipher in CBC mode is
        returned. Raises [Not_found] if the input is not in ECB mode.
     *)

  val ofb_of_ecb : sc -> sc
    (** For a given cipher in ECB mode, a new cipher in OFB mode is
        returned. Raises [Not_found] if the input is not in ECB mode.
     *)

  val ctr_of_ecb : sc -> sc
    (** For a given cipher in ECB mode, a new cipher in CTR mode is
        returned. Raises [Not_found] if the input is not in ECB mode.
     *)

end

module type CIPHERS = sig val ciphers : Symmetric_cipher.sc list end

module Bundle(C:CIPHERS) : Netsys_crypto_types.SYMMETRIC_CRYPTO
    (** Bundle a list of ciphers as crypto module *)

module Add_modes (SC : Netsys_crypto_types.SYMMETRIC_CRYPTO) :
         Netsys_crypto_types.SYMMETRIC_CRYPTO
    (** Returns a new crypto module where missing modes are added for
        all ECB ciphers. The added modes are CBC, OFB, and CTR.
        Existing ciphers are returned unchanged.
     *)

