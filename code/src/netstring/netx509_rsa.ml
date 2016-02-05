(* details in RFC-3447 *)

(* 
  type private_key_v0 =
    { modulus : XXX;
      public_exponent : int;
      private_exponent : int;
      prime1 : XXX;
      prime2 : XXX;
      exponent1 : XXX;
      exponent2 : XXX;
      coefficient : XXX;
    }

  type other_prime_info =
    { opi_prime : XXX;
      opi_exponent : XXX;
      opi_coefficient : XXX
    }

  type private_key =
    | V0 of private_key_v0
    | V1 of private_key_v0 * other_prime_info list

  val decode_der : string -> private_key

(*
val v : Netasn1.Value.value =
  Netasn1.Value.Seq
   [Netasn1.Value.Integer <abstr>; Netasn1.Value.Integer <abstr>;
    Netasn1.Value.Integer <abstr>; Netasn1.Value.Integer <abstr>;
    Netasn1.Value.Integer <abstr>; Netasn1.Value.Integer <abstr>;
    Netasn1.Value.Integer <abstr>; Netasn1.Value.Integer <abstr>;
    Netasn1.Value.Integer <abstr>]
 *)

  type public_key =
    { modulus : XXX;
      exponent : int;
    }

(*
val v : Netasn1.Value.value =
  Netasn1.Value.Seq
   [Netasn1.Value.Seq
     [Netasn1.Value.OID [|1; 2; 840; 113549; 1; 1; 1|]; Netasn1.Value.Null];
    Netasn1.Value.Bitstring <abstr>]
let Netasn1.Value.Seq[_; Netasn1.Value.Bitstring bs] = v;;
let pubkey = Netasn1.Value.get_bitstring_data bs;;
let n,pubkey_der = Netasn1.decode_ber pubkey;;                        
val n : int = 270
val pubkey_der : Netasn1.Value.value =
  Netasn1.Value.Seq
   [Netasn1.Value.Integer <abstr>; Netasn1.Value.Integer <abstr>]

 *)

 *)
