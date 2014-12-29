#use "topfind";;
#require "netstring";;

(* There is extensive test data in
   http://www.unicode.org/Public/3.2-Update/NormalizationTest-3.2.0.txt
   but I haven't found time to use it
 *)

open Printf
open Netsaslprep

let test f n =
  printf "Test %s %!" n;
  try
    if f() then
      print_endline "ok"
    else
      print_endline "FAILED!!!!";
    flush stdout
  with
    | error ->
        let bt = Printexc.get_backtrace() in
        print_endline ("Test " ^ n ^ ": Exception " ^ Netexn.to_string error ^ 
                         ", backtrace: " ^ bt);
        flush stdout
;;


let t_rfc4013() =
  (* The few tests from RFC 4013 *)
  let b1 = 
    (* I<U+00AD>X *)
    saslprep_a [| 73; 173; 88; |] = [| 73; 88 |] in
  let b2 = 
    (* user *)
    saslprep_a [| 117; 115; 101; 114 |] = [| 117; 115; 101; 114 |] in
  let b3 =
    (* USER *)
    saslprep_a [| 85; 83; 69; 82 |] = [| 85; 83; 69; 82 |] in
  let b4 =
    (* <U+00AA> *)
    saslprep_a [| 170 |] = [| 97 |] in
  let b5 =
    (* <U+2168> *)
    saslprep_a [| 8552 |] = [| 73; 88 |] in
  let b6 =
    (* <U+0007> *)
    try ignore(saslprep_a [| 7 |]); false with SASLprepError -> true in
  let b7 = 
    (* <U+0627><U+0031> *)
    try ignore(saslprep_a [| 1575; 49 |]); false 
    with SASLprepError -> true in
  b1 && b2 && b3 && b4 && b5 && b6 && b7


let a_ring = 0xc5
let d_dot_above = 0x1e0a
let d_dot_below = 0x1e0c
let e_macron = 0x112
let e_macron_grave = 0x1e14
let e_grave = 0xc8
let dot_above = 0x307
let dot_below = 0x323
let grave = 0x300
let macron = 0x304
let ring = 0x30a
let horn = 0x31b
let angstrom = 0x212b


let t_nfkc_1() =
  (* from http://www.unicode.org/reports/tr15/tr15-22.html *)
  let b1 =
    saslprep_a [| d_dot_above |] = [| d_dot_above |] in
  let b2 =
    saslprep_a [| 68; dot_above |] = [| d_dot_above |] in
  let b3 =
    saslprep_a [| d_dot_below; dot_above |] = [| d_dot_below; dot_above |] in
  let b4 =
    saslprep_a [| d_dot_above; dot_below |] = [| d_dot_below; dot_above |] in
  let b5 =
    saslprep_a [| 68; dot_above; dot_below |] = [| d_dot_below; dot_above |] in
  let b6 =
    saslprep_a [| 68; dot_above; horn; dot_below |] =
               [| d_dot_below; horn; dot_above |] in
  b1 && b2 && b3 && b4 && b5 && b6


let t_nfkc_2() =
  (* from http://www.unicode.org/reports/tr15/tr15-22.html *)
  let b1 =
    saslprep_a [| e_macron_grave |] = [| e_macron_grave |] in
  let b2 =
    saslprep_a [| e_macron; grave |] = [| e_macron_grave |] in
  let b3 =
    saslprep_a [| e_grave; macron |] = [| e_grave; macron |] in
  let b4 =
    saslprep_a [| angstrom |] = [| a_ring |] in
  let b5 =
    saslprep_a [| a_ring |] = [| a_ring |] in
  b1 && b2 && b3 && b4 && b5


let ffi = 0xfb03
let a_uml = 0xc4
let roman_iv = 0x2163

let t_nfkc_3() =
  (* from http://www.unicode.org/reports/tr15/tr15-22.html *)
  let b1 =
    (* Äffin w/o ffi *)
    saslprep_a [| a_uml; 102; 102; 105; 110 |] =
               [| a_uml; 102; 102; 105; 110 |] in
  let b2 =
    (* Äffin w/ ffi *)
    saslprep_a [| a_uml; ffi; 110 |] = [| a_uml; 102; 102; 105; 110 |] in
  let b3 =
    (* H IV (well, the text says Henry IV but this is so long) *)
    saslprep_a [| 72; 32; 73; 86 |] =  [| 72; 32; 73; 86 |] in
  let b4 =
    (* same with roman numeral *)
    saslprep_a [| 72; 32; roman_iv |] = [| 72; 32; 73; 86 |] in
  b1 && b2 && b3 && b4


let ga = 0x30ac
let ka = 0x30ab
let ten = 0x3099
let hw_ka = 0xff76
let hw_ten = 0xff9e

let t_nfkc_4() =
  (* from http://www.unicode.org/reports/tr15/tr15-22.html *)
  let b1 =
    saslprep_a [| ga |] = [| ga |] in
  let b2 =
    saslprep_a [| ka; ten |] = [| ga |] in
  let b3 =
    saslprep_a [| hw_ka; hw_ten |] = [| ga |] in
  let b4 =
    saslprep_a [| ka; hw_ten |] = [| ga |] in
  let b5 =
    saslprep_a [| hw_ka; ten |] = [| ga |] in
  b1 && b2 && b3 && b4 && b5


let () =
  test t_rfc4013 "t_rfc4013";
  test t_nfkc_1 "t_nfkc_1";
  test t_nfkc_2 "t_nfkc_2";
  test t_nfkc_3 "t_nfkc_3";
  test t_nfkc_4 "t_nfkc_4"

