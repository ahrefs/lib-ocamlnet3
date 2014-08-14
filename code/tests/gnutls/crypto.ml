open Nettls_gnutls.Symmetric_crypto
open Printf

let print_hex s =
  let l = String.length s in
  for k = 0 to l - 1 do
    printf " %02x" (Char.code s.[k]);
    if (k+1) mod 16 = 0 then printf "\n"
  done;
  if l mod 16 <> 0 then printf "\n"

let run title f expected_result =
  printf "Test %s: %!" title;
  try
    let r = f() in
    if r <> expected_result then (
      printf "EXPECTED:\n";
      print_hex expected_result;
      printf "ACTUAL:\n";
      print_hex r;
      failwith "unexpected result"
    );
    printf "ok\n%!";
  with
    | error ->
         printf "error: %s\n%!" (Printexc.to_string error)


let test_encrypt name mode key iv data () =
  let n = String.length data in
  let cipher = find (name,mode) in
  let ctx1 = create cipher key in
  let ctx2 = create cipher key in
  set_iv ctx1 iv;
  set_iv ctx2 iv;
  let m1 = Netsys_mem.memory_of_string data in
  let m2 = Bigarray.Array1.create Bigarray.char Bigarray.c_layout n in
  let m3 = Bigarray.Array1.create Bigarray.char Bigarray.c_layout n in
  Bigarray.Array1.fill m2 'X';
  Bigarray.Array1.fill m3 'X';
  encrypt ctx1 m1 m2;
  let ok = decrypt ctx2 m2 m3 in
  if not ok then failwith "decrypt error";
  let s2 = Netsys_mem.string_of_memory m2 in
  let s3 = Netsys_mem.string_of_memory m3 in
  if s3 <> data then failwith "decryption does not restore plaintext";
  s2

(* Test data *)

let d1 =
  "\xc8\x6c\xe3\x24\x0e\xe8\x00\x1e\x91\x78\x29\xe4\x25\xc3\x92\x09\
   \xc5\xe7\x47\x83\xc2\x79\xe9\x40\xf1\xa3\xeb\x3c\x6a\xe6\x0b\x78\
   \x70\xf5\x5f\x63\x0b\x90\xa2\xbf\xe4\xaf\xec\xeb\xcf\xcb\xa6\xf5\
   \x77\x98\xf3\x1f\x56\x93\xa0\x1e\x91\xca\xd5\x00\x85\x5e\x31\xf1"

let k8 = "01234567"
let k16 = "0123456789abcdef"

let no_iv = ""  
let iv16 = "fedcba9876543210"

(* AES-128 *)

let d1_aes128_ecb =
  "\x09\xb6\x8a\x43\x18\xf9\x81\x74\x78\x76\x68\x9b\x91\xf9\xf5\xaf\
   \x2e\xcd\xc1\x68\xb7\xeb\x12\x7a\x58\x0c\xf9\xb7\xcb\x80\x3d\xef\
   \x34\xda\x3b\x6e\x61\x6a\x56\xcb\x5a\x7a\x7e\xb4\xd3\xd8\xaa\xd2\
   \x08\x70\x34\x93\xc5\x1b\x23\x4e\xa3\x0e\x6f\xd0\xa6\xee\x18\xf2"

(* openssl enc -aes-128-ecb -K 30313233343536373839616263646566 -e -in d1 -nopad -nosalt  *)

let d1_aes128_cbc =
  "\xab\x76\xbc\x68\x9f\x82\xcd\xe4\xf3\x47\x51\xf1\xf3\x8c\x54\x49\
   \xc5\xed\x72\xd9\xf5\xf5\x2a\x1a\x46\xb0\x19\x0f\x26\xbe\xbd\xb2\
   \x26\x73\x54\xc4\x66\x51\x30\xa1\x72\x91\xc4\x23\x2b\xc2\xce\x3b\
   \x94\x92\x40\x28\x7b\x74\x78\xfd\xee\xc1\x6a\x32\x86\x26\x09\x24"

(* openssl enc -aes-128-cbc -K 30313233343536373839616263646566 -iv 66656463626139383736353433323130 -e -in d1 -nopad -nosalt *)

let () =
  run "aes-128-ecb"
      (test_encrypt "AES-128" "ECB" k16 no_iv d1)
      d1_aes128_ecb

let () =
  run "aes-128-cbc"
      (test_encrypt "AES-128" "CBC" k16 iv16 d1)
      d1_aes128_cbc

