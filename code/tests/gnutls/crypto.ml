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


let run_aead title f (expected_result, expected_mac) =
  printf "Test %s: %!" title;
  try
    let r, mac = f() in
    if r <> expected_result then (
      printf "EXPECTED:\n";
      print_hex expected_result;
      printf "ACTUAL:\n";
      print_hex r;
      failwith "unexpected result"
    );
    if mac <> expected_mac then (
      printf "EXPECTED MAC:\n";
      print_hex expected_mac;
      printf "ACTUAL:\n";
      print_hex mac;
      failwith "unexpected MAC"
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

let test_encrypt_aead name mode key iv data hdr () =
  let n = String.length data in
  let cipher = find (name,mode) in
  let ctx1 = create cipher key in
  let ctx2 = create cipher key in
  set_iv ctx1 iv;
  set_header ctx1 hdr;
  set_iv ctx2 iv;
  set_header ctx2 hdr;
  let m1 = Netsys_mem.memory_of_string data in
  let m2 = Bigarray.Array1.create Bigarray.char Bigarray.c_layout n in
  let m3 = Bigarray.Array1.create Bigarray.char Bigarray.c_layout n in
  Bigarray.Array1.fill m2 'X';
  Bigarray.Array1.fill m3 'X';
  encrypt ctx1 m1 m2;
  let mac1 = mac ctx1 in
  let ok = decrypt ctx2 m2 m3 in
  if not ok then failwith "decrypt error";
  let s2 = Netsys_mem.string_of_memory m2 in
  let s3 = Netsys_mem.string_of_memory m3 in
  if s3 <> data then failwith "decryption does not restore plaintext";
  let mac2 = mac ctx2 in
  if mac1 <> mac2 then failwith "bad MAC";
  (s2, mac1)

(* Test data *)

let d1 =
  "\xc8\x6c\xe3\x24\x0e\xe8\x00\x1e\x91\x78\x29\xe4\x25\xc3\x92\x09\
   \xc5\xe7\x47\x83\xc2\x79\xe9\x40\xf1\xa3\xeb\x3c\x6a\xe6\x0b\x78\
   \x70\xf5\x5f\x63\x0b\x90\xa2\xbf\xe4\xaf\xec\xeb\xcf\xcb\xa6\xf5\
   \x77\x98\xf3\x1f\x56\x93\xa0\x1e\x91\xca\xd5\x00\x85\x5e\x31\xf1"

let d_gcm =
  "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\
   \x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\
   \x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\
   \xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39"

let a_gcm =
  "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\
   \xab\xad\xda\xd2"

let iv_gcm =
  "\x93\x13\x22\x5d\xf8\x84\x06\xe5\x55\x90\x9c\x5a\xff\x52\x69\xaa\
   \x6a\x7a\x95\x38\x53\x4f\x7d\xa1\xe4\xc3\x03\xd2\xa3\x18\xa7\x28\
   \xc3\xc0\xc9\x51\x56\x80\x95\x39\xfc\xf0\xe2\x42\x9a\x6b\x52\x54\
   \x16\xae\xdb\xf5\xa0\xde\x6a\x57\xa6\x37\xb3\x9b"

let k8 = "01234567"
let k16 = "0123456789abcdef"

let k16_gcm = "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08"

let no_iv = ""  
let iv8 = "fedcba98"
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

let d1_aes128_ofb =
  "\xc3\x27\x35\x55\xf8\x98\x7f\x17\x29\x40\xea\x32\xef\xdf\xf8\x34\
   \x8d\x63\x67\xc0\xbd\x03\xcd\xa4\x53\x3a\x59\x5a\x74\x4e\xf5\x9b\
   \x6b\xbe\x78\x92\xcd\x97\x74\xc9\xa5\xb7\xe0\x8b\x01\x3e\x2d\xfe\
   \xfe\x00\xd4\x4b\x37\x66\x86\xd3\x75\x0d\x1c\x50\x64\x47\x43\x70"

let d1_aes128_ctr =
  "\xc3\x27\x35\x55\xf8\x98\x7f\x17\x29\x40\xea\x32\xef\xdf\xf8\x34\
   \x87\x82\xab\xba\x6d\xde\x64\xcf\x17\x5b\xba\x8a\xd8\x6f\x7c\x59\
   \xf4\x4f\xad\x2d\xeb\xa1\xdd\xc1\xab\xfe\x7f\x7f\x7c\xd0\x8e\x2b\
   \x81\x63\xa9\x66\xf7\x2b\x26\xf4\x5f\xfb\x3c\x90\x40\xc8\xd1\xcf"

(* GCM test vectors from 
   http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 *)

let d_aes128_gcm =
  "\x8c\xe2\x49\x98\x62\x56\x15\xb6\x03\xa0\x33\xac\xa1\x3f\xb8\x94\
   \xbe\x91\x12\xa5\xc3\xa2\x11\xa8\xba\x26\x2a\x3c\xca\x7e\x2c\xa7\
   \x01\xe4\xa9\xa4\xfb\xa4\x3c\x90\xcc\xdc\xb2\x81\xd4\x8c\x7c\x6f\
   \xd6\x28\x75\xd2\xac\xa4\x17\x03\x4c\x34\xae\xe5"

let d_aes128_mac =
  "\x61\x9c\xc5\xae\xff\xfe\x0b\xfa\x46\x2a\xf4\x3c\x16\x99\xd0\x50"

let () =
  run "aes-128-ecb"
      (test_encrypt "AES-128" "ECB" k16 no_iv d1)
      d1_aes128_ecb

let () =
  run "aes-128-cbc"
      (test_encrypt "AES-128" "CBC" k16 iv16 d1)
      d1_aes128_cbc

let () =
  run "aes-128-ofb"
      (test_encrypt "AES-128" "OFB" k16 iv16 d1)
      d1_aes128_ofb

let () =
  run "aes-128-ctr"
      (test_encrypt "AES-128" "CTR" k16 iv16 d1)
      d1_aes128_ctr

let have_aes_gcm =
  try ignore(find ("AES-128","GCM")); true with Not_found -> false

let () =
  if have_aes_gcm then
    run_aead "aes-128-gcm"
             (test_encrypt_aead "AES-128" "GCM" k16_gcm iv_gcm d_gcm a_gcm)
             (d_aes128_gcm, d_aes128_mac)

(* CAST *)

(* In OpenSSL this is cast5 *)

let d1_cast128_ecb =
  "\x0d\xb3\xf7\xed\x53\x86\xce\x8a\x0f\xe9\xc0\x0a\x46\x38\x96\xb0\
   \x9d\xb8\x76\x3f\xfa\x38\x78\x2f\x71\x86\x7b\x11\x7e\xd5\x2c\x06\
   \x2d\x0e\x28\xef\x42\xaa\x1f\x8e\x59\xf8\x9c\x87\x14\xf9\xd6\x1d\
   \x7d\xd0\x5b\xa8\xa3\x07\xf2\xdb\x48\xaf\x6c\xff\x3d\xad\x02\xa5"

let d1_cast128_cbc =
  "\xca\xcd\xa4\x9d\x1b\x6d\x38\x80\xae\x5f\x2f\x9e\x4b\x98\x11\xdc\
   \xa0\x03\x5c\x11\x26\x6a\x3f\xbe\x9f\x24\x5e\x2f\xc7\xb5\xbe\x24\
   \x58\x29\x99\xd0\xca\xfc\xbd\x1b\xae\x87\x84\x55\xc3\xb2\x77\x6b\
   \xdb\x49\x62\x02\x10\xdc\x09\xb8\x3c\x7c\xa0\x79\x60\xf6\xb4\x9a"

let d1_cast128_ofb =
  "\xf9\xe1\xd0\x98\x17\xe6\x2a\x16\xc4\xbe\xce\x5e\x1a\x11\x70\x9a\
   \x2f\xa4\x2c\x8c\x9f\x7b\xb5\x46\x3e\xcf\xa6\xb1\xbb\x68\x85\xe7\
   \xc9\x2e\x9b\x27\xe5\xf4\x75\xe8\x58\x6e\xff\x0e\x7f\x2b\xc4\x66\
   \x6a\xa7\x9d\x32\x9e\x5f\xfd\x12\x50\xaa\x7a\x34\x50\x37\x09\x80"

let () =
  run "cast-128-ecb"
      (test_encrypt "CAST-128" "ECB" k16 no_iv d1)
      d1_cast128_ecb

let () =
  run "cast-128-cbc"
      (test_encrypt "CAST-128" "CBC" k16 iv8 d1)
      d1_cast128_cbc

let () =
  run "cast-128-ofb"
      (test_encrypt "CAST-128" "OFB" k16 iv8 d1)
      d1_cast128_ofb

(* DES *)

let d1_des_ecb =
  "\x40\x9b\xc8\x65\xf3\xa8\xa1\x91\xfa\xcc\x1a\x13\x70\xd8\xc2\x34\
   \xbf\x1c\x52\x48\x79\xc0\x4d\xde\x25\xd3\xda\xb0\xd6\xbd\xf0\x7b\
   \xc7\xb2\x6d\xf9\xc3\xa0\xfb\xbd\x9a\x2d\x24\x72\x6c\x6f\x39\x3f\
   \x24\xae\xd7\x18\x58\x3d\xf9\x45\x2e\x88\x60\x29\x38\x20\xd5\x21"

let d1_des_cbc =
  "\xc9\x33\xf1\x67\x03\x44\xab\x28\x7f\x10\xf1\xc4\x3e\x03\x52\x5c\
   \xc3\xd4\xec\x4e\x2f\xc5\x60\x94\x6d\xf9\xfb\xa8\xb5\x71\x98\x5d\
   \x9f\x18\xee\x2f\x3f\xaa\xee\x46\xcc\xf9\x2d\xfe\x75\x4c\xd0\x3d\
   \x2d\x0e\xdd\x8a\x01\x61\xb6\x18\xcd\xd0\x5f\xd1\x11\x4a\x5c\xa2"


let () =
  run "des-56-ecb"
      (test_encrypt "DES-56" "ECB" k8 no_iv d1)
      d1_des_ecb

let () =
  run "des-56-cbc"
      (test_encrypt "DES-56" "CBC" k8 iv8 d1)
      d1_des_cbc


(* RC4 *)

let d1_rc4 =
  "\x4c\x04\xa3\x7d\xf3\xa6\xa0\x86\x98\x8e\x73\x7a\xe5\x50\xc1\x4c\
   \x27\x0a\x6f\x53\x4e\x48\x12\x2a\x1d\xe5\xa6\x93\x30\xd1\x6c\x7c\
   \x7d\x13\x92\x77\x39\xfe\x19\xdc\xc1\x12\x31\xf0\xad\x97\x67\xf9\
   \xd3\x34\x97\xa4\x63\x0a\xc1\xd9\x61\x94\xec\x2f\x8a\xe9\xe3\xa7"

let () =
  run "arcfour-128"
      (test_encrypt "ARCFOUR-128" "STREAM" k16 no_iv d1)
      d1_rc4
