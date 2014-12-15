#use "topfind";;
#require "netstring";;

open Netasn1


let hdr001 () =
  let s = "\x04\x08PQRSTUVWXYZ" in
  let (hdr_len, tc, pc, tag, len_opt) = decode_ber_header s in
  hdr_len = 2 && tc = Value.Universal && pc = Value.Primitive && 
    tag = 4 && len_opt = Some 8


let hdr002 () =
  let s = "\x04\x81\xc9" in
  let (hdr_len, tc, pc, tag, len_opt) = 
    decode_ber_header ~skip_length_check:true s in
  hdr_len = 3 && tc = Value.Universal && pc = Value.Primitive && 
    tag = 4 && len_opt = Some 201


let hdr003 () =
  let s = "\x24\x80" in
  let (hdr_len, tc, pc, tag, len_opt) = 
    decode_ber_header ~skip_length_check:true s in
  hdr_len = 2 && tc = Value.Universal && pc = Value.Constructed && 
    tag = 4 && len_opt = None


let prim001 () =
  let s = "\x04\x08PQRSTUVWXYZ" in
  let (len, v) = decode_ber s in
  len = 10 && v = Value.Octetstring "PQRSTUVW"


let prim002 () =
  let s = "\x01\x01\x00" in
  let (len, v) = decode_ber s in
  len = 3 && v = Value.Bool false

let prim003 () =
  let s = "\x01\x01\x01" in
  let (len, v) = decode_ber s in
  len = 3 && v = Value.Bool true

let prim004 () =
  let s = "\x02\x01\x00" in
  let (len, v) = decode_ber s in
  len = 3 && 
    (match v with
       | Value.Integer i -> Value.get_int i = 0
       | _ -> false
    )

let prim005 () =
  let s = "\x02\x01\x05" in
  let (len, v) = decode_ber s in
  len = 3 && 
    (match v with
       | Value.Integer i -> Value.get_int i = 5
       | _ -> false
    )

let prim006 () =
  let s = "\x02\x02\x3f\xf0" in
  let (len, v) = decode_ber s in
  len = 4 && 
    (match v with
       | Value.Integer i -> Value.get_int i = 0x3ff0
       | _ -> false
    )

let prim007 () =
  let s = "\x02\x02\x81\xf0" in
  let (len, v) = decode_ber s in
  len = 4 && 
    (match v with
       | Value.Integer i -> Value.get_int i = 0x81f0 - 0x10000
       | _ -> false
    )

let prim008 () =
  let s = "\x06\x03\x81\x34\x03" in
  let (len, v) = decode_ber s in
  len = 5 && v = Value.OID [| 2; 100; 3 |]


let prim009 () =
  let s = "\x0d\x03\x81\x34\x03" in
  let (len, v) = decode_ber s in
  len = 5 && v = Value.ROID [| 180; 3 |]


let constr001 () =
  let s = "\x24\x0c\x04\x05ABCDE\x04\x03FGH" in
  let (len, v) = decode_ber s in
  len = 14 && v = Value.Octetstring "ABCDEFGH"


let constr002 () =
  let s = "\x2c\x0c\x04\x05ABCDE\x04\x03FGH" in
  let (len, v) = decode_ber s in
  len = 14 && v = Value.UTF8String "ABCDEFGH"


let constr003 () =
  let s = "\x2c\x12\x04\x05ABCDE\x24\x09\x04\x03FGH\x04\x02IJ" in
  let (len, v) = decode_ber s in
  len = 20 && v = Value.UTF8String "ABCDEFGHIJ"


let constr004 () =
  let s = "\x2c\x80\x04\x05ABCDE\x04\x03FGH\x00\x00" in
  let (len, v) = decode_ber s in
  len = 16 && v = Value.UTF8String "ABCDEFGH"


let constr005 () =
  let s = "\x2c\x14\x04\x05ABCDE\x24\x80\x04\x03FGH\x04\x02IJ\x00\x00" in
  let (len, v) = decode_ber s in
  len = 22 && v = Value.UTF8String "ABCDEFGHIJ"


let constr006 () =
  let s =
    "\x2c\x17\x04\x05ABCDE\x24\x80\x04\x03FGH\x04\x02IJ\x00\x00\x04\x01K" in
  let (len, v) = decode_ber s in
  len = 25 && v = Value.UTF8String "ABCDEFGHIJK"


let constr007 () =
  let s =
    "\x2c\x80\x04\x05ABCDE\x24\x80\x04\x03FGH\x04\x02IJ\x00\x00\x04\x01K\x00\x00" in
  let (len, v) = decode_ber s in
  len = 27 && v = Value.UTF8String "ABCDEFGHIJK"


let tagged001 () =
  let s = "\x81\x05ABCDE" in
  let (len, v) = decode_ber s in
  len = 7 && v = Value.Tagptr(Value.Context, 1, Value.Primitive, s, 2, 5)


let tagged002 () =
  let s = "\xa1\x0c\x04\x05ABCDE\x04\x03FGH" in
  let (len, v) = decode_ber s in
  len = 14 && v = Value.Tagptr(Value.Context, 1, Value.Constructed, s, 2, 12)

let tagged003 () =
  let s = "\xa1\x0c\x04\x05ABCDE\x04\x03FGH" in
  let (len, v) = decode_ber s in
  match v with
    | Value.Tagptr(_, _, Value.Constructed, s, pos, len) ->
        let (ilen, iv) = 
          decode_ber_contents
            ~pos ~len s Value.Constructed Type_name.UTF8String in
        ilen = 12 && iv = Value.UTF8String "ABCDEFGH"
    | _ ->
        false

let tagged004 () =
  let s = "\xa1\x80\x04\x05ABCDE\x04\x03FGH\x00\x00" in
  let (len, v) = decode_ber s in
  match v with
    | Value.Tagptr(_, _, Value.Constructed, s, pos, len) ->
        let (ilen, iv) = 
          decode_ber_contents
            ~pos ~len s Value.Constructed Type_name.UTF8String in
        ilen = 12 && iv = Value.UTF8String "ABCDEFGH"
    | _ ->
        false

let seq001 () =
  let s = "\x30\x0c\x04\x05ABCDE\x04\x03FGH" in
  let (len, v) = decode_ber s in
  len = 14 && 
    v = Value.Seq [ Value.Octetstring "ABCDE"; Value.Octetstring "FGH" ]

let seq002 () =
  let s = "\x30\x80\x04\x05ABCDE\x04\x03FGH\x00\x00" in
  let (len, v) = decode_ber s in
  len = 16 && 
    v = Value.Seq [ Value.Octetstring "ABCDE"; Value.Octetstring "FGH" ]


let bits001 () =
  let s = "\x03\x02\x00\xfc" in
  let (len, v) = decode_ber s in
  len = 4 && 
    match v with
      | Value.Bitstring b ->
          Value.get_bitstring_bits b =
            [| true; true; true; true; true; true; false; false |]
      | _ ->
          false

let bits002 () =
  let s = "\x03\x02\x02\xdc" in
  let (len, v) = decode_ber s in
  len = 4 && 
    match v with
      | Value.Bitstring b ->
          Value.get_bitstring_bits b =
            [| true; true; false; true; true; true |]
      | _ ->
          false
  
let bits003 () =
  let s = "\x23\x08\x03\x02\x00\x99\x03\x02\x07\x80" in
  let (len, v) = decode_ber s in
  len = 10 && 
    match v with
      | Value.Bitstring b ->
          Value.get_bitstring_bits b =
            [| true; false; false; true;
               true; false; false; true;
               true
              |]
      | _ ->
          false


let bits004 () =
  let s = "\x23\x80\x03\x02\x00\x99\x03\x02\x07\x80\x00\x00" in
  let (len, v) = decode_ber s in
  len = 12 && 
    match v with
      | Value.Bitstring b ->
          Value.get_bitstring_bits b =
            [| true; false; false; true;
               true; false; false; true;
               true
              |]
      | _ ->
          false


let complex001 () =
  let s = "\x30\x13\x02\x01\x05\x16\x0e\x41\x6e\x79\x62\x6f\x64\x79\x20\x74\x68\x65\x72\x65\x3f" in
  let (len, v) = decode_ber s in
  len = 21 && 
    match v with
      | Value.Seq [ Value.Integer i; Value.IA5String s ] ->
          Value.get_int i = 5 &&
          s = "Anybody there?"
      | _ -> false


let pem =
  (* Just one certificate from /etc/ssl/certs/ca-certificates.txt *)
  "MIIEuDCCA6CgAwIBAgIBBDANBgkqhkiG9w0BAQUFADCBtDELMAkGA1UEBhMCQlIx
EzARBgNVBAoTCklDUC1CcmFzaWwxPTA7BgNVBAsTNEluc3RpdHV0byBOYWNpb25h
bCBkZSBUZWNub2xvZ2lhIGRhIEluZm9ybWFjYW8gLSBJVEkxETAPBgNVBAcTCEJy
YXNpbGlhMQswCQYDVQQIEwJERjExMC8GA1UEAxMoQXV0b3JpZGFkZSBDZXJ0aWZp
Y2Fkb3JhIFJhaXogQnJhc2lsZWlyYTAeFw0wMTExMzAxMjU4MDBaFw0xMTExMzAy
MzU5MDBaMIG0MQswCQYDVQQGEwJCUjETMBEGA1UEChMKSUNQLUJyYXNpbDE9MDsG
A1UECxM0SW5zdGl0dXRvIE5hY2lvbmFsIGRlIFRlY25vbG9naWEgZGEgSW5mb3Jt
YWNhbyAtIElUSTERMA8GA1UEBxMIQnJhc2lsaWExCzAJBgNVBAgTAkRGMTEwLwYD
VQQDEyhBdXRvcmlkYWRlIENlcnRpZmljYWRvcmEgUmFpeiBCcmFzaWxlaXJhMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwPMudwX/hvm+Uh2b/lQAcHVA
isamaLkWdkwP9/S/tOKIgRrL6Oy+ZIGlOUdd6uYtk9Ma/3pUpgcfNAj0vYm5gsyj
Qo9emsc+x6m4VWwk9iqMZSCK5EQkAq/Ut4n7KuLE1+gdftwdIgxfUsPt4CyNrY50
QV57KM2UT8x5rrmzEjr7TICGpSUAl2gVqe6xaii+bmYR1QrmWaBSAG59LrkrjrYt
bRhFboUDe1DK+6T8s5L6k8c8okpbHpa9veMztDVC9sPJ60MWXh6anVKo1UcLcbUR
yEeNvZneVRKAAU6ouwdjDvwlsaKydFKwed0ToQ47bmUKgcm+wV3eTRk36UOnTwID
AQABo4HSMIHPME4GA1UdIARHMEUwQwYFYEwBAQAwOjA4BggrBgEFBQcCARYsaHR0
cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0RQQ2FjcmFpei5wZGYwPQYDVR0f
BDYwNDAyoDCgLoYsaHR0cDovL2FjcmFpei5pY3BicmFzaWwuZ292LmJyL0xDUmFj
cmFpei5jcmwwHQYDVR0OBBYEFIr68VeEERM1kEL6V0lUaQ2kxPA3MA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQAZA5c1
U/hgIh6OcgLAfiJgFWpvmDZWqlV30/bHFpj8iBobJSm5uDpt7TirYh1Uxe3fQaGl
YjJe+9zd+izPRbBqXPVQA34EXcwk4qpWuf1hHriWfdrx8AcqSqr6CuQFwSr75Fos
SzlwDADa70mT7wZjAmQhnZx2xJ6wfWlT9VQfS//JYeIc7Fue2JNLd00UOSMMaiK/
t79enKNHEA2fupH3vEigf5Eh4bVAN5VohrTm6MY53x7XQZZr1ME7a55lFEnSeT0u
mlOAjR2mAbvSM5X5oSZNrmetdzyTj2flCM8CC7MLab0kkdngRIlUBGHF1/S5nmPb
K+9A46sd33oqK8n8"

let complex002 () =
  let s = Netencoding.Base64.decode ~accept_spaces:true pem in
  let (len, v) = decode_ber s in
  len = 1212







let test f n =
  try
    if f() then
      print_endline ("Test " ^ n ^ " ok")
    else
      print_endline ("Test " ^ n ^ " FAILED!!!!");
    flush stdout
  with
    | error ->
        let bt = Printexc.get_backtrace() in
        print_endline ("Test " ^ n ^ ": Exception " ^ Netexn.to_string error ^ 
                         ", backtrace: " ^ bt);
        flush stdout
;;


let () =
  Printexc.record_backtrace true;
  test hdr001 "hdr001";
  test hdr002 "hdr002";
  test hdr003 "hdr003";
  test prim001 "prim001";
  test prim002 "prim002";
  test prim003 "prim003";
  test prim004 "prim004";
  test prim005 "prim005";
  test prim006 "prim006";
  test prim007 "prim007";
  test prim008 "prim008";
  test prim009 "prim009";
  test constr001 "constr001";
  test constr002 "constr002";
  test constr003 "constr003";
  test constr004 "constr004";
  test constr005 "constr005";
  test constr006 "constr006";
  test constr007 "constr007";
  test tagged001 "tagged001";
  test tagged002 "tagged002";
  test tagged003 "tagged003";
  test tagged004 "tagged004";
  test seq001 "seq001";
  test seq002 "seq002";
  test bits001 "bits001";
  test bits002 "bits002";
  test bits003 "bits003";
  test bits004 "bits004";
  test complex001 "complex001";
  test complex002 "complex002"


