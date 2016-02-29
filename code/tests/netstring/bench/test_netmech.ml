#use "topfind";;
#require "netstring";;
#require "nettls-gnutls";;

open Printf

let verbose = ref false;;

(match Sys.argv with
   | [| _; "-verbose" |] -> verbose := true
   | _ -> ()
);;


let contains ~pat s =
  let p = Netaux.KMP.make_pattern pat in
  let k = Netaux.KMP.find_pattern p s in
  k <= String.length s - String.length pat


let is_auth_error =
  function
  | `Auth_error _ -> true
  | _ -> false

let test_sasl
      ?(check_final_client = fun _ -> true)
      ?(check_final_server = fun _ -> true)
      ?(check_client_props = [])
      ?(check_server_props = [])
      (m:(module Netsys_sasl_types.SASL_MECHANISM))
      client_creds server_creds
      client_params server_params
      user authz
  =
  let module M = (val m) in
  let sc = M.init_credentials server_creds in
  let lookup = (fun _ _ -> Some sc) in
  let ss = ref (M.create_server_session ~lookup ~params:server_params()) in

  let cc = M.init_credentials client_creds in
  let cs =
    ref (M.create_client_session ~user ~authz ~creds:cc ~params:client_params()) in
  
  assert((M.server_state !ss = `Emit && M.client_state !cs = `Wait && 
            M.client_first <> `Required) ||
           (M.server_state !ss = `Wait && M.client_state !cs = `Emit && 
              M.client_first = `Required));

  let stop = ref false in
  let last_server = ref "" in
  let last_client = ref "" in
  while not !stop do
    (* Emit server challenge and process it on the client *)
    if M.server_state !ss = `Emit then (
      let ss', msg = M.server_emit_challenge !ss in
      ss := ss';
      assert(M.server_state !ss = `Wait || M.server_sends_final_data);
      if !verbose then
        printf "S: %S\n%!" msg;
      last_server := msg;

      assert(M.client_state !cs = `Wait);
      let cs' = M.client_process_challenge !cs msg in
      cs := cs';

      stop := (M.client_state !cs = `OK || is_auth_error (M.client_state !cs));
    );
    (* Emit client response and process it on the server *)
    if M.client_state !cs = `Emit || M.client_state !cs = `Stale then (
      let cs', msg = M.client_emit_response !cs in
      cs := cs';
      if !verbose then
        printf "C: %S\n%!" msg;
      last_client := msg;

      assert(M.server_state !ss = `Wait);
      let ss' = M.server_process_response !ss msg in
      ss := ss';

      stop := (M.client_state !cs = `OK || is_auth_error (M.client_state !cs) ||
                 M.server_state !ss = `OK || is_auth_error (M.server_state !ss))
    )
  done;

  assert(M.server_state !ss = `OK || is_auth_error (M.server_state !ss));

  (* It is possible that the server reaches `Auth_error, but the client
     is not told that via SASL, but with the normal protocol.
   *)
  assert((M.server_state !ss = `OK && M.client_state !cs = `OK) ||
           is_auth_error (M.server_state !ss));

  assert(check_final_server !last_server);
  assert(check_final_client !last_client);

  List.iter
    (fun (k,v) ->
       assert(M.server_prop !ss k = v)
    )
    check_server_props;
  List.iter
    (fun (k,v) ->
       assert(M.client_prop !cs k = v)
    )
    check_client_props;

  M.server_state !ss


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


let t_plain_01() =
  let creds = [ "password", "sEcReT", [] ] in
  let r =
    test_sasl
      (module Netmech_plain_sasl.PLAIN) creds creds [] [] "user" "admin" in
  r = `OK


let t_plain_02() =
  let s_creds = [ "password", "sEcReT", [] ] in
  let c_creds = [ "password", "wrong", [] ] in
  let r =
    test_sasl
      (module Netmech_plain_sasl.PLAIN) c_creds s_creds [] [] "user" "admin" in
  is_auth_error r


let t_crammd5_01() =
  let creds = [ "password", "sEcReT", [] ] in
  let r =
    test_sasl
      (module Netmech_crammd5_sasl.CRAM_MD5) creds creds [] [] "user" "" in
  r = `OK

let t_crammd5_02() =
  let s_creds = [ "password", "sEcReT", [] ] in
  let c_creds = [ "password", "wrong", [] ] in
  let r =
    test_sasl
      (module Netmech_crammd5_sasl.CRAM_MD5)
      c_creds s_creds [] [] "user" "" in
  is_auth_error r

let t_crammd5_03() =
  (* The example from RFC 2195 *)
  Netmech_crammd5_sasl.override_challenge "1896.697170952@postoffice.reston.mci.net";
  let creds = [ "password", "tanstaaftanstaaf", [] ] in
  let r =
    test_sasl
      ~check_final_client:(fun msg ->
                           msg = "tim b913a602c7eda7a495b4e6e7334d3890")
      (module Netmech_crammd5_sasl.CRAM_MD5) creds creds [] [] "tim" "" in
  r = `OK


let t_digestmd5_01() =
  let creds = [ "password", "sEcReT", [] ] in
  let s_params = [ "realm", "kingdom of apples", true ] in
  let c_params = [ "digest-uri", "orange/mango", true ] in
  let r =
    test_sasl
      ~check_client_props:[ "realm", "kingdom of apples";
                            "digest-uri", "orange/mango" ]
      (module Netmech_digest_sasl.DIGEST_MD5) 
      creds creds c_params s_params "user" "" in
  r = `OK

let t_digestmd5_02() =
  let s_creds = [ "password", "sEcReT", [] ] in
  let c_creds = [ "password", "wrong", [] ] in
  let r =
    test_sasl
      (module Netmech_digest_sasl.DIGEST_MD5)
      c_creds s_creds [] [] "user" "" in
  is_auth_error r


let t_digestmd5_03() =
  (* the example from RFC 2831 *)
  let creds = [ "password", "secret", [] ] in
  let s_params = [ "realm", "elwood.innosoft.com", true;
                   "nonce", "OA6MG9tEQGm2hh", true ] in
  let c_params = [ "digest-uri", "imap/elwood.innosoft.com", true;
                   "cnonce", "OA6MHXh6VqTrRk", true ] in
  let r =
    test_sasl
      ~check_client_props:[ "realm", "elwood.innosoft.com";
                            "digest-uri", "imap/elwood.innosoft.com" ]
      ~check_final_client:(fun msg ->
                             contains ~pat:"response=\"d388dad90d4bbd760a152321f2143af7\"" msg
                          )
      ~check_final_server:(fun msg ->
                             contains ~pat:"rspauth=\"ea40f60335c427b5527b84dbabcdfffd\"" msg
                          )
      (module Netmech_digest_sasl.DIGEST_MD5) 
      creds creds c_params s_params "chris" "" in
  r = `OK


let t_scramsha1_01() =
  let creds = [ "password", "sEcReT", [] ] in
  let s_params = [] in
  let c_params = [] in
  let r =
    test_sasl
      (module Netmech_scram_sasl.SCRAM_SHA1) 
      creds creds c_params s_params "user" "" in
  r = `OK


let t_scramsha1_02() =
  let s_creds = [ "password", "sEcReT", [] ] in
  let c_creds = [ "password", "wrong", [] ] in
  let r =
    test_sasl
      (module Netmech_scram_sasl.SCRAM_SHA1)
      c_creds s_creds [] [] "user" "" in
  is_auth_error r


let t_scramsha1_03() =
  (* example from RFC-5802 *)
  let i = 4096 in
  let salt_b64 = "QSXCR+Q6sek8bf92" in
(*
  let salt = Netencoding.Base64.decode salt_b64 in
  let h = Netmech_scram_sasl.SHA1.hash_function in
  let (st_key,srv_key) = Netmech_scram.stored_key h "pencil" salt i in
  let value =
        Netencoding.Base64.encode st_key ^ ":" ^ 
          Netencoding.Base64.encode srv_key in
 *)
  let value = "6dlGYMOdZcOPutkcNY8U2g7vK9Y=:D+CSWLOshSulAsxiupA+qs2/fTE=" in
  let s_creds = [ "authPassword-SCRAM-SHA-1", 
                  value,
                  [ "info", sprintf "%d:%s" i salt_b64 ]
                ] in
  let c_creds = [ "password", "pencil", [] ] in
  let s_params = [ "nonce", "3rfcNHYJY1ZVvWVs7j", true ] in
  let c_params = [ "nonce", "fyko+d2lbbFgONRv9qkxdawL", true ] in
  let r =
    test_sasl
      ~check_final_client:(fun msg ->
                             contains ~pat:"p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=" msg
                          )
      ~check_final_server:(fun msg ->
                             contains ~pat:"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=" msg
                          )
      (module Netmech_scram_sasl.SCRAM_SHA1) 
      c_creds s_creds c_params s_params "user" "" in
  r = `OK


let t_scramsha256_01() =
  (* example from SCRAM-256/HTTP draft *)
  let i = 4096 in
  let salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==" in
  let salt = Netencoding.Base64.decode salt_b64 in
  let h = `SHA_256 in
  let (st_key,srv_key) = Netmech_scram.stored_key h "pencil" salt i in
  let value =
        Netencoding.Base64.encode st_key ^ ":" ^ 
          Netencoding.Base64.encode srv_key in
  let s_creds = [ "authPassword-SCRAM-SHA-256", 
                  value,
                  [ "info", sprintf "%d:%s" i salt_b64 ]
                ] in
  let c_creds = [ "password", "pencil", [] ] in
  let s_params = [ "nonce", "%hvYDpWUa2RaTCAfuxFIlj)hNlF", true ] in
  let c_params = [ "nonce", "rOprNGfwEbeRWgbNEkqO", true ] in
  let r =
    test_sasl
      ~check_final_client:(fun msg ->
                             true
                             (*contains ~pat:"p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=" msg*)
                          )
      ~check_final_server:(fun msg ->
                             true
                             (*contains ~pat:"v=rmF9pqV8S7suAoZWja4dJRkFsKQ=" msg*)
                          )
      (module Netmech_scram_sasl.SCRAM_SHA256) 
      c_creds s_creds c_params s_params "user" "" in
  r = `OK


let () =
  test t_plain_01 "t_plain_01";
  test t_plain_02 "t_plain_02";

  test t_crammd5_01 "t_crammd5_01";
  test t_crammd5_02 "t_crammd5_02";
  test t_crammd5_03 "t_crammd5_03";

  test t_digestmd5_01 "t_digestmd5_01";
  test t_digestmd5_02 "t_digestmd5_02";
  test t_digestmd5_03 "t_digestmd5_03";

  test t_scramsha1_01 "t_scramsha1_01";
  test t_scramsha1_02 "t_scramsha1_02";
  test t_scramsha1_03 "t_scramsha1_03";

  test t_scramsha256_01 "t_scramsha256_01";
