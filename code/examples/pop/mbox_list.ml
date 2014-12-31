(* Copyright (c) 2000 Patrick Doane.
 * For conditions of distribution and use, see copyright notice in LICENSE, *)

open Netchannels
open Printf

module U = Unix

let () =
  Nettls_gnutls.init()

let bracket
    (before : 'a -> 'b)
    (after : 'b -> unit)
    (f : 'b -> 'c)
    (init : 'a) =
  let x = before init in
  let res =
    try f x with exn -> after x; raise exn
  in
  after x;
  res

let prompt ?(echo=true) s =
  output_string stdout s;
  flush stdout;
  if echo then
    input_line stdin
  else
    let fd = U.descr_of_in_channel stdin in
    let tio = U.tcgetattr fd in
    let old_echo = tio.U.c_echo in
    bracket
      (fun () ->
	(* Modify terminal settings to turn echo off *)
	tio.U.c_echo <- false;
	U.tcsetattr fd U.TCSADRAIN tio)
      (fun () ->
	(* Restore terminal settings *)
	tio.U.c_echo <- old_echo;
	U.tcsetattr fd U.TCSADRAIN tio;
	output_char stdout '\n';
	flush stdout)
      (fun _ ->
	(* Get password from stdin *)
	input_line stdin
      ) ()

let connect_to (server, port) =
  let inet_addr = (U.gethostbyname server).U.h_addr_list.(0) in
  let addr = U.ADDR_INET (inet_addr, port) in
  U.open_connection addr

let close_connection (ic,oc) =
  U.shutdown_connection ic;
  close_out oc

let make_connection server port f =
  bracket connect_to close_connection f (server,port)

let pop3_session =
  bracket 
    (fun (ic,oc) -> new Netpop.client
      (new input_channel ic) (new output_channel oc))
    (fun sess -> 
      printf "Closing mailbox...\n"; flush stdout; 
      sess#quit ())

let main () =
  let user = Netsaslprep.saslprep (prompt "User: ") in
  let server = prompt "Hostname: " in
  let passwd = Netsaslprep.saslprep (prompt ~echo:false "Password: ") in
  let tls_config = 
    Netsys_tls.create_x509_config
      ~system_trust:true
      ~peer_auth:`Required    (* try `None if TLS does not work *)
      (Netsys_crypto.current_tls()) in
  try
    make_connection server Netpop.tcp_port (pop3_session
      (fun sess ->
        printf "Trying to start TLS...\n%!";
        Netpop.authenticate
          ~tls_config
          ~tls_peer:server
          sess;
        if sess#tls_endpoint <> None then
          printf "TLS succeeded\n%!"
        else
          printf "No TLS\n%!";
	printf "Attempting authentication...\n%!";
        ( try
            Netpop.authenticate
              ~sasl_mechs:[ (module Netmech_scram_sasl.SCRAM_SHA1);
                            (module Netmech_digest_sasl.DIGEST_MD5);
                            (module Netmech_crammd5_sasl.CRAM_MD5);
                            (module Netmech_plain_sasl.PLAIN);
                          ]
              ~user
              ~creds:[ "password", passwd, [] ]
              ~sasl_params:[ "secure", 
                             string_of_bool (sess#tls_endpoint = None),
                             true ]
              (* i.e. if there is no TLS, disallow insecure SASL mechs *)
              sess;
          with
            | Netpop.Authentication_error ->
                 printf "SASL failed, trying APOP\n%!";
                 ( try
	           sess#apop user passwd;
	           with _ when sess#tls_endpoint <> None ->
	             printf "APOP failed, trying plaintext password.\n%!";
	             sess#user user; 
	             sess#pass passwd;
                 )
        );
	printf "Successfully opened mailbox!\n%!";
	
	let count,_,_ = sess#stat () in
	printf "Mailbox has %d messages\n%!" count;
	
	for i = 1 to count do
	  printf "message %d\n" i;
	  let hdr = sess#top i () in
	  let hdr = (string_of_in_obj_channel hdr) ^ "\n" in
	  let fields, _ = 
	    Netmime_string.scan_header hdr 0 (String.length hdr)
	  in
	  List.iter (fun (name,body) ->
	    printf "%s: %s\n" name body;
	    flush stdout
          ) fields
	done;
	
	flush stdout;
      )
    )
  with
    | Not_found ->
         printf "Error finding host %s\n%!" server
    | Netpop.Authentication_error ->
         printf "Cannot authenticate\n%!"
;;

(* Netpop.Debug.enable := true;; *)

U.handle_unix_error main ()
