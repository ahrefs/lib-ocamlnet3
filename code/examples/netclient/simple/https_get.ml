#require "netclient,nettls-gnutls";;

(* This example shows how to get a file from a HTTP server using
 * the Convenience module.
 *
 * Load this into the toplevel, then:
 * get_and_print "https://www.google.com/";;
 *)

(* You get https support with this: *)
let () =
  Nettls_gnutls.init()


open Nethttp_client.Convenience;;

let get_and_print url =
  let s = http_get url in
  print_string s;
  flush stdout
;;
