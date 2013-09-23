open Nettls_gnutls_bindings;;
open Printf;;

let connect () =
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect s (Unix.ADDR_INET(Unix.inet_addr_of_string "188.107.175.122", 443));
  let sess = gnutls_init [ `Client] in
  let creds = gnutls_certificate_allocate_credentials() in
  gnutls_certificate_set_x509_trust_file creds "/etc/ssl/certs/ca-certificates.crt" `Pem;
  gnutls_certificate_set_verify_flags creds [];
  gnutls_credentials_set sess (`Certificate creds);
  let prio = gnutls_priority_init "PERFORMANCE" in
  gnutls_priority_set sess prio;
  set_fd sess s;
  b_set_verify_callback sess
                        (fun sess ->
                           let certs = gnutls_certificate_get_peers sess in
                           printf "Got %d certificates\n%!" (Array.length certs);
                           let l = gnutls_certificate_verify_peers2 sess in
                           printf "Status: [%s]\n%!"
                             (String.concat
                                ","
                                (List.map string_of_verification_status_flag l));
                           l = []
                        );
  gnutls_handshake sess;
  (s, sess)


let to_mem s =
  let m = 
    Bigarray.Array1.create Bigarray.char Bigarray.c_layout (String.length s) in
  Netsys_mem.blit_string_to_memory s 0 m 0 (String.length s);
  m


let to_str m =
  let l = Bigarray.Array1.dim m in
  let s = String.create l in
  Netsys_mem.blit_memory_to_string m 0 s 0 l;
  s


let cycle() =
  let (s,sess) = connect() in
  let n = gnutls_record_send sess (to_mem "GET / HTTP/1.0\n\n") in
  eprintf "n=%d\n%!" n;
  let n = ref 1 in
  let buf = Netsys_mem.alloc_memory_pages 4096 in
  while !n > 0 do
    n := gnutls_record_recv sess buf;
    output_string stdout (to_str (Bigarray.Array1.sub buf 0 !n));
  done;
  printf "\n%!"

  
let ca_certs() =
  let f = open_in "/etc/ssl/certs/ca-certificates.crt" in
  let n = in_channel_length f in
  let data = String.create n in
  really_input f data 0 n;
  close_in f;
  gnutls_x509_crt_list_import data `Pem []
