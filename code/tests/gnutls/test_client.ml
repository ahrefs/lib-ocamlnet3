open Netsys_tls

let test1() =
  let c = 
    create_x509_config 
      ~peer_auth:`Required 
      ~trust:[`PEM_file "certs/x509-ca.pem"]
      (Netsys_crypto.current_tls()) in
  let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let addr = Unix.inet_addr_of_string "127.0.0.1" in
  Unix.connect s (Unix.ADDR_INET(addr, 4242));
  let ep = create_file_endpoint ~role:`Client ~rd_file:s ~wr_file:s c in
  start_tls ep;
  let fd_style = `TLS ep in
  let ch = new Netchannels.socket_descr ~fd_style s in
  let ch_in = Netchannels.lift_in (`Raw (ch :> Netchannels.raw_in_channel)) in
  let ch_out = Netchannels.lift_out (`Raw (ch :> Netchannels.raw_out_channel)) in
  ch_out # output_string "This is a line!\n";
  ch_out # flush();
  let line = ch_in # input_line() in
  print_endline ("Got: " ^ line);
  ch # close_out();
  ch # close_in()
;;



let () =
  Printexc.record_backtrace true;
  Netsys_tls.Debug.enable := true;
  Nettls_gnutls.init();
  test1()
