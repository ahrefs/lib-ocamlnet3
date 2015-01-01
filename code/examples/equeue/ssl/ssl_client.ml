#use "topfind";;
#require "equeue,nettls-gnutls";;

(* This example connects stdin/stdout with a remote SSL service. To test
 * replace the following IP address and port with real numbers, e.g.
 * with an HTTPS server. Then start with
 *
 * ocaml ssl_client.ml
 *
 * Then enter something like:
 * 
 * GET / HTTP/1.0
 *
 * (+ double new lines).
 *)

let remote_name = "www.google.com" ;;
let remote_ip_addr = 
  (Uq_resolver.get_host_by_name remote_name).Unix.h_addr_list.(0)
let remote_port = 443 ;;


let maybe_error err_opt =
  match err_opt with
    | None -> ()
    | Some err ->
	raise err
;;


let communicate tls_mplex =
  prerr_endline "* TLS handshake done";
       
  let esys = tls_mplex # event_system in

  let shutdown_in = ref (fun _ _ _ -> ()) in
  let shutdown_out = ref (fun _ _ _ -> ()) in

  let in_ch = 
    new Uq_transfer.input_async_mplex 
	~onshutdown:(`Action (fun ch m s -> !shutdown_in ch m s))
	~buffer_size:10
	tls_mplex in
  let _sender =
    new Uq_transfer.sender
	~src:in_ch
	~dst:Unix.stdout
	~close_dst:false
	esys in
       
  let out_ch =
    new Uq_transfer.output_async_mplex
	~onshutdown:(`Action (fun ch m s -> !shutdown_out ch m s))
	~buffer_size:10
	tls_mplex in
  let _receiver =
    new Uq_transfer.receiver
	~src:Unix.stdin
	~dst:out_ch
	~close_src:false
	esys in
       
  (* Shutdown actions: Because we have two channels attached to a
   * single multiplexer, we must synchronize the shutdown.
   *)
  shutdown_in := ( fun ch m s ->
		     (* The SSL connection is terminated. If the out_ch
                      * is already finished, we shut down the multiplexer.
                      * Else we simply abort the output channel.
                      *)
		     match out_ch # state with
		       | `Working _ ->
			    out_ch # abort()
		       | _ ->
			    m # start_shutting_down
				  ~when_done:(fun _ -> ()) ()
		 );
  shutdown_out := (fun ch m s ->
		     (* The terminal connection is terminated. Now we
                      * have to check whether in_ch is still alive.
                      *)
		     match in_ch # state with
		       | `Working _ ->
			    in_ch # abort()
		       | _ ->
			    m # start_shutting_down
				  ~when_done:(fun _ -> ()) ()
		  );
  
  ()



let main() =
  Nettls_gnutls.init();
  let esys = Unixqueue.create_unix_event_system() in
  let cl = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  prerr_endline "* TCP connected";
  Unix.connect cl 
    (Unix.ADDR_INET
       (remote_ip_addr, remote_port));
  
  let tls_config =
    Netsys_tls.create_x509_config
      ~system_trust:true
      ~peer_auth:`Required
      (module Nettls_gnutls.TLS) in
  let cl_mplex =
    Uq_multiplex.create_multiplex_controller_for_connected_socket cl esys in
  let _tls_mplex = 
    Uq_multiplex.tls_multiplex_controller
      ~on_handshake:communicate
      ~role:`Client ~peer_name:(Some remote_name) tls_config cl_mplex in
  esys# run()
;;


(* Unixqueue.set_debug_mode true;*)
main();;

prerr_endline "DONE";
