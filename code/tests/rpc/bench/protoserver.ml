(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Printf

module A = Proto_aux;;
module S = Proto_srv.PROTO.V1;;

let start_servers esys server_spec_list =
  (* Rpc_server.verbose true; *)

  let server_list =
    List.map
      (fun (proto,mode) ->
	 Servercore.install_server esys proto false mode
      )
      server_spec_list
  in

  (* Install signal handlers: *)
  List.iter
    (fun signal ->
       Sys.set_signal
	 signal
	 (Sys.Signal_handle
	    (fun _ ->
	       (* Stop all started servers: *)
	       List.iter Rpc_server.stop_server server_list;
	       (* Note: this will not stop the servers immediately, but at the
		* next safe point.
		*)
	    )
	 )
    )
    [ Sys.sighup; Sys.sigint; Sys.sigquit; Sys.sigterm ];

  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;

  let rec auto_restart f arg =
    try f arg
    with err ->
      Servercore.log ("Uncaught exception: " ^ Netexn.to_string err);
      auto_restart f arg
  in

  (* Fork *)
  match Unix.fork() with
      0 ->
	(* Child *)
	(* We could also start here a new session. But because this daemon
	 * is only for tests, we do not do it. This has the consequence that
	 * the daemon will terminate when the terminal terminates.
	 * It would even be better to begin a new background process group
	 * here, but the necessary system calls are missing in Unix.
	 *)
	(* ignore(Unix.setsid()); *)
	auto_restart Unixqueue.run esys;
	exit 99
    | n when n > 0 ->
	(* Parent *)
	printf "pid=%d\n" n;
	flush stdout
    | _ ->
	assert false
;;

let main() =
  let want_tcp = ref false in
  let want_udp = ref false in
  let want_unix = ref false in
  let enable_ssl = ref false in
  Arg.parse
      [ "-tcp", Arg.Set want_tcp,
	     "            Listen on a TCP socket";
	"-udp", Arg.Set want_udp,
	     "            Listen on a UDP socket";
	"-unix", Arg.Set want_unix,
	      "           Listen on a Unix Domain Socket";
	"-ssl", Arg.Set enable_ssl,
	     "            Enable SSL (incompatible with -udp)";

	"-debug", Arg.String (fun s -> Netlog.Debug.enable_module s),
	"<module>  Enable debug messages for <module>";
	
	"-debug-all", Arg.Unit (fun () -> Netlog.Debug.enable_all()),
	"  Enable all debug messages";
	
	"-debug-list", Arg.Unit (fun () -> 
                                   List.iter print_endline (Netlog.Debug.names());
                                   exit 0),
	"  Show possible modules for -debug, then exit"
	  
      ]
      (fun s -> raise(Arg.Bad("Unexpected argument")))
      "Usage: protoserver [ options ]";
  if !want_udp && !enable_ssl then
    failwith "-udp and -ssl are incompatible";
  let socket_config =
    if !enable_ssl then (
      Nettls_gnutls.init();
      let tls_config =
        Netsys_tls.create_x509_config
          ~keys:[`PEM_file "testserver.crt",
                 `PEM_file "testserver.key",
                 None]
          ~peer_auth:`None
          (module Nettls_gnutls.TLS) in
      Rpc_server.tls_socket_config tls_config
    )
    else
      Rpc_server.default_socket_config in
  let server_spec_list =
    (if !want_tcp then
       [ Rpc.Tcp, `Socket(Rpc.Tcp, Rpc_server.Localhost 0, socket_config) ]
     else [])
    @
    (if !want_udp then
       [ Rpc.Udp, `Socket(Rpc.Udp, Rpc_server.Localhost 0, socket_config) ]
     else [])
    @
    (if !want_unix then
       let name = Unix.getcwd() ^ "/" ^ "socket" in
       (try Sys.remove name with _ -> ());
       [ Rpc.Tcp, `Socket(Rpc.Tcp, Rpc_server.Unix name, socket_config ) ]
     else [])
  in

  let esys = Unixqueue.create_unix_event_system() in
  start_servers esys server_spec_list
;;


main();;
