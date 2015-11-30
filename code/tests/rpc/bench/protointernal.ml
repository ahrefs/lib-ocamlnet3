(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Printf

module A = Proto_aux;;
module S = Proto_srv.PROTO.V1;;
module C = Proto_clnt.PROTO.V1;;

let start_servers esys server_spec_list =
  (* Rpc_server.verbose true; *)

  let server_list =
    List.map
      (fun (proto,mode) ->
	 Servercore.install_server esys proto true mode
      )
      server_spec_list
  in

  let stop() =
    (* Stop all started servers: *)
    List.iter Rpc_server.stop_server server_list;
    (* Note: this will not stop the servers immediately, but at the
     * next safe point.
     *) in

  (* Install signal handlers: *)
  List.iter
    (fun signal ->
       Sys.set_signal
	 signal
	 (Sys.Signal_handle
	    (fun _ -> stop())
	 )
    )
    [ Sys.sighup; Sys.sigint ];

  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;

  let rec auto_restart f arg =
    try f arg
    with err ->
      Servercore.log ("Uncaught exception: " ^ Netexn.to_string err);
      auto_restart f arg
  in

  let thr =
    Thread.create
      (fun () ->
         auto_restart Unixqueue.run esys;
      )
      () in
  (fun () ->
    stop();
    Thread.join thr
  )
;;


let with_client serversock f =
  let clientsock =
    Netsys_polysocket.create_client 10 in
  Netsys_polysocket.connect clientsock serversock;
  let client =
    C.create_client2
      (`Internal_socket clientsock) in
  f client;
  Rpc_client.shut_down client


let ping_test client =
  printf "ping... %!";
  C.ping client ();
  printf "ok\n%!"


let revert_test client =
  printf "revert... %!";
  let s = C.revert client "Remote Procedure Call" in
  if s <> "llaC erudecorP etomeR" then failwith "Bad result";
  printf "ok\n%!"


let run_tests serversock =
  with_client serversock ping_test;
  with_client serversock revert_test;
  ()
      


let main() =
  Arg.parse
      [ "-debug", Arg.String (fun s -> Netlog.Debug.enable_module s),
	"<module>  Enable debug messages for <module>";
	
	"-debug-all", Arg.Unit (fun () -> Netlog.Debug.enable_all()),
	"  Enable all debug messages";
	
	"-debug-list", Arg.Unit (fun () -> 
                                   List.iter print_endline (Netlog.Debug.names());
                                   exit 0),
	"  Show possible modules for -debug, then exit"
	  
      ]
      (fun s -> raise(Arg.Bad("Unexpected argument")))
      "Usage: protointernal [ options ]";

  let serversock =
    Netsys_polysocket.create_server() in

  let server_spec_list =
    [ Rpc.Tcp, `Internal_socket(serversock) ] in

  let esys = Unixqueue.create_unix_event_system() in
  let stop = start_servers esys server_spec_list in

  run_tests serversock;

  stop()
;;


main();;
