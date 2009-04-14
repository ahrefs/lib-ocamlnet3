(* $Id$ *)

let start() =
  let host = ref "localhost" in
  let port = ref None in
  let query = ref None in
  let tmo = ref (-1.0) in
  let shutdown = ref false in
  let lastquery = ref false in
  let debug = ref false in
  Arg.parse
    [ "-host", Arg.Set_string host,
      "<hostname>  Contact the finder daemon on this host";
      
      "-port", Arg.Int (fun n -> port := Some n),
      "<port>  Bypass portmapper, and use this port directly";

      "-timeout", Arg.Set_float tmo,
      "<tmo>  Set a timeout value in seconds";

      "-shutdown", Arg.Set shutdown,
      "  Shut the server down";

      "-lastquery", Arg.Set lastquery,
      "  Show the last query";

      "-debug", Arg.Set debug,
      "  Enable (some) debug messages";
    ]
    (fun s -> query := Some s)
    "usage: finder_client [options] <query>";

  let query_string =
    match !query with
      | None -> 
	  if not !shutdown && not !lastquery then 
	    failwith "Query is missing on the command-line";
	  None
      | Some q -> 
	  Some q in

  Unixqueue_util.set_debug_mode !debug;

  let rpc_client =
    match !port with
      | None ->
	  Finder_service_clnt.Finder.V1.create_portmapped_client
	    !host Rpc.Tcp 
      | Some p ->
	  Finder_service_clnt.Finder.V1.create_client
	    (Rpc_client.Inet(!host,p)) Rpc.Tcp
  in
  Rpc_client.configure rpc_client 0 !tmo;

  try
    if !lastquery then (
      print_endline
	("Last query: " ^ 
	    Finder_service_clnt.Finder.V1.lastquery rpc_client ())
    );
    ( match query_string with
	| Some q ->
	    ( match Finder_service_clnt.Finder.V1.find rpc_client q with
		| `not_found ->
		    print_endline ("Not found: " ^ q)
		| `found fullpath ->
		    print_endline fullpath
	    )
	| None -> ()
    );
    if !shutdown then (
      Finder_service_clnt.Finder.V1.shutdown rpc_client ()
    )
  with
    | Rpc_client.Communication_error exn ->
	prerr_endline ("RPC: I/O error: " ^ Printexc.to_string exn)
    | Rpc_client.Message_lost ->
	prerr_endline "RPC: Message lost"
    | Rpc.Rpc_server Rpc.Unavailable_program ->
	prerr_endline "RPC: Unavailable program"
    | Rpc.Rpc_server (Rpc.Unavailable_version(_,_)) ->
	prerr_endline "RPC: Unavailable version";
    | Rpc.Rpc_server Rpc.Unavailable_procedure ->
	prerr_endline "RPC: Unavailable procedure";
    | Rpc.Rpc_server Rpc.Garbage ->
	prerr_endline "RPC: Garbage";
    | Rpc.Rpc_server Rpc.System_err ->
	prerr_endline "RPC: System error";
    | Rpc.Rpc_server (Rpc.Rpc_mismatch(_,_)) ->
	prerr_endline "RPC: Mismatch of RPC version";
    | Rpc.Rpc_server Rpc.Auth_bad_cred ->
	prerr_endline "RPC: Bad credentials";
    | Rpc.Rpc_server Rpc.Auth_rejected_cred ->
	prerr_endline "RPC: Rejected credentials";
    | Rpc.Rpc_server Rpc.Auth_bad_verf ->
	prerr_endline "RPC: Bad verifier";
    | Rpc.Rpc_server Rpc.Auth_rejected_verf ->
	prerr_endline "RPC: Rejected verifier";
    | Rpc.Rpc_server Rpc.Auth_too_weak ->
	prerr_endline "RPC: Authentication too weak";
    | Rpc.Rpc_server Rpc.Auth_invalid_resp ->
	prerr_endline "RPC: Invalid authentication response";
    | Rpc.Rpc_server Rpc.Auth_failed ->
	prerr_endline "RPC: Authentication failed";
;;

Netsys_signal.init();
start();;
