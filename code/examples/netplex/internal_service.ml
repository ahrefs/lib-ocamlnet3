(* $Id$ *)

(* This example needs OCaml-4.02 or newer *)

open Netplex_types
open Printf

type message =
  | Request of string list
  | Response of string

type _ polysocket_kind +=
   | Tmessage : message polysocket_kind

let concat_service_factory() : processor_factory =
  ( object
      method name = "concat_service"

      method create_processor ctrl_cfg cf addr =
	( object (self)
	    inherit Netplex_kit.empty_processor_hooks()

	    method supported_ptypes = [ `Multi_threading ]

            method process ~when_done cont fd proto =
              failwith "process: not supported for an internal-only service"

            method process_internal ~when_done cont srvbox proto =
              let Polyserver_box(kind, srv) = srvbox in
              match kind with
                | Tmessage ->
                    let (rd,wr) =
                      Netsys_polysocket.accept ~nonblock:false srv in
                    ( try
                        while true do
                          let msg =
                            Netsys_polypipe.read ~nonblock:false rd in
                          let req =
                            match msg with
                              | Some(Request l) -> l
                              | Some Response _ -> 
                                  failwith "process_internal: got Response"
                              | None ->
                                  raise End_of_file in
                          printf "Server: processing message\n%!";
                          let resp = String.concat "/" req in
                          Netsys_polypipe.write
                            ~nonblock:false wr (Some (Response resp));
                        done;
                      with End_of_file ->
                        printf "Server: got EOF, now closing\n%!";
                        Netsys_polypipe.write
                          ~nonblock:false wr None;  (* respond with EOF *)
                        (* Not closing rd/wr. This is the task of the client *)
                        when_done()
                    )
                | _ ->
                    failwith "process_internal: wrong kind"

            method config_internal =
              [ "my_protocol", Polysocket_kind_box Tmessage ]
          end
        )
    end
  )


let rpc_service_factory() : Netplex_types.processor_factory =
  let proc_operation s =
    let l = String.length s in
    let u = Bytes.create l in
    for k = 0 to l-1 do
      Bytes.set u k s.[l-1-k]
    done;
    Bytes.to_string u in
  let setup srv _ =
    Operation_srv.P.V.bind
    ~proc_null:(fun () -> ())
    ~proc_operation
    srv in
  Rpc_netplex.rpc_factory
    ~configure:(fun _ _ -> ())
    ~name:"rpc_service"
    ~setup
    ~hooks:(fun _ -> new Netplex_kit.empty_processor_hooks())
    ()


let same : type s t . s polysocket_kind * t polysocket_kind -> (s,t) eq =
  function
  | Tmessage, Tmessage -> Equal
  | Txdr, Txdr -> Equal
  | _ -> Not_equal

let kind_check =
  fun k ->
    same (Tmessage,k)

let client_hooks =
  ( object
      inherit Netplex_kit.empty_processor_hooks () 
      method post_start_hook _ =
        (* This code is run in a different thread. Create here a client and
           check the internal service out
         *)
        let client =
          Netplex_internal.connect_client
            { Netplex_types.kind_check = fun k -> same (Tmessage,k) }
            1
            "my_server_identifier" in
        let (rd,wr) =
          Netsys_polysocket.endpoint ~synchronous:true ~nonblock:false client in
        let req =
          Request [ "abc"; "123"; "XYZ" ] in
        Netsys_polypipe.write ~nonblock:false wr (Some req);
        let resp =
          Netsys_polypipe.read ~nonblock:false rd in
        ( match resp with
            | Some(Response s) ->
                printf "Client: Got response: %s\n%!" s
            | Some(Request _) ->
                failwith "got request back"
            | None ->
                failwith "got EOF"
        );
        (* now send eof *)
        Netsys_polypipe.write ~nonblock:false wr None;
        (* now await eof *)
        while
          Netsys_polypipe.read ~nonblock:false rd <> None
        do () done;
        printf "Client: Got EOF\n%!";
        Netsys_polypipe.close rd;
        Netsys_polypipe.close wr;
        Netsys_polysocket.close_client client;
        printf "Client: done\n%!";
        (* Now connect to operation_service, an RPC-based internal service *)
        let other_client =
          Netplex_internal.connect_client
            { Netplex_types.kind_check = fun k -> same (Txdr,k) }
            1
            "rpc_server_identifier" in
        let rpc_client =
          Operation_clnt.P.V.create_client2
            (`Internal_socket other_client) in
        let r = Operation_clnt.P.V.operation rpc_client "abcdef" in
        printf "Client: RPC result = %s\n%!" r;
        Rpc_client.shut_down rpc_client;
        Netplex_cenv.system_shutdown()
    end
  )


let main() =
  let (opt_list, cmdline_cfg) = Netplex_main.args() in
  let opt_list' =
    [ "-debug", Arg.String (fun s -> Netlog.Debug.enable_module s),
      "<module>  Enable debug messages for <module>";

      "-debug-all", Arg.Unit (fun () -> Netlog.Debug.enable_all()),
      "  Enable all debug messages";

      "-debug-list", Arg.Unit (fun () -> 
                                 List.iter print_endline (Netlog.Debug.names());
                                 exit 0),
      "  Show possible modules for -debug, then exit";
   ] @ opt_list in
  
  Arg.parse
    opt_list'
    (fun s -> raise (Arg.Bad ("Don't know what to do with: " ^ s)))
    (sprintf "usage: %s [options]" (Filename.basename Sys.argv.(0)));

  let parallelizer = Netplex_mt.mt() in
  Netplex_main.startup
    ~late_initializer:(
      fun _ ctrl ->
        Netplex_kit.add_helper_service ctrl "client" client_hooks
    )
    parallelizer
    Netplex_log.logger_factories   (* allow all built-in logging styles *)
    Netplex_workload.workload_manager_factories (* ... all ways of workload management *)
    [ concat_service_factory();
      rpc_service_factory();
    ]
    cmdline_cfg


let () =
  Printexc.record_backtrace true;
  Netsys_signal.init();
  main()
