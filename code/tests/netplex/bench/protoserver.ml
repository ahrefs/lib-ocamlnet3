(* $Id$ *)

open Netplex_types
open Printf


let configure _ _ = ()


let proc_hard_work() =
  Unix.sleep 1;
  1

let proc_fail() =
  failwith "proc_fail"

let proc_exit() =
  exit 3


let vv1 = ref None
let vv2 = ref None

let estvar vv =
  match !vv with
    | None ->
        ignore(Netplex_sharedvar.create_var "the_variable");
        let new_vv = Netplex_sharedvar.vv_access "the_variable" in
        vv := Some new_vv;
        new_vv
    | Some vv_to_use ->
        vv_to_use

let setvar vv s =
  let vv_to_use = estvar vv in
  ignore(Netplex_sharedvar.vv_set vv_to_use s)
  
let proc_setvar1 s =
  setvar vv1 s

let proc_setvar2 s =
  setvar vv2 s

let getvar vv =
  let vv_to_use = estvar vv in
  Netplex_sharedvar.vv_get vv_to_use

let proc_getvar1 () =
  getvar vv1

let proc_getvar2 () =
  getvar vv2

let updvar vv =
  let vv_to_use = estvar vv in
  ignore(Netplex_sharedvar.vv_update vv_to_use)

let proc_updvar1 () =
  updvar vv1

let proc_updvar2 () =
  updvar vv2


let setup rpc () =
  Proto_srv.P.V1.bind
    ~proc_ping:(fun () -> ())
    ~proc_hard_work
    ~proc_fail
    ~proc_exit
    ~proc_setvar1
    ~proc_setvar2
    ~proc_getvar1
    ~proc_getvar2
    ~proc_updvar1
    ~proc_updvar2
    rpc
;;


let proto_factory (non_responsive,cont_fail) =
  let hooks _ =
    ( object
	inherit Netplex_kit.empty_processor_hooks ()

        method post_add_hook _ ctrl =
          ctrl # add_plugin Netplex_sharedvar.plugin

	method post_start_hook _ =
	  if non_responsive then
	    Unix.sleep 1000000;
	  if cont_fail then
	    exit 3
      end
    ) in

  Rpc_netplex.rpc_factory
    ~configure
    ~name:"proto"
    ~setup
    ~hooks
    ()

let start() =
  let non_responsive = ref false in
  let cont_fail = ref false in

  let opts, cmdconf = Netplex_main.args() in
  Arg.parse 
    ( opts @
	[ "-non-responsive", Arg.Set non_responsive,
	  "  Force that the containers sleep instead of starting up";

	  "-cont-failure", Arg.Set cont_fail,
	  "  Force that the containers fail instead of starting up";
	]
    )
    (fun s -> raise(Arg.Bad ("Unknown arg: " ^ s))) 
    "usage: protoserver";
  let par = Netplex_mp.mp() in
  Netplex_main.startup
    par
    Netplex_log.logger_factories
    Netplex_workload.workload_manager_factories
    [ proto_factory (!non_responsive, !cont_fail) ]
    cmdconf
;;

Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
(*
Netplex_log.debug_scheduling := true;
Rpc_netplex.debug_rpc_service := true;
 *)
start();;
