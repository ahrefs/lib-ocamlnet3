(* $Id$ *)

let service_name = "ocamlnet_queues"

module C1 = Queues_clnt.QUEUESPROG.QUEUESVERS1 ;;

Qclient.pluggable_auth_module :=
  ( "auth_gssapi",
    (fun host ->
       let cconf =
         Netsys_gssapi.create_client_config
           ~target_name:(service_name ^ "@" ^ host, 
                         Netsys_gssapi.nt_hostbased_service)
           ~privacy:`Required
           () in
       let clnt = C1.create_portmapped_client host Rpc.Tcp in
       Rpc_client.set_auth_methods clnt 
         [ Rpc_auth_gssapi.client_auth_method
             ~user_name_interpretation:(`Plain_name Netsys_gssapi.nt_user_name)
             (module Netgss.System)
             cconf
         ];
       clnt
    )
  )
;;
