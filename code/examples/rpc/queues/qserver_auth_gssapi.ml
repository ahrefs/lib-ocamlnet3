(* $Id$ *)

(* Configure qserver for GSSAPI authentication *)

let service_name = "ocamlnet_queues"

let sconf =
  Netsys_gssapi.create_server_config
    ~acceptor_name:(service_name, Netsys_gssapi.nt_hostbased_service)
    ~privacy:`Required
    () ;;

Qserver.pluggable_auth_module :=
  ( "auth_gssapi",
    (`Socket(Rpc.Tcp, Rpc_server.Portmapped, Rpc_server.default_socket_config)),
    (fun srv ->
       Rpc_server.set_auth_methods
         srv
         [ Rpc_auth_gssapi.server_auth_method
             ~user_name_format:`Plain_name
             ~max_age:300.0
             (module Netgss.System)
             sconf
         ]
    )
  )
;;
