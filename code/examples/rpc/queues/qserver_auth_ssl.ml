(* $Id$ *)

(* Configure qserver for SSL authentication (UNSAFE) *)

Nettls_gnutls.init() ;;

let tls_config =
  Netsys_tls.create_x509_config
    ~trust:[ `PEM_file "ca.crt" ]
    ~keys:[ (`PEM_file "server.crt", `PEM_file "server.key", None) ]
    ~peer_auth:`Required
    (Netsys_crypto.current_tls())

let tls_socket_config =
  Rpc_server.tls_socket_config tls_config ;;

Qserver.pluggable_auth_module :=
  ( "auth_ssl",
    (`Socket(Rpc.Tcp, Rpc_server.Portmapped, tls_socket_config)),
    (fun srv ->
       Rpc_server.set_auth_methods
	 srv
	 [ Rpc_server.auth_transport ]
    )
  )
;;
