(* $Id$ *)

module C1 = Queues_clnt.QUEUESPROG.QUEUESVERS1 ;;

Nettls_gnutls.init() ;;

let tls_config =
  Netsys_tls.create_x509_config
    ~trust:[ `PEM_file "ca.crt" ]
    ~keys:[ (`PEM_file "client.crt", `PEM_file "client.key", None) ]
    ~peer_auth:`Required
    (Netsys_crypto.current_tls())

let tls_socket_config =
  Rpc_client.tls_socket_config tls_config ;;

Qclient.pluggable_auth_module :=
  ( "auth_ssl",
    (fun host ->
       let clnt = C1.create_client2 
	 (`Socket(Rpc.Tcp, 
		  Rpc_client.Portmapped host,
		  tls_socket_config)) in
       clnt
    )
  )
;;
