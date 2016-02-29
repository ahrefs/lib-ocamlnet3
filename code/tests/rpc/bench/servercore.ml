(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Printf

module A = Proto_aux;;
module S = Proto_srv.PROTO.V1;;

let log message =
  (* Output [message] to the log medium. This is currently stderr. *)
  prerr_endline ("Log: " ^ message)
;;


let catch_error f reply =
  try (f reply : unit)
  with
    | Sys_error e ->
        log ("Sys_error: " ^ e);
	log ("(Not replying)");
    | Unix.Unix_error(code,msg,fn) ->
        log ("Unix_error: " ^ Unix.error_message code ^
             (if msg <> "" then ": " ^ msg else "") ^
             (if fn <> "" then " [" ^ fn ^ "]" else ""));
	log ("(Not replying)");
;;


let auth_methods =
  let server_key_verifier =
    ( object
        method scram_credentials user =
          match user with
            | "guest" ->
                let icount = 4096 in
                let salt = Netmech_scram.create_salt() in
                let spw = 
                  Netmech_scram.salt_password `SHA_1 
                                              "guest_password" salt icount in
                `Salted_password(spw, salt, icount)
            | _ ->
                raise Not_found
      end
    ) in
  let gss_api =
    Netmech_scram_gssapi.scram_gss_api
      ~server_key_verifier
      (Netmech_scram.profile `GSSAPI `SHA_1) in
  let gss_auth_meth =
    Rpc_auth_gssapi.server_auth_method
      ~shared_context:true  (* for UDP *)
      ~user_name_format:`Plain_name
      gss_api
      (Netsys_gssapi.create_server_config
         ~mech_types: [Netmech_scram_gssapi.scram_mech]
         ()
      ) in
  [ Rpc_auth_sys.server_auth_method ~require_privileged_port:false ();
    gss_auth_meth;
    Rpc_server.auth_none;
  ]
;;


let proc_ping session () =
  catch_error
    (fun reply ->
       reply()
    )
;;


let proc_revert session s =
  catch_error
    (fun reply ->
       let l = String.length s in
       let s' = String.create l in
       for i = 0 to l -1 do
	 s'.[ i ] <- s.[ l - 1 - i ]
       done;
       reply s'
    )
;;


let batch_in_accu = ref "";;

let proc_batch_in session (first,last,s) =
  catch_error
    (fun reply ->
       if first then batch_in_accu := "";
       batch_in_accu := !batch_in_accu ^ s;
       if last then reply !batch_in_accu
    )
;;


let proc_batch_out session s =
  catch_error
    (fun reply ->
       for i = 0 to String.length s - 1 do
	 let s' = String.make 1 s.[i] in
	 reply (Some s')
       done;
       reply None
    )
;;


let retransmit_state = ref false;;

let proc_retransmit1 session () =
  catch_error
    (fun reply ->
       retransmit_state := false;
       reply()
    )
;;


let proc_retransmit2 session () =
  catch_error
    (fun reply ->
       if !retransmit_state then reply();
       retransmit_state := true
    )
;;


let proc_install_dropping_filter session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       Rpc_server.set_session_filter srv
	 (fun _ ->
	    Rpc_server.set_session_filter srv (fun _ -> `Accept);
	    `Drop
	 );
       reply ()
    )
;;


let proc_install_rejecting_filter session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       Rpc_server.set_session_filter srv
	 (fun _ ->
	    Rpc_server.set_session_filter srv (fun _ -> `Accept);
	    `Reject
	 );
       reply ()
    )
;;


let proc_install_denying_filter session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       Rpc_server.set_session_filter srv
	 (fun _ ->
	    Rpc_server.set_session_filter srv (fun _ -> `Accept);
	    `Deny
	 );
       reply ()
    )
;;


let proc_install_dropping_filter_with_limit session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       Rpc_server.set_session_filter srv
	 (fun _ ->
	    Rpc_server.set_session_filter srv (fun _ -> `Accept);
	    `Accept_limit_length(80, `Drop)
	 );
       reply ()
    )
;;


let proc_auth_sys session() =
  catch_error
    (fun reply ->
       let m = Rpc_server.get_auth_method session in
       if m#name <> "AUTH_SYS" then
	 Rpc_server.reply_error session Rpc.Auth_failed
       else (
	 let username = Rpc_server.get_user session in
	 let (uid,gid,gids,_) = Rpc_auth_sys.parse_user_name username in
	 if uid = 50 && gid = 51 && gids = [|52;53|] then
	   reply()
	 else
	   Rpc_server.reply_error session Rpc.Auth_rejected_cred
       )
    )
;;


let proc_enable_auth_local session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       Rpc_server.set_auth_methods srv
	 [ Rpc_auth_local.server_auth_method();
	   Rpc_server.auth_none
	 ];
       reply()
    )
;;


let proc_auth_local session() =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       let m = Rpc_server.get_auth_method session in
       if m#name <> "AUTH_LOCAL" then
	 Rpc_server.reply_error session Rpc.Auth_failed
       else (
	 let username = Rpc_server.get_user session in
	 Rpc_server.set_auth_methods srv auth_methods;
	 reply username;
       )
    )
;;


let proc_auth_dh session user =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       let m = Rpc_server.get_auth_method session in
       if m#name <> "AUTH_DH" then
	 Rpc_server.reply_error session Rpc.Auth_failed
       else (
	 let username = Rpc_server.get_user session in
	 Rpc_server.set_auth_methods srv auth_methods;
	 reply username;
       )
    )
;;


let proc_auth_scram session () =
  let srv = Rpc_server.get_server session in
  catch_error
    (fun reply ->
       let m = Rpc_server.get_auth_method session in
       if m#name <> "RPCSEC_GSS" then
	 Rpc_server.reply_error session Rpc.Auth_failed
       else (
	 let username = Rpc_server.get_user session in
	 Rpc_server.set_auth_methods srv auth_methods;
	 reply username;
       )
    )
;;


let install_server esys proto internal mode =
  let srv =
    Rpc_server.create2 mode esys in
  S.bind_async
    ~proc_ping
    ~proc_revert
    ~proc_batch_in
    ~proc_batch_out
    ~proc_retransmit1
    ~proc_retransmit2
    ~proc_install_dropping_filter
    ~proc_install_rejecting_filter
    ~proc_install_denying_filter
    ~proc_install_dropping_filter_with_limit
    ~proc_auth_sys
    ~proc_enable_auth_local
    ~proc_auth_local
    ~proc_auth_dh
    ~proc_auth_scram
    srv;
  Rpc_server.set_auth_methods srv auth_methods;

  if not internal then (
    match Rpc_server.get_main_socket_name srv with
	Unix.ADDR_UNIX filename ->
	  printf "unix_path=%s\n" filename
      | Unix.ADDR_INET(addr,port) ->
	  ( match proto with
		Rpc.Tcp -> printf "tcp_port=%d\n" port
	      | Rpc.Udp -> printf "udp_port=%d\n" port
	  )
  );
  flush stdout;
  srv
;;
