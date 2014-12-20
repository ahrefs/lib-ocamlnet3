(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Netnumber
open Netxdr
open Rpc
open Rpc_portmapper_aux
open Printf

type t =
    { esys : Unixqueue.event_system;
      client : Rpc_client.t
    }
;;


let mk_mapping prog vers prot port =
  let proc_num =
    if prot = Tcp then 6 else 17 in
  { prog; vers; prot = proc_num; port }
;;

let mk_rpcb r_prog r_vers r_netid r_addr r_owner =
  { r_prog; r_vers; r_netid; r_addr; r_owner }
;;

let mk_mapping_from_rpcb rpcb =
  { prog = rpcb.r_prog;
    vers = rpcb.r_vers;
    prot = ( match rpcb.r_netid with
               | "tcp" -> 6
               | "udp" -> 17
               | _ -> raise Not_found
           );
    port = if rpcb.r_addr = "" then 0 else 
             snd(Rpc.parse_inet_uaddr rpcb.r_addr);
  }
;;

let try_mapping_from_rpcb rpcb =
  try
    mk_mapping_from_rpcb rpcb, true
  with
    | Failure _
    | Not_found -> 
        (* good enough for unsetting: *)
        { prog = rpcb.r_prog;
          vers = rpcb.r_vers; 
          prot = 0;
          port = 0
        }, false
;;


let rec dest_pmaplist l =
  match l with
    | None -> 
        []
    | Some e ->
        let prot =
          match e.map.prot with
	    | 6 -> Tcp
	    | 17 -> Udp
	    | _  -> failwith "illegal protocol specifier found" in
        (e.map.prog, e.map.vers, prot, e.map.port) :: dest_pmaplist e.next
;;


let create ?(esys = Unixqueue.create_unix_event_system()) conn =
  let cf = Rpc_client.default_socket_config in
  let client = Rpc_client.unbound_create (`Socket(Rpc.Tcp,conn,cf)) esys in
  Rpc_client.bind client Rpc_portmapper_clnt.PMAP.V2._program;
  Rpc_client.bind client Rpc_portmapper_clnt.PMAP.V3._program;
  Rpc_client.bind client Rpc_portmapper_clnt.PMAP.V4._program;
  { esys; client }
;;


let create_inet ?esys s =
  create ?esys (Rpc_client.Inet(s,111))
;;


let create_local ?esys () =
  if Sys.file_exists "/run/rpcbind.sock" then
    create ?esys (Rpc_client.Unix "/run/rpcbind.sock")
  else if Sys.file_exists "/var/run/rpcbind.sock" then
    create ?esys (Rpc_client.Unix "/var/run/rpcbind.sock")
  else
    create_inet ?esys "localhost"
;;


let shut_down pm =
  Rpc_client.shut_down pm.client
;;


let null pm =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_null pm.client ()
;;

let null'async pm callback =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_null'async pm.client () callback
;;


let set pm prog vers prot port =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_set
    pm.client
    (mk_mapping prog vers prot port)
;;

let set'async pm prog vers prot port callback =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_set'async
    pm.client
    (mk_mapping prog vers prot port)
    callback
;;


let set_rpcbind'async pm prog vers netid uaddr owner callback =
  let b = mk_rpcb prog vers netid uaddr owner in
  let m, m_ok = try_mapping_from_rpcb b in
  Rpc_portmapper_clnt.PMAP.V3.rpcbproc_set'async
    pm.client b
    (fun getresult ->
       try
         let ok = getresult() in
         callback (fun () -> ok)
       with
         | Rpc.Rpc_server (Rpc.Unavailable_version _) when m_ok ->
             Rpc_portmapper_clnt.PMAP.V2.pmapproc_set'async
               pm.client m callback
         | error ->
             callback (fun () -> raise error)
    )
;;


let set_rpcbind pm prog vers netid uaddr owner =
  Rpc_client.synchronize
    pm.esys
    (set_rpcbind'async pm prog vers netid uaddr)
    owner
;;


let unset pm prog vers prot port =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_unset
    pm.client
    (mk_mapping prog vers prot port)
;;

let unset'async pm prog vers prot port callback =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_unset'async
    pm.client
    (mk_mapping prog vers prot port)
    callback
;;


let unset_rpcbind'async pm prog vers netid uaddr owner callback =
  let b = mk_rpcb prog vers netid uaddr owner in
  let m, _ = try_mapping_from_rpcb b in
  eprintf "CALLING\n%!";
  Rpc_portmapper_clnt.PMAP.V3.rpcbproc_unset'async
    pm.client b
    (fun getresult ->
       eprintf "CALLBACK\n%!";
       try
         let ok = getresult() in
         callback (fun () -> ok)
       with
         | Rpc.Rpc_server (Rpc.Unavailable_version _) ->
             Rpc_portmapper_clnt.PMAP.V2.pmapproc_unset'async
               pm.client m callback
         | error ->
             callback (fun () -> raise error)
    )
;;


let unset_rpcbind pm prog vers netid uaddr owner =
  Rpc_client.synchronize
    pm.esys
    (unset_rpcbind'async pm prog vers netid uaddr)
    owner
;;


let getport pm prog vers prot =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_getport
    pm.client
    (mk_mapping prog vers prot 0)
;;

let getport'async pm prog vers prot callback =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_getport'async
    pm.client
    (mk_mapping prog vers prot 0)
    callback
;;


(*
let uaddr_of_netid =
  function
    | "tcp"
    | "udp" -> "0.0.0.0.0.0"
    | "tcp6"
    | "udp6" -> "::.0.0"
    | "unix"
    | "local" -> "/"
    | _ -> ""
 *)


let getaddr_rpcbind'async pm prog vers netid caller_uaddr callback =
  let b = mk_rpcb prog vers netid caller_uaddr "" in
  let m, m_ok = try_mapping_from_rpcb b in
  Rpc_portmapper_clnt.PMAP.V3.rpcbproc_getaddr'async
    pm.client b
    (fun getresult ->
       try
         let uaddr = getresult() in
         callback (fun () -> if uaddr = "" then None else Some uaddr)
       with
         | Rpc.Rpc_server (Rpc.Unavailable_version _) when m_ok ->
             Rpc_portmapper_clnt.PMAP.V2.pmapproc_getport'async
               pm.client m
               (fun getresult ->
                  try
                    let port = getresult() in
                    let uaddr = Rpc.create_inet_uaddr Unix.inet_addr_any port in
                    callback (fun () -> if port=0 then None else Some uaddr)
                  with
                    | error ->
                        callback (fun () -> raise error)
               )
         | error ->
             callback (fun () -> raise error)
    )
;;


let getaddr_rpcbind pm prog vers netid caller_uaddr =
  Rpc_client.synchronize
    pm.esys
    (getaddr_rpcbind'async pm prog vers netid)
    caller_uaddr
;;


let dump pm =
  dest_pmaplist
    (Rpc_portmapper_clnt.PMAP.V2.pmapproc_dump pm.client ())
;;

let dump'async pm callback =
  Rpc_portmapper_clnt.PMAP.V2.pmapproc_dump'async pm.client ()
    (fun getresult -> 
       callback (fun () -> dest_pmaplist(getresult()))
    )
;;


let port_of_program program serverhost prot =
  let pm = create_inet serverhost in
  try
    let p = getport pm (Rpc_program.program_number program)
                    (Rpc_program.version_number program)
                    prot in
    if p = 0 then failwith "portmapper does not know the program";
    shut_down pm;
    p
  with
    | error ->
        shut_down pm; raise error
;;


let sockaddr_of_program_rpcbind program serverhost netid =
  let pm = create_inet serverhost in
  ( try
      let uaddr_opt = 
        getaddr_rpcbind 
          pm
          (Rpc_program.program_number program)
          (Rpc_program.version_number program)
          netid "" in
      shut_down pm;
      ( match uaddr_opt with
          | None ->
              failwith "rpcbind does not know the program"
          | Some uaddr -> 
              match Rpc.sockaddr_of_uaddr netid uaddr with
                | Some(sockaddr,prot) -> (sockaddr,prot)
                | None -> failwith ("unknown netid: " ^ netid)
      )
    with
      | error ->
          shut_down pm; raise error
  )

                        
