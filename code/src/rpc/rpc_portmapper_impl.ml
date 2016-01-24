(* $Id$ *)

module type CLIENT =
  sig
    type t

    val create_inet : Unixqueue.event_system -> string -> int -> 
                      Rpc.protocol -> t
    val create_unix : Unixqueue.event_system -> string -> t
    val bind : t -> Rpc_program.t -> unit
    val shut_down : t -> unit
    val synchronize : Unixqueue.event_system ->
                      ('a -> ((unit -> 'b) -> unit) -> unit) ->
                      'a -> 'b
    val event_system : t -> Unixqueue.event_system

    (* from USE_CLIENT: *)
    val use : t -> Rpc_program.t -> unit
    val unbound_sync_call : 
      t -> Rpc_program.t -> string -> Netxdr.xdr_value -> Netxdr.xdr_value
    val unbound_async_call :
      t -> Rpc_program.t -> string -> Netxdr.xdr_value -> 
      ((unit -> Netxdr.xdr_value) -> unit) -> unit
    val xdr_ctx : t -> Netxdr.ctx
  end

open Netnumber
open Netxdr
open Rpc
open Rpc_portmapper_aux
open Printf


module PM(C:CLIENT) = struct
  module PMAP = Rpc_portmapper_clnt.Make'PMAP(C)

  type t =
      { esys : Unixqueue.event_system;
        client : C.t
      }


  let mk_mapping prog vers prot port =
    let proc_num =
      if prot = Tcp then 6 else 17 in
    { prog; vers; prot = proc_num; port }

  let mk_rpcb r_prog r_vers r_netid r_addr r_owner =
    { r_prog; r_vers; r_netid; r_addr; r_owner }

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


  let bind client =
    C.bind client program_PMAP'V2;
    C.bind client program_PMAP'V3;
    C.bind client program_PMAP'V4


  let create_for client =
    bind client;
    let esys = C.event_system client in
    { client; esys }


  let create_inet ?(esys=Unixqueue.create_unix_event_system()) host proto =
    let client = C.create_inet esys host 111 proto in
    bind client;
    { client; esys }


  let create_unix ?(esys=Unixqueue.create_unix_event_system()) path =
    let client = C.create_unix esys path in
    bind client;
    { client; esys }


  let create_local ?(esys=Unixqueue.create_unix_event_system()) () =
    if Sys.file_exists "/run/rpcbind.sock" then
      create_unix ~esys "/run/rpcbind.sock"
    else if Sys.file_exists "/var/run/rpcbind.sock" then
      create_unix ~esys "/var/run/rpcbind.sock"
    else
      create_inet ~esys "localhost" Rpc.Tcp


  let shut_down pm =
    C.shut_down pm.client


  let null pm =
    PMAP.V2.pmapproc_null pm.client ()

  let null'async pm callback =
    PMAP.V2.pmapproc_null'async pm.client () callback


  let set pm prog vers prot port =
    PMAP.V2.pmapproc_set
      pm.client
      (mk_mapping prog vers prot port)

  let set'async pm prog vers prot port callback =
    PMAP.V2.pmapproc_set'async
      pm.client
      (mk_mapping prog vers prot port)
      callback


  let set_rpcbind'async pm prog vers netid uaddr owner callback =
    let b = mk_rpcb prog vers netid uaddr owner in
    let m, m_ok = try_mapping_from_rpcb b in
    PMAP.V3.rpcbproc_set'async
      pm.client b
      (fun getresult ->
         try
           let ok = getresult() in
           callback (fun () -> ok)
         with
           | Rpc.Rpc_server (Rpc.Unavailable_version _) when m_ok ->
               PMAP.V2.pmapproc_set'async
                 pm.client m callback
           | error ->
               callback (fun () -> raise error)
      )


  let set_rpcbind pm prog vers netid uaddr owner =
    C.synchronize
      pm.esys
      (set_rpcbind'async pm prog vers netid uaddr)
      owner


  let unset pm prog vers prot port =
    PMAP.V2.pmapproc_unset
      pm.client
      (mk_mapping prog vers prot port)

  let unset'async pm prog vers prot port callback =
    PMAP.V2.pmapproc_unset'async
      pm.client
      (mk_mapping prog vers prot port)
      callback


  let unset_rpcbind'async pm prog vers netid uaddr owner callback =
    let b = mk_rpcb prog vers netid uaddr owner in
    let m, _ = try_mapping_from_rpcb b in
    PMAP.V3.rpcbproc_unset'async
      pm.client b
      (fun getresult ->
         try
           let ok = getresult() in
           callback (fun () -> ok)
         with
           | Rpc.Rpc_server (Rpc.Unavailable_version _) ->
               PMAP.V2.pmapproc_unset'async
                 pm.client m callback
           | error ->
               callback (fun () -> raise error)
      )


  let unset_rpcbind pm prog vers netid uaddr owner =
    C.synchronize
      pm.esys
      (unset_rpcbind'async pm prog vers netid uaddr)
      owner


  let getport pm prog vers prot =
    PMAP.V2.pmapproc_getport
      pm.client
      (mk_mapping prog vers prot 0)

  let getport'async pm prog vers prot callback =
    PMAP.V2.pmapproc_getport'async
      pm.client
      (mk_mapping prog vers prot 0)
      callback


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
    PMAP.V3.rpcbproc_getaddr'async
      pm.client b
      (fun getresult ->
         try
           let uaddr = getresult() in
           callback (fun () -> if uaddr = "" then None else Some uaddr)
         with
           | Rpc.Rpc_server (Rpc.Unavailable_version _) when m_ok ->
               PMAP.V2.pmapproc_getport'async
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


  let getaddr_rpcbind pm prog vers netid caller_uaddr =
    C.synchronize
      pm.esys
      (getaddr_rpcbind'async pm prog vers netid)
      caller_uaddr


  let dump pm =
    dest_pmaplist
      (PMAP.V2.pmapproc_dump pm.client ())

  let dump'async pm callback =
    PMAP.V2.pmapproc_dump'async pm.client ()
      (fun getresult -> 
         callback (fun () -> dest_pmaplist(getresult()))
      )


  let port_of_program program serverhost prot =
    let pm = create_inet serverhost Rpc.Udp in
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


  let sockaddr_of_program_rpcbind program serverhost netid =
    let proto =
      if netid = "udp" || netid = "udp6" then Rpc.Udp else Rpc.Tcp in
    let pm = create_inet serverhost proto in
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

                        
end
