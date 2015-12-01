(* $Id$ *)

open Netplex_types

let registry = Hashtbl.create 5
let mutex = (!Netsys_oothr.provider) # create_mutex()

let register_server (name:string) (box:polyserver_box) =
  Netsys_oothr.serialize
    mutex
    (fun () ->
       if Hashtbl.mem registry name then
         failwith
           ( "Netplex_internal.register_server: the name has already been used \
              for a different registration: " ^ name);
       Hashtbl.add registry name box
    )
    ()

let connect_client :
      type a . a kind_check -> int -> string -> 
                a Netsys_polysocket.polyclient =
  fun is_kind n name ->
    let box =
      Netsys_oothr.serialize
        mutex
        (fun () ->
           try Hashtbl.find registry name
           with Not_found ->
             failwith ("Netplex_internal.connect_client: service not found: " ^ 
                         name)
        )
        () in
    let Polyserver_box(srv_kind, srv) = box in
    match is_kind.kind_check srv_kind with
      | Equal ->
          let client = Netsys_polysocket.create_client n in
          Netsys_polysocket.connect client srv;
          client
      | Not_equal ->
          failwith ("Netplex_internal.connect_client: wrong kind: " ^ 
                      name)
