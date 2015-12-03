(* $Id$ *)

open Netplex_types
open Printf


let create_server_socket = 
  Netplex_util.create_server_socket

let close_server_socket =
  Netplex_util.close_server_socket

let open_master_sockets srvname prots =
  let fdlist = ref [] in
  let sockets = ref [] in

  try
    List.iter
      (fun proto ->
	 let addresses =  (* skip `Container addresses *)
	   Array.of_list
	     (List.filter
		(function
		   | `Container _ -> false
                   | `Internal _ -> false
		   | _ -> true 
		)
		(Array.to_list proto#addresses)
	     ) in
	 let fda =
	   Array.map
	     (fun addr ->
		let fd = 
		  Netplex_util.create_server_socket srvname proto addr in
		fdlist := fd :: !fdlist;
		Netlog.Debug.track_fd
		  ~owner:"Netplex_sockserv"
		  ~descr:(sprintf 
			    "Master socket service=%s proto=%s %s"
			    srvname proto#name 
			    (Netsys.string_of_fd fd))
		  fd;
		fd
	     )
	     addresses in
	 sockets := (proto#name, fda) :: !sockets
      )
      prots;
    List.rev !sockets
  with
    | error ->
	List.iter (fun fd -> try Unix.close fd with _ -> ()) !fdlist;
	raise error
;;



let close_master_sockets sockets =
  List.iter
    (fun (_, fda) ->
       Array.iter
	 (fun fd ->
	    Netplex_util.close_server_socket_1 ~release:true fd
	 )
	 fda
    )
    sockets
;;


let close_internal_sockets sockets =
  List.iter
    (fun (_,Polyserver_box(_,srv)) ->
       Unix.close (Netsys_polysocket.accept_descr srv);
       Netsys_polysocket.close_server srv;
    )
    sockets


let open_internal_sockets prots proc =
  let sockets = ref [] in
  let reglist = ref [] in
  try
    List.iter
      (fun proto ->
	 let addresses =
	   List.filter
	     (function
               | `Internal _ -> true
	       | _ -> false 
	     )
	     (Array.to_list proto#addresses) in
         match addresses with
           | [] -> ()
           | [addr] ->
               let name =
                 match addr with
                   | `Internal name -> name
                   | _ -> assert false in
               let Polysocket_kind_box kind =
                 try List.assoc proto#name proc#config_internal
                 with Not_found ->
                   try List.assoc "*" proc#config_internal
                   with Not_found ->
                      failwith ("Netplex_sockserv.open_internal_sockets: \
                                 no entry in config_internal found for \
                                 protocol: " ^ proto#name) in
               let srv =
                 Netsys_polysocket.create_server() in
               let reg() =
                 Netplex_internal.register_server
                   name (Polyserver_box(kind,srv)) in
               sockets := (proto#name,Polyserver_box(kind,srv)) :: !sockets;
               reglist := reg :: !reglist;
           | _ ->
               failwith ("Netplex_sockserv.open_internal_sockets: \
                          more than one internal socket for protocol: " ^
                           proto#name)
      )
      prots;
    List.iter
      (fun f -> f())
      (List.rev !reglist);
    List.rev !sockets
  with
    | error ->
        close_internal_sockets !sockets;
	raise error
;;


class std_socket_service 
	proc
        config : socket_service =
  let sockets = open_master_sockets config#name config#protocols in
  let internal_sockets = open_internal_sockets config#protocols proc in
  let startup_directory = ref None in
object(self)
  method name = config#name
  method sockets = sockets
  method internal_sockets = internal_sockets
  method socket_service_config = config
  method processor = proc
  method create_container sockserv =
    Netplex_container.create_container sockserv
  method shutdown () =
    close_master_sockets sockets;
    close_internal_sockets internal_sockets
  method on_add ctrl =
    startup_directory := Some(ctrl#startup_directory)
  method startup_directory = 
    match !startup_directory with
      | None -> failwith "startup_directory"
      | Some d -> d
end


let create_socket_service = new std_socket_service 


let any_file_client_connector =
  Netplex_util.any_file_client_connector

let client_connector = 
  Netplex_util.client_connector
