(* $Id$ *)

let connect_e =
  Uq_engines.connector

let client_endpoint =
  Uq_engines.client_endpoint

let connect ?proxy addr tmo =
  let esys = Unixqueue.create_unix_event_system() in
  let run e1 =
    let e2 = Uq_engines.timeout_engine tmo Uq_engines.Timeout e1 in
    Unixqueue.run esys;
    match e2#state with
      | `Done n -> n
      | `Error err -> raise err
      | `Aborted -> failwith "Aborted"
      | `Working _ -> assert false in
  run(connect_e ?proxy addr esys)


let client_channel st timeout =
  let esys = Unixqueue.create_unix_event_system() in
  let fd = client_endpoint st in
  let dev = `Polldescr(Netsys.get_fd_style fd, fd, esys) in
  Uq_io.io_obj_channel dev timeout
