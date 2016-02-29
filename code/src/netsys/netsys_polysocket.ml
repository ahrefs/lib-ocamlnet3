(* $Id$ *)

type 'a polypipe = 'a Netsys_polypipe.polypipe

type 'a polyendpoint =
    'a polypipe * 'a polypipe

type 'a conn_request =
    { cl_endpoint : 'a polyendpoint;
      srv_endpoint : 'a polyendpoint;
      rd_notify : bool polypipe;
      wr_notify : bool polypipe;
    }

type 'a polyserver =
    { rd_requests : 'a conn_request polypipe;
      wr_requests : 'a conn_request polypipe;
      mutable accepting : bool;
      mutable dead : bool;
    }

type 'a polyclient_state =
  | Unconnected of int
  | Requesting1 of 'a conn_request * 'a polyserver
  | Requesting2 of 'a conn_request * 'a polyserver
  | Connected of 'a polyendpoint
  | Refused
  | Closed

type 'a polyclient =
    { mutable state : 'a polyclient_state }

let create_client n =
  if n < 1 then invalid_arg "Netsys_polysocket.create_client";
  { state = Unconnected(n) }

let connect cl srv =
  match cl.state with
    | Unconnected(n) ->
        let (rd1, wr1) = Netsys_polypipe.create n in
        let (rd2, wr2) = Netsys_polypipe.create n in
        let (rd_not, wr_not)  = Netsys_polypipe.create 1 in
        let cr =
          { cl_endpoint = (rd1, wr2);
            srv_endpoint = (rd2, wr1);
            rd_notify = rd_not;
            wr_notify = wr_not
          } in
        cl.state <- Requesting1(cr, srv);
        ( try
            Netsys_polypipe.write ~nonblock:false srv.wr_requests (Some cr)
            (* this write is always immediately successful *)
          with
            | Unix.Unix_error(Unix.EPIPE,_,_) ->
                raise (Unix.Unix_error(Unix.ECONNREFUSED,
                                       "Netsys_polysocket.endpoint", ""));
        );
    | Requesting1 _
    | Requesting2 _ ->
        raise (Unix.Unix_error(Unix.EALREADY, "Netsys_polysocket.connect", ""))
    | Connected _ ->
        raise (Unix.Unix_error(Unix.EISCONN, "Netsys_polysocket.connect", ""))
    | Refused ->
        raise (Unix.Unix_error(Unix.ECONNREFUSED,
                               "Netsys_polysocket.connect", ""))
    | Closed ->
        raise Netsys_polypipe.Closed

let close_cr cr =
  Netsys_polypipe.close cr.rd_notify;
  Netsys_polypipe.close (fst cr.cl_endpoint);
  Netsys_polypipe.close (snd cr.cl_endpoint);
  Netsys_polypipe.close (fst cr.srv_endpoint);
  Netsys_polypipe.close (snd cr.srv_endpoint)


let rec endpoint ~synchronous ~nonblock cl =
  match cl.state with
    | Unconnected _ ->
        raise (Unix.Unix_error(Unix.ENOTCONN, "Netsys_polysocket.connect", ""))
    | Requesting1(cr,srv) ->
        if not srv.accepting then
          raise (Unix.Unix_error(Unix.ECONNREFUSED,
                                 "Netsys_polysocket.endpoint", ""));
        cl.state <- Requesting2(cr,srv);
        endpoint ~nonblock ~synchronous cl
    | Requesting2(cr,srv) ->
        if synchronous then (
          let ok = Netsys_polypipe.read ~nonblock cr.rd_notify in
          if ok = Some false then (
            cl.state <- Refused;
            close_cr cr;
            raise (Unix.Unix_error(Unix.ECONNREFUSED,
                                   "Netsys_polysocket.endpoint", ""))
          )
        ) else (
          if not srv.accepting then (
            close_cr cr;
            raise (Unix.Unix_error(Unix.ECONNREFUSED,
                                   "Netsys_polysocket.endpoint", ""));
          )
        );
        Netsys_polypipe.close cr.rd_notify;
        cl.state <- Connected(cr.cl_endpoint);
        cr.cl_endpoint
    | Connected ep ->
        ep
    | Refused ->
        raise (Unix.Unix_error(Unix.ECONNREFUSED,
                               "Netsys_polysocket.endpoint", ""))
    | Closed ->
        raise Netsys_polypipe.Closed

let close_client cl =
  match cl.state with
    | Unconnected _ -> ()
    | Requesting1(cr,srv)
    | Requesting2(cr,srv) ->
        close_cr cr;
        cl.state <- Closed
    | Connected ep ->
        Netsys_polypipe.close (fst ep);
        Netsys_polypipe.close (snd ep);
        cl.state <- Closed
    | Refused
    | Closed ->
        ()


let set_connect_notify cl f =
  match cl.state with
    | Unconnected _ ->
        raise (Unix.Unix_error(Unix.ENOTCONN, "Netsys_polysocket.set_connect_notify", ""))
    | Requesting1(cr,srv)
    | Requesting2(cr,srv) ->
        Netsys_polypipe.set_read_notify cr.rd_notify f
    | Connected _ ->
        ()
    | Refused ->
        ()
    | Closed ->
        raise Netsys_polypipe.Closed


let connect_descr cl =
  match cl.state with
    | Unconnected _ ->
        raise (Unix.Unix_error(Unix.ENOTCONN, "Netsys_polysocket.connect_descr", ""))
    | Requesting1(cr,srv)
    | Requesting2(cr,srv) ->
        Netsys_polypipe.read_descr cr.rd_notify
    | Connected _ ->
        raise (Unix.Unix_error(Unix.EISCONN, "Netsys_polysocket.connect_descr", ""))
    | Refused ->
        raise (Unix.Unix_error(Unix.ECONNREFUSED, "Netsys_polysocket.connect_descr", ""))
    | Closed ->
        raise Netsys_polypipe.Closed

let create_server () =
  let (rd_requests, wr_requests) = Netsys_polypipe.create max_int in
  { rd_requests;
    wr_requests;
    accepting = true;
    dead = false;
  }

let accept ~nonblock srv =
  if srv.dead then raise Netsys_polypipe.Closed;
  srv.accepting <- true;
  match Netsys_polypipe.read ~nonblock srv.rd_requests with
    | None ->
        assert false
    | Some cr ->
        ( try
            Netsys_polypipe.write ~nonblock:false cr.wr_notify (Some true)
          with
            | Netsys_polypipe.Closed -> ()
        );
        cr.srv_endpoint

let accept_descr srv =
  Netsys_polypipe.read_descr srv.rd_requests

let set_accept_notify srv f =
  Netsys_polypipe.set_read_notify srv.rd_requests f

let pending_connection srv =
  Netsys_polypipe.length srv.rd_requests > 0

let refuse ~nonblock srv =
  srv.accepting <- false;
  while Netsys_polypipe.length srv.rd_requests > 0 do
    match Netsys_polypipe.read ~nonblock srv.rd_requests with
      | None ->
          assert false
      | Some cr ->
          let exn =
            Unix.Unix_error(Unix.ECONNREFUSED, "Netsys_polysocket", "") in
          let (p1,p2) = cr.cl_endpoint in
          Netsys_polypipe.set_exception p1 exn;
          Netsys_polypipe.set_exception p2 exn;
          ( try
              Netsys_polypipe.write ~nonblock:false cr.wr_notify (Some false)
            with
              | Netsys_polypipe.Closed -> ()
          )
  done
  

let close_server srv =
  if not srv.dead then (
    Netsys_polypipe.close srv.rd_requests;
    Netsys_polypipe.close srv.wr_requests;
  );
  srv.dead <- true
