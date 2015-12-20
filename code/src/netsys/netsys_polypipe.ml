(* $Id$ *)

open Printf

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netsys_polypipe" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netsys_polypipe" Debug.enable

let () =
  Netlog.Debug.register_module "Netsys_polypipe" Debug.enable

exception Closed

type notifier =
  | NE of Netsys_posix.not_event * Unix.file_descr option
  | W32 of Netsys_win32.w32_event
  | Plain

type 'a pipe =
    { buffer : 'a Queue.t;
      mutable eof : bool;
      size : int;
      mutable rd_descr : notifier;
      mutable wr_descr : notifier;
      mutable rd_state : bool;
      mutable wr_state : bool;
      rd_cond : Netsys_oothr.condition;
      wr_cond : Netsys_oothr.condition;
      mutex : Netsys_oothr.mutex;
      mutable rd_notify : unit -> unit;
      mutable wr_notify : unit -> unit;
      mutable dead : bool;
      mutable exn : exn option;
    }

type 'a polypipe =
    { pipe : 'a pipe;
      readable : bool;
      writable : bool;
      id : int;
    }

let is_win32 =
  Sys.os_type = "Win32"

let create_notifier() =
  if is_win32 then
    W32 (Netsys_win32.create_event())
  else
    NE (Netsys_posix.create_event(), None)

let create_pipe n =
  { buffer = Queue.create();
    eof = false;
    size = n;
    rd_descr = Plain;
    wr_descr = Plain;
    rd_state = false;
    wr_state = true;
    rd_cond = !Netsys_oothr.provider # create_condition();
    wr_cond = !Netsys_oothr.provider # create_condition();
    rd_notify = (fun () -> ());
    wr_notify = (fun () -> ());
    mutex = !Netsys_oothr.provider # create_mutex();
    dead = false;
    exn = None;
  }

let upgrade_pipe p =
  (* p must be locked *)
  if p.rd_descr = Plain && p.wr_descr = Plain then (
    let rd_descr = create_notifier() in
    let wr_descr = create_notifier() in
    if p.rd_state then (
      match rd_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
        | Plain -> assert false
    );
    if p.wr_state then (
      match wr_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
        | Plain -> assert false
    );
    p.rd_descr <- rd_descr;
    p.wr_descr <- wr_descr
  )


let create n =
  let p = create_pipe n in
  let id = Oo.id (object end) in
  ( { pipe = p; readable = true; writable = false; id },
    { pipe = p; readable = false; writable = true; id }
  )

let length pp =
  pp.pipe.mutex # lock();
  let n = Queue.length pp.pipe.buffer in
  pp.pipe.mutex # unlock();
  n

let eof pp =
  pp.pipe.eof

let rec read ~nonblock pp =
  if not pp.readable then
    raise(Unix.Unix_error(Unix.EACCES, "Netsys_polypipe.read", ""));
  pp.pipe.mutex # lock();
  read_locked ~nonblock pp

and read_locked ~nonblock pp =
  let n = Queue.length pp.pipe.buffer in
  if n > 0 then (
    let at_min = (n = 1) in
    let at_max = (n >= pp.pipe.size) in
    let msg = Queue.take pp.pipe.buffer in
    if at_min then (
      pp.pipe.rd_state <- false;
      match pp.pipe.rd_descr with
        | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
        | W32 ev -> Netsys_win32.reset_event ev
        | Plain -> ()
    );
    if at_max then (
      pp.pipe.wr_state <- true;
      pp.pipe.wr_cond # signal();
      match pp.pipe.wr_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
        | Plain -> ()
    );
    pp.pipe.mutex # unlock();
    dlogr
      (fun () ->
         sprintf "read id=%d uncongested n=%d" pp.id n
      );
    if at_max then pp.pipe.wr_notify();
    Some msg
  ) else (
    if pp.pipe.eof then (
      pp.pipe.mutex # unlock();
      None
    ) else (
      assert (not pp.pipe.rd_state);
      if nonblock then (
        pp.pipe.mutex # unlock();
        dlogr
          (fun () -> sprintf "read id=%d congested EAGAIN" pp.id);
        raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.read", ""))
      ) else (
        dlogr
          (fun () -> sprintf "read id=%d congested blocked" pp.id);
        while not pp.pipe.rd_state do
          pp.pipe.rd_cond # wait pp.pipe.mutex;
        done;
        dlogr
          (fun () -> sprintf "read id=%d congested unblocked" pp.id);
        read_locked ~nonblock pp
      )
    )
  )

let rec write ~nonblock pp msg_opt =
  if not pp.writable then
    raise(Unix.Unix_error(Unix.EACCES, "Netsys_polypipe.write", ""));
  pp.pipe.mutex # lock();
  write_locked ~nonblock pp msg_opt

and write_locked_eof pp =
  let old_eof = pp.pipe.eof in
  pp.pipe.eof <- true;
  let n = Queue.length pp.pipe.buffer in
  let notify = not old_eof && (n = 0) in
  if notify then (
    pp.pipe.rd_state <- true;
    ( match pp.pipe.rd_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
        | Plain -> ()
    );
    pp.pipe.rd_cond # broadcast();
    pp.pipe.mutex # unlock();
  ) else
    pp.pipe.mutex # unlock();
  dlogr
    (fun () -> sprintf "write id=%d eof" pp.id);
  if notify then pp.pipe.rd_notify();
  
and write_locked ~nonblock pp msg_opt =
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
  match msg_opt with
    | None ->
        write_locked_eof pp
    | Some msg ->
        if pp.pipe.eof then (
          pp.pipe.mutex # unlock();
          raise(Unix.Unix_error(Unix.EPIPE, "Netsys_polypipe.write", ""))
        );
        let n = Queue.length pp.pipe.buffer in
        if n < pp.pipe.size then (
          Queue.add msg pp.pipe.buffer;
          let at_min = (n = 0) in
          let at_max = (n+1 >= pp.pipe.size) in
          if at_min then (
            pp.pipe.rd_state <- true;
            pp.pipe.rd_cond # signal();
            match pp.pipe.rd_descr with
              | NE(ev,_) -> Netsys_posix.set_event ev
              | W32 ev -> Netsys_win32.set_event ev
              | Plain -> ()
          );
          if at_max then (
            pp.pipe.wr_state <- false;
            match pp.pipe.wr_descr with
              | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
              | W32 ev -> Netsys_win32.reset_event ev
              | Plain -> ()
          );
          pp.pipe.mutex # unlock();
          dlogr
            (fun () -> sprintf "write id=%d uncongested n=%d" pp.id n);
          if at_min then pp.pipe.rd_notify();
        ) else (
          if nonblock then (
            pp.pipe.mutex # unlock();
            dlogr
              (fun () -> sprintf "write id=%d congested EAGAIN" pp.id);
            raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.write", ""));
          );
          dlogr
            (fun () -> sprintf "write id=%d congested blocked" pp.id);
          while not pp.pipe.wr_state do
            pp.pipe.wr_cond # wait pp.pipe.mutex
          done;
          dlogr
            (fun () -> sprintf "write id=%d congested unblocked" pp.id);
          write_locked ~nonblock pp msg_opt
        )


let read_descr pp =
  pp.pipe.mutex # lock();
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
  upgrade_pipe pp.pipe;
  match pp.pipe.rd_descr with
    | NE(ev, None) ->
        let fd = Netsys_posix.get_event_fd ev in
        pp.pipe.rd_descr <- NE(ev, Some fd);
        pp.pipe.mutex # unlock();
        fd
    | NE(_, Some fd) ->
        pp.pipe.mutex # unlock();
        fd
    | W32 ev ->
        let fd = Netsys_win32.event_descr ev in
        pp.pipe.mutex # unlock();
        fd
    | Plain ->
        assert false

let write_descr pp =
  pp.pipe.mutex # lock();
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
  upgrade_pipe pp.pipe;
  match pp.pipe.wr_descr with
    | NE(ev, None) ->
        let fd = Netsys_posix.get_event_fd ev in
        pp.pipe.wr_descr <- NE(ev, Some fd);
        pp.pipe.mutex # unlock();
        fd
    | NE(_, Some fd) ->
        pp.pipe.mutex # unlock();
        fd
    | W32 ev ->
        let fd = Netsys_win32.event_descr ev in
        pp.pipe.mutex # unlock();
        fd
    | Plain ->
        assert false

let set_exception pp exn =
  pp.pipe.mutex # lock();
  if pp.pipe.exn = None then (
    pp.pipe.exn <- Some exn;
  );
  if pp.writable && not pp.pipe.eof then 
    write_locked_eof pp   (* and unlock *)
  else
    pp.pipe.mutex # unlock()

let get_exception pp =
  pp.pipe.exn

let set_read_notify pp f =
  pp.pipe.rd_notify <- f

let set_write_notify pp f =
  pp.pipe.wr_notify <- f

let close pp =
  pp.pipe.mutex # lock();
  if not pp.pipe.dead then (
    ( match pp.pipe.rd_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
        | Plain -> ()
    );
    ( match pp.pipe.wr_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
        | Plain -> ()
    );
    pp.pipe.dead <- true;
    pp.pipe.mutex # unlock();
    set_exception pp Closed;
  )
  else
    pp.pipe.mutex # unlock()

