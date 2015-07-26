(* $Id$ *)

exception Closed

type notifier =
  | NE of Netsys_posix.not_event * Unix.file_descr option
  | W32 of Netsys_win32.w32_event


type 'a pipe =
    { buffer : 'a Queue.t;
      mutable eof : bool;
      size : int;
      mutable rd_descr : notifier;
      mutable wr_descr : notifier;
      mutex : Netsys_oothr.mutex;
      mutable dead : bool;
      mutable exn : exn option;
    }

type 'a polypipe =
    { pipe : 'a pipe;
      readable : bool;
      writable : bool;
    }

let is_win32 =
  Sys.os_type = "Win32"

let create_notifier() =
  if is_win32 then
    W32 (Netsys_win32.create_event())
  else
    NE (Netsys_posix.create_event(), None)

let create_pipe n =
  let rd_descr = create_notifier() in
  let wr_descr = create_notifier() in
  ( match wr_descr with
      | NE(ev,_) -> Netsys_posix.set_event ev
      | W32 ev -> Netsys_win32.set_event ev
  );
  { buffer = Queue.create();
    eof = false;
    size = n;
    rd_descr;
    wr_descr;
    mutex = !Netsys_oothr.provider # create_mutex();
    dead = false;
    exn = None;
  }

let create n =
  let p = create_pipe n in
  ( { pipe = p; readable = true; writable = false },
    { pipe = p; readable = false; writable = true }
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
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
  let n = Queue.length pp.pipe.buffer in
  if n > 0 then (
    let at_min = (n = 1) in
    let at_max = (n >= pp.pipe.size) in
    let msg = Queue.take pp.pipe.buffer in
    if at_min then (
      match pp.pipe.rd_descr with
        | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
        | W32 ev -> Netsys_win32.reset_event ev
    );
    if at_max then (
      match pp.pipe.wr_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
    );
    pp.pipe.mutex # unlock();
    Some msg
  ) else (
    pp.pipe.mutex # unlock();
    if pp.pipe.eof then
      None
    else (
      if nonblock then
        raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.read", ""))
      else (
        ( match pp.pipe.rd_descr with
            | NE(ev,_) -> Netsys_posix.wait_event ev
            | W32 ev -> ignore(Netsys_win32.event_wait ev (-1.0))
        );
        read ~nonblock pp
      )
    )
  )

let rec write ~nonblock pp msg_opt =
  if not pp.writable then
    raise(Unix.Unix_error(Unix.EACCES, "Netsys_polypipe.write", ""));
  pp.pipe.mutex # lock();
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
  match msg_opt with
    | None ->
        pp.pipe.eof <- true;
        ( match pp.pipe.rd_descr with
            | NE(ev,_) -> Netsys_posix.set_event ev
            | W32 ev -> Netsys_win32.set_event ev
        );
        ( match pp.pipe.wr_descr with
            | NE(ev,_) -> Netsys_posix.set_event ev;
            | W32 ev -> Netsys_win32.set_event ev
        );
        pp.pipe.mutex # unlock();
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
            match pp.pipe.rd_descr with
              | NE(ev,_) -> Netsys_posix.set_event ev
              | W32 ev -> Netsys_win32.set_event ev
          );
          if at_max then (
            match pp.pipe.wr_descr with
              | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
              | W32 ev -> Netsys_win32.reset_event ev
          );
          pp.pipe.mutex # unlock();
        ) else (
          pp.pipe.mutex # unlock();
          if nonblock then
            raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.write", ""));
          ( match pp.pipe.wr_descr with
              | NE(ev,_) -> Netsys_posix.wait_event ev
              | W32 ev -> ignore(Netsys_win32.event_wait ev (-1.0))
          );
          write ~nonblock pp msg_opt
        )


let read_descr pp =
  pp.pipe.mutex # lock();
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
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

let write_descr pp =
  pp.pipe.mutex # lock();
  ( match pp.pipe.exn with
      | None -> ()
      | Some exn ->
          pp.pipe.mutex # unlock();
          raise exn
  );
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

let set_exception pp exn =
  if pp.pipe.exn = None then
    pp.pipe.exn <- Some exn

let close pp =
  pp.pipe.mutex # lock();
  if not pp.pipe.dead then (
    ( match pp.pipe.rd_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
    );
    ( match pp.pipe.wr_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
    );
    pp.pipe.dead <- true;
    set_exception pp Closed;
  );
  pp.pipe.mutex # unlock()

