(* $Id$ *)

type notifier =
  | NE of Netsys_posix.not_event * Unix.file_descr option
  | W32 of Netsys_win32.w32_event


type 'a polypipe =
    { buffer : 'a Queue.t;
      mutable eof : bool;
      size : int;
      non_blocking : bool;
      mutable rd_descr : notifier;
      mutable wr_descr : notifier;
      mutex : Netsys_oothr.mutex;
      mutable dead : bool;
    }

let is_win32 =
  Sys.os_type = "Win32"

let create_notifier() =
  if is_win32 then
    W32 (Netsys_win32.create_event())
  else
    NE (Netsys_posix.create_event(), None)

let create n nb =
  let rd_descr = create_notifier() in
  let wr_descr = create_notifier() in
  ( match wr_descr with
      | NE(ev,_) -> Netsys_posix.set_event ev
      | W32 ev -> Netsys_win32.set_event ev
  );
  { buffer = Queue.create();
    eof = false;
    size = n;
    non_blocking = nb;
    rd_descr;
    wr_descr;
    mutex = !Netsys_oothr.provider # create_mutex();
    dead = false;
  }

let length pp =
  pp.mutex # lock();
  let n = Queue.length pp.buffer in
  pp.mutex # unlock();
  n

let eof pp =
  pp.eof

let rec read pp =
  pp.mutex # lock();
  if pp.dead then (
    pp.mutex # unlock();
    failwith "Netsys_polypipe.read: pipe is closed";
  );
  let n = Queue.length pp.buffer in
  if n > 0 then (
    let at_min = (n = 1) in
    let at_max = (n >= pp.size) in
    let msg = Queue.take pp.buffer in
    if at_min then (
      match pp.rd_descr with
        | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
        | W32 ev -> Netsys_win32.reset_event ev
    );
    if at_max then (
      match pp.wr_descr with
        | NE(ev,_) -> Netsys_posix.set_event ev
        | W32 ev -> Netsys_win32.set_event ev
    );
    pp.mutex # unlock();
    Some msg
  ) else (
    pp.mutex # unlock();
    if pp.eof then
      None
    else (
      if pp.non_blocking then
        raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.read", ""))
      else (
        ( match pp.rd_descr with
            | NE(ev,_) -> Netsys_posix.wait_event ev
            | W32 ev -> ignore(Netsys_win32.event_wait ev (-1.0))
        );
        read pp
      )
    )
  )

let rec write pp msg_opt =
  pp.mutex # lock();
  if pp.dead then (
    pp.mutex # unlock();
    failwith "Netsys_polypipe.write: pipe is closed";
  );
  match msg_opt with
    | None ->
        pp.eof <- true;
        ( match pp.rd_descr with
            | NE(ev,_) -> Netsys_posix.set_event ev
            | W32 ev -> Netsys_win32.set_event ev
        );
        ( match pp.wr_descr with
            | NE(ev,_) -> Netsys_posix.set_event ev;
            | W32 ev -> Netsys_win32.set_event ev
        );
        pp.mutex # unlock();
    | Some msg ->
        if pp.eof then (
          pp.mutex # unlock();
          raise(Unix.Unix_error(Unix.EPIPE, "Netsys_polypipe.write", ""))
        );
        let n = Queue.length pp.buffer in
        if n < pp.size then (
          Queue.add msg pp.buffer;
          let at_min = (n = 0) in
          let at_max = (n+1 >= pp.size) in
          if at_min then (
            match pp.rd_descr with
              | NE(ev,_) -> Netsys_posix.set_event ev
              | W32 ev -> Netsys_win32.set_event ev
          );
          if at_max then (
            match pp.wr_descr with
              | NE(ev,_) -> ignore(Netsys_posix.consume_event ev)
              | W32 ev -> Netsys_win32.reset_event ev
          );
          pp.mutex # unlock();
        ) else (
          pp.mutex # unlock();
          if pp.non_blocking then
            raise(Unix.Unix_error(Unix.EAGAIN, "Netsys_polypipe.write", ""));
          ( match pp.wr_descr with
              | NE(ev,_) -> Netsys_posix.wait_event ev
              | W32 ev -> ignore(Netsys_win32.event_wait ev (-1.0))
          );
          write pp msg_opt
        )


let read_descr pp =
  pp.mutex # lock();
  if pp.dead then (
    pp.mutex # unlock();
    failwith "Netsys_polypipe.read_descr: pipe is closed";
  );
  match pp.rd_descr with
    | NE(ev, None) ->
        let fd = Netsys_posix.get_event_fd ev in
        pp.rd_descr <- NE(ev, Some fd);
        pp.mutex # unlock();
        fd
    | NE(_, Some fd) ->
        pp.mutex # unlock();
        fd
    | W32 ev ->
        let fd = Netsys_win32.event_descr ev in
        pp.mutex # unlock();
        fd

let write_descr pp =
  pp.mutex # lock();
  if pp.dead then (
    pp.mutex # unlock();
    failwith "Netsys_polypipe.write_descr: pipe is closed";
  );
  match pp.wr_descr with
    | NE(ev, None) ->
        let fd = Netsys_posix.get_event_fd ev in
        pp.wr_descr <- NE(ev, Some fd);
        pp.mutex # unlock();
        fd
    | NE(_, Some fd) ->
        pp.mutex # unlock();
        fd
    | W32 ev ->
        let fd = Netsys_win32.event_descr ev in
        pp.mutex # unlock();
        fd

let close pp =
  pp.mutex # lock();
  if not pp.dead then (
    ( match pp.rd_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
    );
    ( match pp.wr_descr with
        | NE(ev,_) ->
            Netsys_posix.destroy_event ev
        | W32 _ ->
            ()
    );
    pp.dead <- true;
  );
  pp.mutex # unlock()

