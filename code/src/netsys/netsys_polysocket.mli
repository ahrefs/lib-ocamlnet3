(* $Id$ *)

(** Polymorphic message sockets *)

(** These pipes are restricted to a single process, and can be used
    to send messages of any types between threads.
 *)

(** {2 Types} *)

type 'a polyendpoint =
    'a Netsys_polypipe.polypipe * 'a Netsys_polypipe.polypipe
  (** An endpoint is simply a pair [(rd,wr)] where [rd] is a polypipe open
      for reading, and [wr] is a polypipe open for writing.
   *)

type 'a polyclient
  (** A client, connected or unconnected *)

type 'a polyserver
  (** A server *)

(** {2 Clients} *)

val create_client : int -> 'a polyclient
  (** Create a new socket client. The int is the number of messages in the
      pipe buffer.
   *)

val connect : 'a polyclient -> 'a polyserver -> unit
  (** Requests the connection with this server. This function returns always
      immediately.

      Possible [Unix.unix_error] codes:
       - [EALREADY]
       - [EISCONN]
   *)

val endpoint : synchronous:bool -> nonblock:bool ->
               'a polyclient -> 'a polyendpoint
  (** Returns the endpoint once connected. In asynchronous mode, the
      connect is immediately successful. In synchronous mode, it is
      awaited that the server accepts the connection. If also [nonblock]
      is true, the [Unix_error] [EAGAIN] is returned if such waiting
      is needed.

      Possible [Unix.unix_error] codes:
       - [EAGAIN]: the client is non-blocking, and the connection is not yet
         established
       - [EINTR]: a signal arrived
       - [ECONNREFUSED]: the server went down in the meantime
       - [ENOTCONN]: no previous [connect]

      If called several times, this function always returns the same endpoint.
   *)

val close_client : 'a polyclient -> unit
  (** Closes the client and the endpoint. Further interactions with the client
      raise the exception {!Netsys_polypipe.Closed}.
   *)

val set_connect_notify : _ polyclient -> (unit -> unit) -> unit
  (** [set_connect_notify cl f]: Sets that the function [f] is called when
      the connection is accepted. There can only be one such function; any
      previous function is overwritten. Only future connect events are
      reported. The function is called from a different thread.
   *)

val connect_descr : 'a polyclient -> Unix.file_descr
  (** Returns a descriptor that can be used for polling. This is only
      meaningful for synchronous connects. When the descriptor
      is readable the connection is accepted, and calling [endpoint]
      again is promising.

      If [connect_descr] is called several times, always the same descriptor is
      returned.

      The caller has to close the descriptor after use.

      You can call this function only after [connect].
   *)


(** {2 Servers} *)

val create_server : unit -> 'a polyserver
  (** Create a new socket server.

      Note that a server needs 2-6 file descriptors in the current
      implementation.
   *)

val accept : nonblock:bool -> 'a polyserver -> 'a polyendpoint
  (** Accepts the next connection (or returns the next connection from the
      backlog queue). If the server is blocking, this
      function waits until the connection is established.

      Possible [Unix.unix_error] codes:
       - [EAGAIN]: the server is non-blocking, and no connection attempt is
         pending
       - [EINTR]: a signal arrived
   *)

val refuse : nonblock:bool -> 'a polyserver -> unit
  (** All pending connection attempts will be refused. The clients will get
      [ECONNREFUSED]. It is possible to return to accepting connections.

      For a non-blocking [refuse] you need to call [refuse] again after
      catching [EAGAIN].
   *)

val pending_connection : _ polyserver -> bool
  (** Whether there is a client waiting for being accepted *)

val close_server : 'a polyserver -> unit
  (** Closes the server. The accepted endpoints need to be closed separately.

      Further interactions with the server cause that the exception
      {!Netsys_polypipe.Closed} will be raised.
   *)

val set_accept_notify : _ polyserver -> (unit -> unit) -> unit
  (** [set_accept_notify srv f]: Sets that the function [f] is called when
      a new connection arrives. There can only be one such function; any
      previous function is overwritten. The event is edge-triggered: when
      several connections arrive the function is only called once. The
      function is called from a different thread.
   *)

val accept_descr : 'a polyserver -> Unix.file_descr
  (** Returns a descriptor that can be used for polling. When the descriptor
      is readable a pending connection exists. If called several times,
      always the same descriptor is returned.

      The caller has to close the descriptor after use.

      You can call this function before or after [accept].
   *)
