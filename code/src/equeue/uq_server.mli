(* $Id$ *)

open Uq_engines

(** {2 Server sockets} *)

type listen_address =
    [ `Socket of sockspec * listen_options
    | `W32_pipe of Netsys_win32.pipe_mode * string * listen_options
(* ---
 * `Command: Does not work, as the command has no way to tell us when
 * a new connection is accepted. (It should output something for that
 * purpose; is there a standard protocol for this?)
 * Maybe what we really need is a listen_option that filters the whole
 * stream through a command (bidirectional filter).
 * ---
    | `Command of string * (int -> Unixqueue.event_system -> unit)
	(* A command (1st arg) is started with the shell, and it is expected
	 * that the command accepts one connection, and that stdin and stdout
	 * are used to transfer data to the process and from the process,
	 * respectively. Only SOCK_STREAM type is supported. Note that the
	 * passed file descriptors are normal pipes, not sockets (so the
	 * descriptors can be individually closed).
	 *
	 * There is not any kind of error detection, so the command should
	 * be failsafe. stderr of the command is connected with stderr of
	 * the caller process.
	 *
	 * No provisions are taken to wait for the process; this is the
	 * task of the caller. After the process has been started, the
	 * 2nd argument is invoked with the process ID and the event system
	 * to give the caller a chance to arrange that the process will be
	 * waited for.
	 *)
 *)
    ]
  (** Specifies the resource to listen on:
   * 
   * - [`Socket(addr,opts)]: It is listened on a socket with address [addr]
   * - [`W32_pipe(mode,name,opts)]: It is listened on a pipe server with
   *   [name] which accepts pipe connections in [mode].
   *)


and listen_options = Uq_engines.listen_options =
    { lstn_backlog : int;    (** The length of the queue of not yet accepted
			      * connections.
			      *)
      lstn_reuseaddr : bool; (** Whether to allow that the address can be
			      * immediately reused after the previous listener
			      * has its socket shut down. (Only for Internet
                              * sockets.)
			      *)
    }
;;


val default_listen_options : listen_options;;
  (** Returns the default options *)

val listen_on_inet_socket : Unix.inet_addr -> int -> Unix.socket_type -> 
                            listen_options -> Unix.file_descr
  (** [listen_on_inet_socket addr port stype opts]: Creates a TCP or UDP 
      server socket
      for IPv4 or IPv6, depending on the type of address. The socket is
      listening.

      As special cases, the addresses "::1" and "::" are always understood 
      even if IPv6 is not avaiable, and treated as the corresponding IPv4
      addresses (127.0.0.1 and 0.0.0.0, resp.) instead.
   *)

val listen_on_unix_socket : string -> Unix.socket_type -> 
                            listen_options -> Unix.file_descr
  (** [listen_on_unix_socket path stype opts]: Creates a Unix Domain server
      socket for the given [path]. The socket is listening.

      On Win32, Unix Domain sockets are emulated by opening an Internet
      socket on the loopback interface, and by writing the port number
      to [path].
   *)


val listen_on_w32_pipe : Netsys_win32.pipe_mode -> string -> listen_options ->
                         Unix.file_descr
  (** [listen_on_w32_pipe mode path opts]: Creates a Win32 pipe server and
      returns the proxy descriptor.
   *)


val listen_on : listen_address -> Unix.file_descr
  (** [listen_on addr]: Creates a server endpoint for [addr] *)


(** This class type is for service providers that listen for connections.
 * By calling [accept], one gets an engine that waits for the next
 * connection, and establishes it.
 *
 * There are services that can only accept one connection for a 
 * certain contact address. In this case [accept] must only be called
 * once. Normally, services can accept any number of connections
 * (multiplexing), and it is allowed to call [accept] again after
 * the previous accept engine was successful.
 *)
class type server_endpoint_acceptor = object

  method server_address : connect_address
    (** The contact address under which the clients can establish new
     * connections with this server.
     *)

  method multiple_connections : bool
    (** Whether it is possible to accept multiple connections *)

  method accept : unit -> (Unix.file_descr * inetspec option) engine
    (** Instantiates an engine that accepts connections on the listening
     * endpoint. 
     *
     * If the connection is successfully established, the state of the engine
     * changes to [`Done(fd,addr)] where [fd] is the connected file descriptor,
     * and where [addr] (if not-[None]) is the endpoint address of the 
     * connecting client (from the server's perspective). Such addresses are
     * only supported for Internet endpoints. If a proxy is used to accept
     * the connections, the returned address is that from the proxy's 
     * view, and usually different from what [Unix.getpeername] returns.
     *
     * The close-on-exec flag of the created endpoint descriptor is always set.
     * The endpoint descriptor is always in non-blocking mode.
     * 
     * It is allowed to shut down [fd] for sending, and it is required to
     * close [fd] after all data transfers have been performed.
     *
     * A call of [accept] allows it only to establish one connection at a time.
     * However, it is allowed to call [accept] several times to accept several
     * connections, provided the acceptor supports this (returned by
     * [multiple_connections]). It is only allowed to call [accept] again
     * when the previous engine was successful.
     *)

  method shut_down : unit -> unit
    (** The server endpoint is shut down such that no further connections
     * are possible. It is required to call this method even for acceptors
     * that do not support multiple connections. It is also required to
     * call this method when an [accept] was not successful.
     *
     * If there is a engine waiting for connections, it is aborted.
     *)
end
;;


class direct_acceptor : 
        ?close_on_shutdown:bool ->
        ?preclose:(unit->unit) ->
        Unix.file_descr -> Unixqueue.event_system -> 
          server_endpoint_acceptor
(** An implementation of [server_endpoint_acceptor] for sockets and Win32
    named pipes. For sockets, the passed descriptor must be the master
    socket. For Win32 named pipes, the passed descriptor must be the
    proxy descriptor of the pipe server..
 *)


val listener : ?proxy:#server_endpoint_listener ->
               listen_address ->
               Unixqueue.event_system ->
                 server_endpoint_acceptor engine ;;
  (** This engine creates a server socket listening on the [listen_address].
   * If passed, the [proxy] is used to create the server socket.
   *
   * On success, the engine goes to state [`Done acc], where [acc] is
   * the acceptor object (see above). The acceptor object can be used
   * to accept incoming connections.
   *)
