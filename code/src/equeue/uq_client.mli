(* $Id$ *)

open Uq_engines

(** Support for socket clients *)

(** Note that Win32 named pipes are also supported by the following
    API's, although they are not sockets. These pipes have a feature
    set comparable to Unix domain sockets.
 *)


type inetspec =
  [ `Sock_inet of (Unix.socket_type * Unix.inet_addr * int)
  | `Sock_inet_byname of (Unix.socket_type * string * int)
  ]

type sockspec =
  [ inetspec
  | `Sock_unix of (Unix.socket_type * string)
  ]
  (** Extended names for socket addresses. Currently, these naming schemes
   * are supported:
   * - [`Sock_unix(stype,path)]: Names the Unix domain socket at [path].
   *   The socket type [stype] is an auxiliary piece of information, but
   *   not a distinguishing part of the name. [path = ""] refers to 
   *   anonymous sockets. Otherwise, the [path] must be an absolute path name.
   * - [`Sock_inet(stype,addr,port)]: Names the Internet socket of type
   *   [stype] bound to the IP address [addr] and the [port].
   *   If [stype = Unix.SOCK_STREAM], a TCP socket is meant, and if 
   *   [stype = Unix.SOCK_DGRAM], a UDP socket is meant. It is allowed
   *   that [addr = Unix.inet_addr_any]. If [port = 0], the name is to
   *   be considered as incomplete.
   * - [`Sock_inet_byname(stype,name,port)]: Names the Internet socket of
   *   type [stype] bound to the IP address corresponding to the 
   *   [name], and bound to the [port]. It is unspecified which naming
   *   service is used to resolve [name] to an IP address, and how it is
   *   used. If the [name] cannot be resolved, no socket is meant; this
   *   is usually an error. [stype] is interpreted as for [`Sock_inet].
   *   If [port = 0], the name is to be considered as incomplete.
   *
   * It is currently not possible to name IP sockets that are bound to
   * several IP addresses but not all IP addresses of the host. 
   *)
;;

val sockspec_of_sockaddr : Unix.socket_type -> Unix.sockaddr -> sockspec
  (** Converts a normal socket address to the extended form *)

val sockspec_of_socksymbol : Unix.socket_type -> Netsockaddr.socksymbol ->
                               sockspec
  (** Converts a {!Netsockaddr.socksymbol} to this form *)


type connect_address =
    [ `Socket of sockspec * connect_options
    | `Command of string * (int -> Unixqueue.event_system -> unit)
    | `W32_pipe of Netsys_win32.pipe_mode * string
    ]
  (** Specifies the service to connect to:
   * 
   * {ul
   * {- [`Socket(addr,opts)]: Connect to the passed socket address}
   * {- [`Command(cmd,handler)]: The [cmd] is started with the shell, 
   *   and [stdin] and [stdout] are used to transfer data to the
   *   process and from the process, respectively. Only [SOCK_STREAM]
   *   type is supported. Note that the passed file descriptors are
   *   normal pipes, not sockets (so the descriptors can be individually
   *   closed).
   *
   *   There is not any kind of error detection, so the command should
   *   be failsafe. [stderr] of the command is connected with [stderr] of
   *   the caller process.
   *
   *   No provisions are taken to wait for the process; this is the
   *   task of the caller. After the process has been started, the
   *   [handler] is invoked with the process ID and the event system
   *   to give the caller a chance to arrange that the process will be
   *   waited for.}
   * {- [`W32_pipe(mode,name)]: A Win32 named pipe}
   * }
   *)


and connect_options = Uq_engines.connect_options =
    { conn_bind : sockspec option;
        (** Bind the connecting socket to this address (same family as the
	 * connected socket required). [None]: Use an anonymous port.
	 *)
    }



val default_connect_options : connect_options;;
  (** Returns the default options *)


type connect_status =
    [ `Socket of Unix.file_descr * sockspec
    | `Command of Unix.file_descr * int
    | `W32_pipe of Unix.file_descr
    ]
  (** This type corresponds with {!Uq_engines.connect_address}: An engine
   * connecting with an address `X will return a status of `X.
   *
   * - [`Socket(fd,addr)]: [fd] is the client socket connected with the
   *   service. [addr] is the socket address of the client that must be
   *   used by the server to reach the client.
   * - [`Command(fd, pid)]: [fd] is the Unix domain socket connected with
   *   the running command. [pid] is the process ID.
   * - [`W32_pipe fd]: [fd] is the proxy descriptor of the connected
   *   Win32 named pipe endpoint. See {!Netsys_win32} how to get the
   *   [w32_pipe] object to access the pipe. The proxy descriptor {b cannot}
   *   be used for I/O.
   *)


val client_endpoint : connect_status -> Unix.file_descr ;;
  (** Returns the client endpoint contained in the [connect_status] *)

val client_channel : Uq_engines.connect_status -> float -> 
                       Netchannels.raw_io_channel
  (** [client_channel st timeout]: returns a bidirectional channel for [st]
      that times out after [timeout] seconds of waiting.
   *)


(** This class type provides engines to connect to a service. In order
 * to get and activate such an engine, call [connect].
 *)
class type client_endpoint_connector = object
  method connect : connect_address -> 
                   Unixqueue.event_system ->
		     connect_status engine
    (** Instantiates an engine that connects to the endpoint given by the
     * [connect_address] argument. If successful, the state of the engine
     * changes to [`Done(status)] where [status] contains the socket 
     * details. The connection is established in the background.
     *
     * The type of status will correspond to the type of connect address
     * (e.g. a [`Socket] address will return a [`Socket] status).
     *
     * The close-on-exec flag of the created socket descriptor is always set.
     * The socket descriptor is always in non-blocking mode.
     *)
end


val connect_e : ?proxy:#Uq_engines.client_endpoint_connector ->
                Uq_engines.connect_address ->
                Unixqueue.event_system ->
	          Uq_engines.connect_status Uq_engines.engine 
  (** This engine connects to a socket as specified by the [connect_address],
     optionally using the [proxy], and changes to the state
     [`Done(status)] when the connection is established.
    
     If the [proxy] does not support the [connect_address], the class 
     will raise [Addressing_method_not_supported].
    
     The descriptor [fd] (part of the [connect_status]) is in non-blocking mode,
     and the close-on-exec flag is set.
     It is the task of the caller to close this descriptor.
    
     The engine attaches automatically to the event system, and detaches
     when it is possible to do so. This depends on the type of the
     connection method. For direct socket connections, the engine can
     often detach immediately when the conection is established. For proxy
     connections it is required that the engine
     copies data to and from the file descriptor. In this case, the
     engine detaches when the file descriptor is closed.
    
     It is possible that name service queries block execution.
     
     If name resolution fails, the engine will enter
     [`Error(Uq_resolver.Host_not_found name)]. 
   *)


val connect : ?proxy:#Uq_engines.client_endpoint_connector ->
              Uq_engines.connect_address ->
              float ->
                Uq_engines.connect_status
  (** [connect addr tmo]: Runs [connect_e] for this [addr], and returns
      the result. After [tmo] seconds, {!Uq_engines.Timeout} will be
      raised.
   *)


(** {b Example} of using [connect_e]: This engine [e] connects to the
    "echo" service as provided by inetd, sends a line of data to it,
    and awaits the response.

    {[
	let e =
	  Uq_engines.connector
	    (`Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "localhost", 7),
		     Uq_engines.default_connect_options))
	    esys
	  ++ (fun cs ->
		match cs with
		  | `Socket(fd,_) ->
		      let mplex =
			Uq_engines.create_multiplex_controller_for_connected_socket
			  ~supports_half_open_connection:true
			  fd esys in
		      let d_unbuf = `Multiplex mplex in
		      let d = `Buffer_in(Uq_io.create_in_buffer d_unbuf) in
		      Uq_io.output_string_e d_unbuf "This is line1\n"
		      ++ (fun () ->
			    Uq_io.input_line_e d 
			    ++ (fun s ->
				  print_endline s;
				  eps_e (`Done()) esys
			       )
			 )
		  | _ -> assert false
	     )
    ]}

 *)


