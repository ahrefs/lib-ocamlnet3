(* 
 * $Id$
 *)

(** Compatibility with OCamlnet-3

   In Ocamlnet-4 many definitions were moved to separate modules that
   once used to reside in {!Uq_engines}. In order to ease the transition,
   this module here provides the old version of [Uq_engines].

   In order to use it, just put this line at the beginnging of the
   ml file:

   {[ module Uq_engines = Uq_engines_compat ]}

   Note that this is really meant as a help for getting through
   transition phases. This module will disappear in future versions of
   OCamlnet.
 *)

exception Closed_channel
exception Broken_communication
exception Watchdog_timeout
exception Timeout
exception Addressing_method_not_supported
exception Cancelled

type 't engine_state =
  [ `Working of int
  | `Done of 't
  | `Error of exn
  | `Aborted
  ]

type 't final_state =
  [ `Done of 't
  | `Error of exn
  | `Aborted
  ]

val string_of_state : 'a engine_state -> string

class type [ 't ] engine = object
  method state : 't engine_state
  method abort : unit -> unit
  method request_notification : (unit -> bool) -> unit
  method request_proxy_notification : ('a engine -> bool) -> unit
  method event_system : Unixqueue.event_system
end

class ['t] delegate_engine : 't #engine -> ['t] engine

val when_state : ?is_done:('a -> unit) ->
                 ?is_error:(exn -> unit) ->
                 ?is_aborted:(unit -> unit) ->
                 ?is_progressing:(int -> unit) ->
                 'a #engine ->
		   unit

class ['a] signal_engine : Unixqueue.event_system ->
object
  inherit ['a] engine
  method signal : 'a final_state -> unit
end

val signal_engine : Unixqueue.event_system -> 
                      'a engine * ('a final_state -> unit)

class ['a,'b] map_engine : map_done:('a -> 'b engine_state) ->
                           ?map_error:(exn -> 'b engine_state) ->
                           ?map_aborted:(unit -> 'b engine_state) ->
                           ?propagate_working : bool ->
                           'a #engine ->
			     ['b] engine

val map_engine : map_done:('a -> 'b engine_state) ->
                 ?map_error:(exn -> 'b engine_state) ->
                 ?map_aborted:(unit -> 'b engine_state) ->
                 ?propagate_working : bool ->
                 'a #engine ->
                    'b engine

class ['a,'b] fmap_engine : 'a #engine -> 
                           ('a final_state -> 'b final_state) -> 
                               ['b] engine
  
val fmap_engine : 'a #engine -> 
                   ('a final_state -> 'b final_state) -> 
                     'b engine

class ['a] meta_engine : 'a #engine -> ['a final_state] engine

val meta_engine : 'a #engine -> 'a final_state engine

class ['t] epsilon_engine : 
             't engine_state -> Unixqueue.event_system -> ['t] engine

val epsilon_engine : 
     't engine_state -> Unixqueue.event_system -> 't engine

class ['a, 'b] seq_engine : 'a #engine -> ('a -> 'b #engine) -> ['b] engine

val seq_engine : 'a #engine -> ('a -> 'b #engine) -> 'b engine

class ['a, 'b] qseq_engine : 'a #engine -> ('a -> 'b #engine) -> ['b] engine
val qseq_engine : 'a #engine -> ('a -> 'b #engine) -> 'b engine

class ['a] stream_seq_engine : 'a -> ('a -> 'a #engine) Stream.t -> 
                               Unixqueue.event_system -> ['a] engine

val stream_seq_engine : 'a -> ('a -> 'a #engine) Stream.t -> 
                         Unixqueue.event_system -> 'a engine

class ['a, 'b] sync_engine : 'a #engine -> 'b #engine -> ['a * 'b] engine

val sync_engine : 'a #engine -> 'b #engine -> ('a * 'b) engine

class ['a,'b] msync_engine : 'a #engine list -> 
                             ('a -> 'b -> 'b) ->
                             'b ->
                             Unixqueue.event_system -> 
                             ['b] engine

val msync_engine : 'a #engine list -> 
                   ('a -> 'b -> 'b) ->
                   'b ->
                   Unixqueue.event_system ->
                      'b engine

class ['a ] delay_engine : float -> (unit -> 'a #engine) -> 
                           Unixqueue.event_system ->
                             ['a] engine

val delay_engine : float -> (unit -> 'a #engine) -> 
                   Unixqueue.event_system ->
                     'a engine

class ['a] timeout_engine : float -> exn -> 'a engine -> ['a] engine

val timeout_engine : float -> exn -> 'a engine -> 'a engine

class watchdog : float -> 
                 'a #engine ->
                   [unit] engine

val watchdog : float -> 'a #engine -> unit engine

class type ['a] serializer_t =
object
  method serialized : (Unixqueue.event_system -> 'a engine) -> 'a engine
end

class ['a] serializer : Unixqueue.event_system -> ['a] serializer_t

val serializer : Unixqueue.event_system -> 'a serializer_t

class type ['a] prioritizer_t =
object
  method prioritized : (Unixqueue.event_system -> 'a engine) -> int -> 'a engine
end

class ['a] prioritizer : Unixqueue.event_system -> ['a] prioritizer_t

val prioritizer : Unixqueue.event_system -> 'a prioritizer_t

class type ['a] cache_t =
object
  method get_engine : unit -> 'a engine
  method get_opt : unit -> 'a option
  method put : 'a -> unit
  method invalidate : unit -> unit
  method abort : unit -> unit
end

class ['a] cache : (Unixqueue.event_system -> 'a engine) ->
                   Unixqueue.event_system ->
                     ['a] cache_t

val cache : (Unixqueue.event_system -> 'a engine) ->
            Unixqueue.event_system ->
              'a cache_t

class ['t] engine_mixin : 't engine_state -> Unixqueue.event_system ->
object
  method state : 't engine_state
  method private set_state : 't engine_state -> unit
  method request_notification : (unit -> bool) -> unit
  method request_proxy_notification : ('t engine -> bool) -> unit
  method private notify : unit -> unit
  method event_system : Unixqueue.event_system
end

module Operators : sig
  val ( ++ ) : 'a #engine -> ('a -> 'b #engine) -> 'b engine
  val ( >> ) : 'a #engine -> 
                   ('a final_state -> 'b final_state) -> 
                     'b engine
  val eps_e : 't engine_state -> Unixqueue.event_system -> 't engine
end


class poll_engine : ?extra_match:(exn -> bool) ->
                    (Unixqueue.operation * float) list -> 
		    Unixqueue.event_system ->
object
  inherit [Unixqueue.event] engine
  method restart : unit -> unit
  method group : Unixqueue.group
end

class ['a] input_engine : (Unix.file_descr -> 'a) ->
                          Unix.file_descr -> float -> Unixqueue.event_system ->
                          ['a] engine

class ['a] output_engine : (Unix.file_descr -> 'a) ->
                           Unix.file_descr -> float -> Unixqueue.event_system ->
                           ['a] engine

class poll_process_engine : ?period:float ->
                            pid:int -> 
                            Unixqueue.event_system ->
			      [Unix.process_status] engine ;;

class type async_out_channel = object
  method output : Bytes.t -> int -> int -> int
  method close_out : unit -> unit
  method pos_out : int
  method flush : unit -> unit
  method can_output : bool
  method request_notification : (unit -> bool) -> unit
end

class type async_in_channel = object
  method input : Bytes.t -> int -> int -> int
  method close_in : unit -> unit
  method pos_in : int
  method can_input : bool
  method request_notification : (unit -> bool) -> unit
end

class pseudo_async_out_channel : 
         #Netchannels.raw_out_channel -> async_out_channel

class pseudo_async_in_channel : 
         #Netchannels.raw_in_channel -> async_in_channel

class receiver : src:Unix.file_descr ->
                 dst:#async_out_channel ->
		 ?close_src:bool ->        (* default: true *)
		 ?close_dst:bool ->        (* default: true *)
		 Unixqueue.event_system ->
		   [unit] engine ;;

class sender : src:#async_in_channel ->
               dst:Unix.file_descr ->
	       ?close_src:bool ->        (* default: true *)
	       ?close_dst:bool ->        (* default: true *)
	       Unixqueue.event_system ->
	         [unit] engine ;;

class type async_out_channel_engine = object
  inherit [ unit ] engine
  inherit async_out_channel
end

class type async_in_channel_engine = object
  inherit [ unit ] engine
  inherit async_in_channel
end

class output_async_descr : dst:Unix.file_descr ->
                           ?buffer_size:int ->
			   ?close_dst:bool ->    (* default: true *)
                           Unixqueue.event_system ->
                             async_out_channel_engine

class input_async_descr : src:Unix.file_descr ->
                          ?buffer_size:int ->
			  ?close_src:bool ->    (* default: true *)
                          Unixqueue.event_system ->
                             async_in_channel_engine

type copy_task =
    [ `Unidirectional of (Unix.file_descr * Unix.file_descr)
    | `Uni_socket of (Unix.file_descr * Unix.file_descr)
    | `Bidirectional of (Unix.file_descr * Unix.file_descr)
    | `Tridirectional of (Unix.file_descr * Unix.file_descr * Unix.file_descr) 
    ]

class copier : copy_task ->
               Unixqueue.event_system ->
		 [unit] engine
type inetspec =
  [ `Sock_inet of (Unix.socket_type * Unix.inet_addr * int)
  | `Sock_inet_byname of (Unix.socket_type * string * int)
  ]

type sockspec =
  [ inetspec
  | `Sock_unix of (Unix.socket_type * string)
  ]

val sockspec_of_sockaddr : Unix.socket_type -> Unix.sockaddr -> sockspec

val sockspec_of_socksymbol : Unix.socket_type -> Netsockaddr.socksymbol ->
                               sockspec

type connect_address =
    [ `Socket of sockspec * connect_options
    | `Command of string * (int -> Unixqueue.event_system -> unit)
    | `W32_pipe of Netsys_win32.pipe_mode * string
    ]

and connect_options = Uq_engines.connect_options =
    { conn_bind : sockspec option;
        (** Bind the connecting socket to this address (same family as the
	 * connected socket required). [None]: Use an anonymous port.
	 *)
    }

val default_connect_options : connect_options;;

type connect_status =
    [ `Socket of Unix.file_descr * sockspec
    | `Command of Unix.file_descr * int
    | `W32_pipe of Unix.file_descr
    ]

val client_endpoint : connect_status -> Unix.file_descr ;;

val client_socket : connect_status -> Unix.file_descr ;;

class type client_endpoint_connector = object
  method connect : connect_address -> 
                   Unixqueue.event_system ->
		     connect_status engine
end

class type client_socket_connector = client_endpoint_connector

val connector : ?proxy:#client_socket_connector ->
                connect_address ->
                Unixqueue.event_system ->
	          connect_status engine 

type listen_options = Uq_engines.listen_options =
    { lstn_backlog : int;
      lstn_reuseaddr : bool
    }

type listen_address =
    [ `Socket of sockspec * listen_options
    | `W32_pipe of Netsys_win32.pipe_mode * string * listen_options
    ]

val default_listen_options : listen_options

class type server_endpoint_acceptor = object
  method server_address : connect_address
  method multiple_connections : bool
  method accept : unit -> (Unix.file_descr * inetspec option) engine
  method shut_down : unit -> unit
end

class type server_socket_acceptor = server_endpoint_acceptor

class direct_acceptor : 
        ?close_on_shutdown:bool ->
        ?preclose:(unit->unit) ->
        Unix.file_descr -> Unixqueue.event_system -> 
          server_endpoint_acceptor
   
class direct_socket_acceptor :
        Unix.file_descr -> Unixqueue.event_system -> 
          server_endpoint_acceptor

class type server_endpoint_listener = object
  method listen : listen_address ->
                  Unixqueue.event_system ->
		    server_endpoint_acceptor engine
end

class type server_socket_listener = server_endpoint_listener

val listener : ?proxy:#server_socket_listener ->
               listen_address ->
	       Unixqueue.event_system ->
		 server_socket_acceptor engine ;;

type datagram_type =
    [ `Unix_dgram
    | `Inet_udp
    | `Inet6_udp
    ]

class type wrapped_datagram_socket =
object
  method descriptor : Unix.file_descr
  method sendto : 
    Bytes.t -> int -> int -> Unix.msg_flag list -> sockspec -> int
  method recvfrom : 
    Bytes.t -> int -> int -> Unix.msg_flag list -> (int * sockspec)
  method shut_down : unit -> unit
  method datagram_type : datagram_type
  method socket_domain : Unix.socket_domain
  method socket_type : Unix.socket_type
  method socket_protocol : int
end

class type datagram_socket_provider =
object
  method create_datagram_socket : datagram_type ->
                                  Unixqueue.event_system ->
                                    wrapped_datagram_socket engine
end


val datagram_provider : ?proxy:#datagram_socket_provider ->
                        datagram_type ->
                        Unixqueue.event_system ->
			  wrapped_datagram_socket engine;;
class type multiplex_controller =
object
  method alive : bool
  method mem_supported : bool
  method event_system : Unixqueue.event_system
  method tls_session_props : Nettls_support.tls_session_props option
  method tls_session : (string * string) option
  method tls_stashed_endpoint : unit -> exn
  method reading : bool
  method start_reading : 
    ?peek:(unit -> unit) ->
    when_done:(exn option -> int -> unit) -> Bytes.t -> int -> int -> unit
  method start_mem_reading : 
    ?peek:(unit -> unit) ->
    when_done:(exn option -> int -> unit) -> Netsys_mem.memory -> int -> int ->
    unit
  method cancel_reading : unit -> unit
  method writing : bool
  method start_writing :
    when_done:(exn option -> int -> unit) -> Bytes.t -> int -> int -> unit
  method start_mem_writing : 
    when_done:(exn option -> int -> unit) -> Netsys_mem.memory -> int -> int ->
    unit
  method supports_half_open_connection : bool
  method start_writing_eof :
    when_done:(exn option -> unit) -> unit -> unit
  method cancel_writing : unit -> unit
  method read_eof : bool
  method wrote_eof : bool
  method shutting_down : bool
  method start_shutting_down :
    ?linger : float ->
    when_done:(exn option -> unit) -> unit -> unit
  method cancel_shutting_down : unit -> unit
  method inactivate : unit -> unit
end


exception Mem_not_supported

val create_multiplex_controller_for_connected_socket : 
      ?close_inactive_descr:bool ->
      ?preclose:(unit -> unit) ->
      ?supports_half_open_connection:bool ->
      ?timeout:(float * exn) ->
      Unix.file_descr -> Unixqueue.unix_event_system -> multiplex_controller

class type datagram_multiplex_controller =
object
  inherit multiplex_controller
  method received_from : Unix.sockaddr
  method send_to : Unix.sockaddr -> unit
end

val create_multiplex_controller_for_datagram_socket : 
      ?close_inactive_descr:bool ->
      ?preclose:(unit -> unit) ->
      ?timeout:(float * exn) ->
      Unix.file_descr -> Unixqueue.unix_event_system -> 
        datagram_multiplex_controller

type onshutdown_out_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_out_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]

type onshutdown_in_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_in_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]

class output_async_mplex : 
       ?onclose:[ `Write_eof | `Ignore ] ->
       ?onshutdown:onshutdown_out_spec ->
       ?buffer_size:int ->
       multiplex_controller ->
         async_out_channel_engine

class input_async_mplex : 
       ?onshutdown:onshutdown_in_spec ->
       ?buffer_size:int ->
       multiplex_controller ->
         async_in_channel_engine

module Debug : sig
  val enable : bool ref
end
