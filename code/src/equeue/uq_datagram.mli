(* $Id$ *)

(** {1 Datagrams} *)

open Uq_engines

type datagram_type =
    [ `Unix_dgram
    | `Inet_udp
    | `Inet6_udp
    ]
  (** - [`Unix_dgram]: Datagrams over Unix domain sockets
   *  - [`Inet_udp]:   Internet v4 UDP protocol
   *  - [`Inet6_udp]:   Internet v6 UDP protocol
   *)
;;


(** A [wrapped_datagram_socket] allows datagrams to be sent via proxies.
 * It provides versions of the [sendto] and [recvfrom] functions that
 * use extended socket names (which are proxy-friendly).
 *)
class type wrapped_datagram_socket =
object
  method descriptor : Unix.file_descr
    (** The underlying file descriptor. This descriptor must not be used
     * to transfer data ([Unix.send(to)], [Unix.recv(from)], etc.), because the
     * descriptor may be connected with a proxy, and the socket addresses
     * may be wrong that are used by the low-level socket functions.
     * The right way is to use the methods below to transfer data. It is
     * allowed, however, to pass the descriptor to [Unix.select], and to check
     * whether transfers are possible. It is also allowed to set or clear
     * non-blocking mode, and the close-on-exec flag, and to modify the
     * socket options.
     *)
  method sendto : 
    Bytes.t -> int -> int -> Unix.msg_flag list -> sockspec -> int
    (** Send data over the (unconnected) socket *)
  method recvfrom : 
    Bytes.t -> int -> int -> Unix.msg_flag list -> (int * sockspec)
    (** Receive data from the (unconnected) socket. The method will
     * raise EAGAIN if the message cannot be processed for some reason,
     * even if the socket is in blocking mode. In this case, the received
     * message is discarded.
     *)
  method shut_down : unit -> unit
    (** Close the descriptor, shuts down any further needed resources *)
  method datagram_type : datagram_type
  method socket_domain : Unix.socket_domain
  method socket_type : Unix.socket_type
  method socket_protocol : int
  (* CHECK: Maybe a method reporting the net size of the send/recv buffers *)
end;;


(** This is a factory for [wrapped_datagram_socket] objects. *)
class type datagram_socket_provider =
object
  method create_datagram_socket : datagram_type ->
                                  Unixqueue.event_system ->
                                    wrapped_datagram_socket engine
    (** Creates an engine that creates a [wrapped_datagram_socket] object
     * and that sets up any further resources the objects needs.
     *)
end ;;


val datagram_provider : ?proxy:#datagram_socket_provider ->
                        datagram_type ->
                        Unixqueue.event_system ->
			  wrapped_datagram_socket engine;;
  (** This engine creates a datagram socket as demanded by the [datagram_type],
   * optionally using [proxy] for sending and receiving datagrams.
   *
   * The socket is unconnected.
   *
   * The socket is in non-blocking mode, and the close-on-exec flag is 
   * set.
   *)


