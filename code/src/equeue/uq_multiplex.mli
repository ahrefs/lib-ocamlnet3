(* $Id$ *)

(** {1 Multiplex Controllers} *)

(** A [multiplex_controller] is a quite low-level device to abstract
  * bidirectional socket connections. It is independent of any real
  * device.
  *
  * There can be a reader, a writer (or both), or alternatively,
  * the shutdown process may be in progress. One cannot have more than
  * one reader and more than more writer.
 *)
class type multiplex_controller =
object
  method alive : bool
    (** If the controller is alive, the socket is not yet completely down. *)

  method mem_supported : bool
    (** Whether [start_mem_reading] and [start_mem_writing] are possible *)

  method event_system : Unixqueue.event_system
    (** Returns the event system *)

  method tls_session_props : Nettls_support.tls_session_props option
    (** If TLS is enabled, this returns the session properties. These
        are first available after the TLS handshake.
     *)

  method tls_session : (string * string) option
    (** If TLS is enabled, this returns (session_id, session_data). This
        is first available after the TLS handshake.
     *)

  method tls_stashed_endpoint : unit -> exn
    (** Returns the TLS endpoint in stashed form. Note that the
        multiplex controller becomes immediately unusable.
     *)

  method reading : bool
    (** True iff there is a reader *)

  method start_reading : 
    ?peek:(unit -> unit) ->
    when_done:(exn option -> int -> unit) -> Bytes.t -> int -> int -> unit
    (** Start reading from the connection. When data is available, the
      * [when_done] callback is invoked. The int is the number of read
      * bytes. It is 0 if an error occurred which is indicated by the
      * exception. The exception [End_of_file] is used when the end of the
      * data stream is reached. The exception [Cancelled] indicates that
      * reading has been cancelled in the meantime.
      *
      * This starts one-time read job only, i.e. it is not restarted
      * after [when_done] has been invoked.
      *
      * It is an error to start reading several times.
      *
      * The function [peek] is called immediately before data is read in
      * from the underlying communication channel.
      *
      * For getting an engine-based version of [start_reading], use
      * a [signal_engine]:
      * {[ 
      *    let (e, signal) = signal_engine esys in
      *    mplex # start_reading ~when_done:(fun xo n -> signal (xo,n)) ...
      * ]}
      * Now [e] will transition to [`Done(x0,n)] when the read is done.
     *)

  method start_mem_reading : 
    ?peek:(unit -> unit) ->
    when_done:(exn option -> int -> unit) -> Netsys_mem.memory -> int -> int ->
    unit
    (** Same as [start_reading], but puts the data into a [memory] buffer.
        There is an optimization for the case that the descriptor is a
        connected socket, or supports [Unix.read]. If this is not possible
        the method raises [Mem_not_supported].
     *)

  method cancel_reading : unit -> unit
    (** Cancels the read job. The [when_done] callback is invoked with the
      * number of bytes read so far (which may be 0) and the exception
      * [Cancelled].
      *
      * It is no error if there is no reader.
     *)

  method writing : bool
   (** True iff there is a writer *)

  method start_writing :
    when_done:(exn option -> int -> unit) -> Bytes.t -> int -> int -> unit
    (** Start writing to the connection. When data is written, the
      * [when_done] callback is invoked. The int is the number of written
      * bytes. It is 0 if an error occurred which is indicated by the
      * exception. The exception [Cancelled] indicates that
      * writing has been cancelled in the meantime.
      *
      * This starts one-time write job only, i.e. it is not restarted
      * after [when_done] has been invoked.
      *
      * It is an error to start writing several times.
      *
      * See the comment for [start_reading] for how to get an engine-based
      * version of this method.
     *)

  method start_mem_writing : 
    when_done:(exn option -> int -> unit) -> Netsys_mem.memory -> int -> int ->
    unit
    (** Same as [start_writing], but takes the data from a [memory] buffer.
        There is an optimization for the case that the descriptor is a
        connected socket, or supports [Unix.write]. If this is not possible
        the method raises [Mem_not_supported].
     *)

  method supports_half_open_connection : bool
    (** Whether the underlying transport mechanism can close the write side
      * of the connection only (half-open connection).
     *)

  method start_writing_eof :
    when_done:(exn option -> unit) -> unit -> unit
    (** Start writing the EOF marker to the connection. When it is written,
      * the [when_done] callback is invoked. The exception [Cancelled] indicates
      * that writing has been cancelled in the meantime.
      *
      * This starts one-time write job only, i.e. it is not restarted
      * after [when_done] has been invoked.
      *
      * It is an error to start writing several times. It is an error to
      * write EOF when the socket does not support half-open connections.
      *
      * See the comment for [start_reading] for how to get an engine-based
      * version of this method.
     *)

  method cancel_writing : unit -> unit
    (** Cancels the write job. The [when_done] callback is invoked with the
      * number of bytes read so far (which may be 0) and the exception
      * [Canelled].
      *
      * It is no error if there is no writer.
     *)

  method read_eof : bool
    (** Whether the EOF marker has been read *)

  method wrote_eof : bool
    (** Whether the EOF marker has been written *)

  method shutting_down : bool
    (** True iff the shutdown is in progress *)

  method start_shutting_down :
    ?linger : float ->
    when_done:(exn option -> unit) -> unit -> unit
    (** Start shutting down the connection. After going through the shutdown
      * procedure, the [when_done] callback is invoked. The exception
      * indicates whether an error happened. [Cancelled] means that the
      * shutdown operation has been cancelled in the meantime.
      *
      * The underlying file descriptor (if any) is not closed. A shutdown
      * is only a protocol handshake. After a shutdown, both [read_eof]
      * and [wrote_eof] are true. Call [inactivate] to close the descriptor.
      *
      * Optionally, one can [linger] for a certain period of time.
      * It is only lingered when the EOF was written before the EOF 
      * is seen on input.
      * Defaults to [linger 60.0]. Set to 0 to turn off.
      *
      * See the comment for [start_reading] for how to get an engine-based
      * version of this method.
     *)

  method cancel_shutting_down : unit -> unit
    (** Cancels the shutdown procedure. After that, the state of the 
      * connection is undefined. The [when_done] callback is invoked with
      * the exception [Cancelled].
      *
      * It is no error if no shutdown is in progress.
     *)

  method inactivate : unit -> unit
    (** Inactivates the connection immediately, and releases any resources
      * the controller is responsible for (e.g. closes file descriptors). 
      * Note that this is more than
      * cancelling all pending operations and shutting the connection down.
      * However, the details of this method are implementation-defined.
      * Callbacks are not invoked.
     *)
end



(** Additional methods for unconnected datagram handling *)
class type datagram_multiplex_controller =
object
  inherit multiplex_controller

  method received_from : Unix.sockaddr
    (** Returns the socket address of the last received datagram. This
      * value is updated just before the [when_done] callback of the
      * reader is invoked.
     *)

  method send_to : Unix.sockaddr -> unit
    (** Sets the socket address of the next datagram to send. *)

end


exception Mem_not_supported
  (** May be raised by multiplex controller methods [start_mem_reading] and
      [start_mem_writing] if these methods are not supported for the kind
      of file descriptor
   *)

val create_multiplex_controller_for_connected_socket : 
      ?close_inactive_descr:bool ->
      ?preclose:(unit -> unit) ->
      ?supports_half_open_connection:bool ->
      ?timeout:(float * exn) ->
      Unix.file_descr -> Unixqueue.unix_event_system -> multiplex_controller
  (** Creates a multiplex controller for a bidirectional socket (e.g.
    * a TCP socket). It is essential that the socket is in connected state.
    * This function also supports Win32 named pipes.
    *
    * Note that the file descriptor is not closed when the attached engines
    * are terminated. One can call [inactivate] manually to do that.
    *
    * [close_inactive_descr]: Whether [inactivate] closes the descriptor.
    * True by default.
    *
    * [preclose]: This function is called just before the descriptor is
    * closed.
    *
    * [supports_half_open_connection]: This implementation does not know
    * how to find out whether the socket supports half-open connections.
    * You can simply set this boolean because of this. Defaults to [false].
    * You can set it to [true] for TCP connections and for Unix-domain
    * connections with stream semantics.
    *
    * [timeout]: If set to [(t, x)], a general timeout of [t] is set.
    * When an operation has been started, and there is no I/O activity within
    * [t] seconds, neither by the started operation nor by another operation,
    * the connection times out. In this case, the operation returns the
    * exception [x].
   *)

val create_multiplex_controller_for_datagram_socket : 
      ?close_inactive_descr:bool ->
      ?preclose:(unit -> unit) ->
      ?timeout:(float * exn) ->
      Unix.file_descr -> Unixqueue.unix_event_system -> 
        datagram_multiplex_controller
  (** Creates a multiplex controller for datagram sockets (e.g. UDP socket).
    *
    * Note that the file descriptor is not closed when the attached engines
    * are terminated. One can call [inactivate] manually to do that.
    *
    * [close_inactive_descr]: Whether [inactivate] closes the descriptor.
    * True by default.
    *
    * [preclose]: This function is called just before the descriptor is
    * closed.
    *
    * [timeout]: If set to [(t, x)], a general timeout of [t] is set.
    * When an operation has been started, and there is no I/O activity within
    * [t] seconds, neither by the started operation nor by another operation,
    * the connection times out. In this case, the operation returns the
    * exception [x].
   *)

val tls_multiplex_controller :
      ?resume:string ->
      ?on_handshake:(multiplex_controller -> unit) ->
      role:[ `Server | `Client ] ->
      peer_name:string option ->
      (module Netsys_crypto_types.TLS_CONFIG) ->
      multiplex_controller ->
        multiplex_controller
  (** Creates a new multiplex controller on top of an existing controller,
      and configures the new controller for running the TLS protocol.

      [resume]: The endpoint resumes an old session whose data are passed here.
      This is only possible for client endpoints.

      [on_handshake]: called back when the handshake is done
   *)

val restore_tls_multiplex_controller :
      ?on_handshake:(multiplex_controller -> unit) ->
      exn ->
      (module Netsys_crypto_types.TLS_CONFIG) ->
      multiplex_controller ->
        multiplex_controller
  (** Like [tls_multiplex_controller], but this function does not create a new
      TLS endpoint. Instead the exn value is assumed to be a stashed old
      endpoint.
   *)

(*
val dtls_multiplex_controller :
      ?resume:string ->
      ?on_handshake:(multiplex_controller -> unit) ->
      role:[ `Server | `Client ] ->
      peer_name:string option ->
      (module Netsys_crypto_types.TLS_CONFIG) ->
      datagram_multiplex_controller ->
        datagram_multiplex_controller

 -- not yet, see comments in uq_multiplex.ml
 *)
