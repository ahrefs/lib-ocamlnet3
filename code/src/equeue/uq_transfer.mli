(* $Id$ *)

open Uq_engines

(** {1 Transfer engines} *)

(** Transfer engines copy data between file descriptors. This kind
    of engine is likely to be declared as deprecated in
    the future. If possible, one should use multiplex controllers
    (see below), and for copying streams the generic copier 
    {!Uq_io.copy_e} is a better choice.

    The pure types [async_in_channel] and [async_out_channel] have been
    proven to be useful for bridging with {!Netchannels}.
 *)

(** An asynchrounous output channel provides methods to output data to
 * a stream descriptor. It is based on [raw_out_channel], which is 
 * defined by the Ocamlnet module [Netchannels] (see there for an 
 * introduction into the idea of using objects as I/O channels).
 * An asynchronous channel can indicate that there is no space in the
 * output buffer. Furthermore, one can request notification in the case
 * that there is no space or again space in the output buffer.
 *)
class type async_out_channel = object

  (** {1 Methods from [raw_out_channel] } *)

  method output : Bytes.t -> int -> int -> int
    (** [output s k n]: Writes the substring of [s] beginning at index
     * [k] with length [n] into the channel. The channel is free to
     * accept only a portion of the string (or even nothing), and 
     * returns the number of bytes it accepts.
     *)

  method close_out : unit -> unit
    (** Closes the channel *)

  method pos_out : int
    (** Returns the number of characters output into the channel *)

  method flush : unit -> unit
    (** Flushes the channel. Asynchronous channels usually ignore
     * flush requests. A potential meaning of flushing could be that
     * no more data are accepted until the current buffer is completely
     * processed. Implementing this is optional.
     *)

  (** {1 Additional control methods} *)

  method can_output : bool
    (** Whether output is possible, i.e. the output method accepts at least
     * one byte
     *)

  method request_notification : (unit -> bool) -> unit
    (** After the notification has been requested, the passed function is
     * be called whenever [can_output] changes its value (or might change
     * its value). The function returns [true] if there is still interest
     * in notification, and [false] if notification must be disabled.
     *
     * There can be any number of parallel active notifications. It is
     * allowed that a notification callback requests further notifications.
     *)
end
;;


(** An asynchrounous input channel provides methods to input data from
 * a stream descriptor. It is based on [raw_in_channel], which is 
 * defined by the Ocamlnet module [Netchannels] (see there for an 
 * introduction into the idea of using objects as I/O channels).
 * An asynchronous channel can indicate that there is no data in the
 * input buffer. Furthermore, one can request notification in the case
 * that there is no data or again data in the input buffer.
 *)
class type async_in_channel = object

  (** {1 Methods from [raw_in_channel] } *)

  method input : Bytes.t -> int -> int -> int
    (** [input s k n]: Reads channel data into the substring of [s]
     * beginning at index [k] with length [n]. The channel is free to
     * fill only a portion of the string (or even nothing). The method 
     * returns the number of bytes actually read.
     *
     * The exception [End_of_file] indicates that the end of the channel
     * is reached. The return value [0], however, means that no data
     * could be read.
     *)

  method close_in : unit -> unit
    (** Closes the channel *)

  method pos_in : int
    (** Returns the number of characters read from the channel *)


  (** {1 Additional control methods} *)

  method can_input : bool
    (** Whether input is possible, i.e. the input method gets at least
     * one byte, or can signal [End_of_file].
     *)

  method request_notification : (unit -> bool) -> unit
    (** After the notification has been requested, the passed function is
     * be called whenever [can_input] changes its value (or might change
     * its value). The function returns [true] if there is still interest
     * in notification, and [false] if notification must be disabled.
     *
     * There can be any number of parallel active notifications. It is
     * allowed that a notification callback requests further notifications.
     *)
end
;;


class pseudo_async_out_channel : 
         #Netchannels.raw_out_channel -> async_out_channel
  (** Takes a {!Netchannels.raw_out_channel} as an asynchronous channel.
      It is always possible to output to this channel.
   *)

class pseudo_async_in_channel : 
         #Netchannels.raw_in_channel -> async_in_channel
  (** Takes a {!Netchannels.raw_in_channel} as an asynchronous channel.
      It is always possible to input from this channel.
   *)


class receiver : src:Unix.file_descr ->
                 dst:#async_out_channel ->
		 ?close_src:bool ->        (* default: true *)
		 ?close_dst:bool ->        (* default: true *)
		 Unixqueue.event_system ->
		   [unit] engine ;;
  (** This engine copies all data from the [src] file descriptor to the
   * [dst] output channel. The engine attaches immediately to the 
   * event system, and detaches automatically. 
   *
   * By default, both the file descriptor and the output channel
   * are closed when the engine stops operation, either successfully
   * or because of an error. 
   *
   * The semantics of the engine is undefined if [src] is not a
   * stream-oriented descriptor.
   *
   * The engine goes to [`Error] state when either reading from [src]
   * or writing to [dst] raises an unexpected exception.
   *
   * For every file descriptor event, the state is advanced from
   * [`Working n] to [`Working (n+1)].
   *
   * TODO: This class cannot yet cope with Win32 named pipes.
   *
   * @param close_src Whether to close [src] when the engine stops
   *   (default: [true])
   * @param close_dst Whether to close [dst] when the engine stops
   *   (default: [true])
   *)


class sender : src:#async_in_channel ->
               dst:Unix.file_descr ->
	       ?close_src:bool ->        (* default: true *)
	       ?close_dst:bool ->        (* default: true *)
	       Unixqueue.event_system ->
	         [unit] engine ;;
  (** This engine copies all data from the [src] input channel to the
   * [dst] file descriptor. The engine attaches immediately to the 
   * event system, and detaches automatically. 
   *
   * By default, both the file descriptor and the output channel
   * are closed when the engine stops operation, either successfully
   * or because of an error. 
   *
   * The semantics of the engine is undefined if [dst] is not a
   * stream-oriented descriptor.
   *
   * The engine goes to [`Error] state when either reading from [src]
   * or writing to [dst] raises an unexpected exception.
   *
   * For every file descriptor event, the state is advanced from
   * [`Working n] to [`Working (n+1)].
   *
   * TODO: This class cannot yet cope with Win32 named pipes.
   *
   * @param close_src Whether to close [src] when the engine stops
   *   (default: [true])
   * @param close_dst Whether to close [dst] when the engine stops
   *   (default: [true])
   *)


class type async_out_channel_engine = object
  inherit [ unit ] engine
  inherit async_out_channel
end
;;
(** Combination of engine + async_out_channel *)


class type async_in_channel_engine = object
  inherit [ unit ] engine
  inherit async_in_channel
end
;;
(** Combination of engine + async_in_channel *)


class output_async_descr : dst:Unix.file_descr ->
                           ?buffer_size:int ->
			   ?close_dst:bool ->    (* default: true *)
                           Unixqueue.event_system ->
                             async_out_channel_engine
  (** This engine implements an [async_out_channel] for the output
   * descriptor [dst]. The engine provides an internal buffer to
   * reduce the number of blocked output operations; by default there
   * is even no limit for the growth of the buffer, and because of this
   * the channel never blocks ([can_output] is always [true]).
   *
   * The engine attaches immediately to the event system, and detaches 
   * automatically. By default, the file descriptor is closed when the
   * engine stops operation, either successfully or because of an
   * error. 
   *
   * If the buffer is full, the class accepts no more data until
   * there is again free space in the buffer. This means that writers
   * must be prepared that [can_output] returns [false], and that
   * the [output] method returns 0. The buffer can only get "full"
   * if the [buffer_size] argument is passed.
   *
   * The notification mechanism is shared by the "engine nature" and
   * by the "channel nature" of this class: If either the [state] or
   * [can_output] change their values, the notification callbacks
   * are invoked.
   *
   * The semantics of the engine is undefined if [dst] is not a
   * stream-oriented descriptor.
   *
   * TODO: This class cannot yet cope with Win32 named piped.
   *
   * @param buffer_size Limits the size of the buffer
   * @param close_dst Whether to close [dst] when the engine stops
   *    (default: [true])
   *)


class input_async_descr : src:Unix.file_descr ->
                          ?buffer_size:int ->
			  ?close_src:bool ->    (* default: true *)
                          Unixqueue.event_system ->
                             async_in_channel_engine
 (** The corresponding class for asynchronous input channels.
   *
   * TODO: This class cannot yet cope with Win32 named piped.
  *)

type copy_task =
    [ `Unidirectional of (Unix.file_descr * Unix.file_descr)
    | `Uni_socket of (Unix.file_descr * Unix.file_descr)
    | `Bidirectional of (Unix.file_descr * Unix.file_descr)
    | `Tridirectional of (Unix.file_descr * Unix.file_descr * Unix.file_descr) 
    ]
  (** Specifies the task the [copier] class has to do:
   *
   * - [`Unidirectional(src,dst)]: Data from [src] are copied to [dst].
   *   EOF of [src] causes that both descriptors are closed.
   * - [`Uni_socket(src,dst)]: Data from [src] are copied to [dst].
   *   EOF of [src] causes that [dst] is shut down for sending; all descriptors
   *   remain open. It is required that [dst] is a socket.
   * - [`Bidirectional(bi1,bi2)]: Data from [bi1] are copied to [bi2],
   *   and data from [bi2] are copied to [bi1]. EOF of one descriptor
   *   causes that the other descriptor is shut down for sending.
   *   When both descriptors are at EOF, both are closed.
   *   It is required that [bi1] and [bi2] are sockets.
   * - [`Tridirectional(bi,dst,src)]: Data from [bi] are copied to [dst],
   *   and data from [src] are copied to [bi] (i.e. a bidirectional
   *   descriptor is split up into two unidirectional descriptors). 
   *   EOF of [bi] causes that [dst] is closed. EOF of [src] causes
   *   that [bi] is shut down for sending. EOF in both directions 
   *   causes that all descriptors are closed. It is required that
   *   [bi] is a socket.
   *)



class copier : copy_task ->
               Unixqueue.event_system ->
		 [unit] engine
  (** This engine copies data between file descriptors as specified by
   * the [copy_task] argument.
   *
   * The task is done when all input descriptors are at EOF. See
   * the description of [copy_task] for details, especially whether
   * the descriptors are closed or not.
   *
   * On error or abort, the descriptors are only closed if they
   * had been closed on regular EOF.
   *
   * The semantics of the engine is undefined if one of the descriptors
   * is not stream-oriented.
   *
   * TODO: This class cannot yet cope with Win32 named piped.
   *)


type onshutdown_out_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_out_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]
  (** See class [output_async_mplex] for explanations *)

type onshutdown_in_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_in_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]
  (** See class [input_async_mplex] for explanations *)

class output_async_mplex : 
       ?onclose:[ `Write_eof | `Ignore ] ->
       ?onshutdown:onshutdown_out_spec ->
       ?buffer_size:int ->
       multiplex_controller ->
         async_out_channel_engine
  (** Creates an asynchronous output channel writing to the multiplex
    * controller (see also [output_async_descr] for the corresponding
    * class writing to a single descriptor).
    *
    * [onclose]: What to do when the [close_out] method is invoked.
    * Defaults to [`Ignore]. [`Write_eof] means to write the EOF marker.
    * Anyway, after doing the close action, the multiplex controller
    * is shutdown.
    *
    * [onshutdown]: What to do when all data (and optionally, the EOF marker)
    * have been written. It is also invoked in case of I/O errors.
    * The default is [`Ignore]. The value [`Initiate_shutdown] means that
    * it is started to shutdown the socket. The success of this action
    * is not waited upon, however. One can also pass [`Action f] in which
    * case the function [f] is called with this object, the
    * multiplex controller, and the proposed next state as arguments. 
    * By checking the proposed next state the function can see why the
    * shutdown function was called.
    *
    * [buffer_size]: The size of the internal buffer. By default unlimited.
    *
    * Note that the engine is done when the output channel is closed.
    * The socket is not shut down, and the underlying file descriptor
    * is not closed! You can define the [shutdown] callback to do something
    * in this case.
   *)


class input_async_mplex : 
       ?onshutdown:onshutdown_in_spec ->
       ?buffer_size:int ->
       multiplex_controller ->
         async_in_channel_engine
  (** Creates an asynchronous input channel reading from the multiplex
    * controller.
    *
    * [onshutdown]: See [output_async_mplex].
    *
    * [buffer_size]: The size of the internal buffer. By default unlimited.
    *
    * Note that the engine is done when the input channel is closed.
    * The socket is not shut down, and the underlying file descriptor
    * is not closed! You can define the [shutdown] callback to do something
    * in this case.
   *)
