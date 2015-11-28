(* 
 * $Id$
 *)


(** An {b engine} performs a certain task in an autonomous way. Engines
 * are attached to a {!Unixqueue.event_system}, and do their task by
 * generating events for resources of the operating system, and 
 * by handling such events. Engines are in one of four states: They
 * may be still {b working}, they may be {b done}, they may be
 * {b aborted}, or they may be in an {b error} state. The three latter
 * states a called {b final states}, because they indicate that the
 * engine has stopped operation.
 *
 * It is possible to ask an engine to notify another object when it
 * changes its state. For simplicity, notification is done by invoking
 * a callback function, and not by issuing notification events.
 *
 * Effectively, engines provide a calculus for cooperative microthreading.
 * This calculus includes combinators for sequential execution and
 * synchronization. Moreover, it is easy to connect it with callback-style
 * microthreading - one can arrange callbacks when an engine is done, and
 * one can catch callbacks and turn them into engines.
 *)

(** {1 Exceptions} *)

exception Closed_channel
  (** Raised when a method of a closed channel object is called (only channel
   * methods count).
   *
   * This exception should be regarded as equivalent to
   * [Netchannels.Closed_channel], but need not be the same exception.
   *)

exception Broken_communication
  (** Some engines indicate this error when they cannot continue because the
   * other endpoint of communication signals an error.
   *
   * This exception is not raised, but used as argument of the [`Error]
   * state.
   *)

exception Watchdog_timeout
  (** Used by the watchdog engine to indicate a timeout. 
   *
   * This exception is not raised, but used as argument of the [`Error]
   * state.
   *)

exception Timeout
  (** Used by [input_engine] and [output_engine] to indicate timeouts *)

exception Addressing_method_not_supported
  (** Raised by [client_endpoint_connector] and [server_endpoint_acceptor] to
   * indicate that the passed address is not supported by the class.
   *)


exception Cancelled
  (** The callback function of a [multiplex_controller] is invoked with this
    * exception if the operation is cancelled.
   *)



(** {1 Engine definition} *)

type 't engine_state =
  [ `Working of int
  | `Done of 't
  | `Error of exn
  | `Aborted
  ]
  (** The type of states with result values of type ['t]:
   * - [`Working n]: The engine is working. The number [n] counts the number
   *   of events that have been processed.
   * - [`Done arg]: The engine has completed its task without errors. 
   *   The argument [arg] is the result value of the engine
   * - [`Error exn]: The engine has aborted because of an error. The
   *   argument [exn] describes the error as an exception.
   * - [`Aborted]: The engine has aborted because the [abort] method
   *   was called 
   *)

  (* `Done, `Error, and `Aborted are final states, i.e. the state will
   * not change again. 
   * CHECK: This is a bit strict, and hard to implement. At least `Done
   * must be final, but it is ok when `Error and `Aborted change, however
   * they must not change back to `Working.
   *)
;;


type 't final_state =
  [ `Done of 't
  | `Error of exn
  | `Aborted
  ]
    (** Same as [engine_state] without [`Working]. These are only the final
	states.
     *)


val string_of_state : 'a engine_state -> string
  (** For debug purposes: Returns a string describing the state *)


(** This class type defines the interface an engine must support. The
 * class parameter ['t] is the type of the result values (when the
 * engine goes to state [`Done]).
 *)
class type [ 't ] engine = object
  (** Requirements for engines *)

  method state : 't engine_state
    (** Returns the state of the engine *)
  method abort : unit -> unit
    (** Forces that the engine aborts operation. If the state is already
     * [`Done ], [`Aborted], or [`Error], this method must do nothing (you 
     * cannot abort an already finished engine).
     *)
  method request_notification : (unit -> bool) -> unit
    (** Requests notification about state changes.
     *
     * After the notification has been requested, the passed function must
     * be called whenever [state] changes its value (or might change
     * its value; it is allowed to call the notification function more
     * frequently than necessary). The function returns [true] if there
     * is still interest in notification, and [false] if notification must
     * be disabled; the function must not be called any longer in this
     * case.
     *
     * There can be any number of parallel active notifications. It is
     * allowed that a notification callback function requests further
     * notifications.
     *
     * If the callback raises an exception, this exception is
     * propagated to the caller of {!Unixqueue.run}.
     *)
  method request_proxy_notification : ('t engine -> bool) -> unit
    (** Requests to call back the function when there is another engine
        that can be used as proxy for this object. Note that this is a pure
        optimization for [qseq_engine], and is normally not implemented
        for any other engine construction. It is ok to define this method
        as a no-op.
     *)
  method event_system : Unixqueue.event_system
    (** Returns the event system the engine is attached to *)
end
;;


class ['t] delegate_engine : 't #engine -> ['t] engine
   (** Turns an engine value into a class *)

(** {1 Engines and callbacks} *)


val when_state : ?is_done:('a -> unit) ->
                 ?is_error:(exn -> unit) ->
                 ?is_aborted:(unit -> unit) ->
                 ?is_progressing:(int -> unit) ->
                 'a #engine ->
		   unit
  (** Watches the state of the argument engine, and arranges that one of
   * the functions is called when the corresponding state change is done. 
   * Once a final state is reached, the engine is no longer watched.
   * Note that [when_state] only observes future state changes.
   *
   * If one of the functions raises an exception, this exception is
   * propagated to the caller of {!Unixqueue.run}.
   * 
   * @param is_done The state transitions to [`Done]. The argument of
   *   [is_done] is the argument of the [`Done] state.
   * @param is_error The state transitions to [`Error]. The argument of
   *   [is_error] is the argument of the [`Error] state.
   * @param is_aborted The state transitions to [`Aborted].
   * @param is_progressing This function is called when the [`Working]
   *   state changes. The int argument is the new [`Working] arg.
   *)

class ['a] signal_engine : Unixqueue.event_system ->
object
  inherit ['a] engine
  method signal : 'a final_state -> unit
end
  (** [let se = new signal_engine esys]: The engine [se] remains in
      [`Working 0] until the method [se # signal x] is called. At this point
      [e] transitions to [x]. Any further call of [signal] does not
      have any effect.

      Also, if [se] is aborted, [signal] does not have any effect.
      
      The function [signal] may be called from a different thread.
      The signalling event is forwarded to the thread running the
      event system.
   *)

val signal_engine : Unixqueue.event_system -> 
                      'a engine * ('a final_state -> unit)
  (** [let (se, signal) = signal_engine esys]: Same as function *)



(** {1 Combinators} *)

(** The following combinators serve as the control structures to connect
    primitive engines with each other.
 *)

class ['a,'b] map_engine : map_done:('a -> 'b engine_state) ->
                           ?map_error:(exn -> 'b engine_state) ->
                           ?map_aborted:(unit -> 'b engine_state) ->
                           ?propagate_working : bool ->
                           'a #engine ->
			     ['b] engine
  (** The [map_engine] observes the argument engine, and when the
   * state changes to [`Done], [`Error], or [`Aborted], the corresponding
   * mapping function is called, and the resulting state becomes the state
   * of the mapped engine. If the engine is already in one of the
   * mentioned states, the map functions are also called (unlike
   * [when_state]).
   *
   * After the state change to [`Done], [`Error], or [`Aborted] has been
   * observed, the map engine detaches from the argument engine,
   * and no further state changes are recognized.
   *
   * The state [`Working] cannot be mapped to another state. It is an
   * error to map final states to [`Working].
   * The result type of the [map_*] functions is [engine_state] 
   * and not [final_state] because of historic reasons.
   *
   * If the mapped engine is aborted, this request will be forwarded
   * to the argument engine.
   *
   * If one of the mapping functions raises an exception, this causes
   * a transiton to [`Error].
   *
   * @param map_done Maps the [`Done] state of the argument engine to
   *   another state. The argument of [map_done] is the argument of the
   *   [`Done] state. Note that [map_done] is non-optional only because
   *   of typing. If it were optional, the type checker would infer ['a = 'b].
   * @param map_error Maps the [`Error] state of the argument engine to
   *   another state. The argument of [map_error] is the argument of the
   *   [`Error] state. 
   * @param map_aborted Maps the [`Aborted] state of the argument engine to
   *   another state.
   * @param propagate_working Specifies whether changes of the [`Working]
   *   state in the argument engine are propagated. Defaults to [true].
   *   If set to [false], the mapped engine remains in [`Working 0] until
   *   it transitions to a final state.
   *
   *)


val map_engine : map_done:('a -> 'b engine_state) ->
                 ?map_error:(exn -> 'b engine_state) ->
                 ?map_aborted:(unit -> 'b engine_state) ->
                 ?propagate_working : bool ->
                 'a #engine ->
                    'b engine
  (** Same as function *)

class ['a,'b] fmap_engine : 'a #engine -> 
                           ('a final_state -> 'b final_state) -> 
                               ['b] engine
  (** Similar to [map_engine] but different calling conventions: The
      mapping function is called when the argument engine reaches a
      final state, and this state can be mapped to another final state.
   *)
  
val fmap_engine : 'a #engine -> 
                   ('a final_state -> 'b final_state) -> 
                     'b engine
  (** Same as function

      After opening {!Uq_engines.Operators}, this is also available
      as operator [>>], e.g.

      {[ 
         e >>
           (function
             | `Done r -> ...
             | `Error error -> ...
             | `Aborted -> ...
           )
       ]}
   *)

class ['a] meta_engine : 'a #engine -> ['a final_state] engine
  (** maps the final state [s] to [`Done s] *)

val meta_engine : 'a #engine -> 'a final_state engine
  (** Same as function *)

class ['t] epsilon_engine : 
             't engine_state -> Unixqueue.event_system -> ['t] engine
  (** This engine transitions from its initial state [`Working 0] in one
   * step ("epsilon time") to the passed constant state. During this time
   * event processing will continue, so concurrently running engines can
   * make progress. For performance reasons, however, external resources
   * like file descriptors are not watched for new events.
   *
   * In previous versions of this library the class was called [const_engine].
   * However, this is not a constant thing. In particular, it is possible
   * that this engine is aborted, so the passed state is not reached.
   * To avoid programming errors because of the misnomer, this class has been
   * renamed.
   *)


val epsilon_engine : 
     't engine_state -> Unixqueue.event_system -> 't engine
  (** Same as function *)


class ['a, 'b] seq_engine : 'a #engine -> ('a -> 'b #engine) -> ['b] engine
  (** This engine runs two engines in sequential order. It is called
   * 
   * {[ let eng_s = new seq_engine eng_a f ]}
   *
   * When [eng_a] goes to the state [`Done arg], the function [f] is called to
   * obtain
   *
   * {[ let eng_b = f arg ]}
   *
   * [eng_b] runs until it is also in state [`Done].
   *
   * If [eng_a] or [eng_b] go to states [`Aborted] or [`Error], the
   * sequential engine [eng_s] does so, too. If [eng_s] is aborted,
   * this request will be forwarded to the currently active engine,
   * [eng_a] or [eng_b].
   *
   * If calling [f] results in an exception, this is handled as if [eng_a]
   * signaled an exception.
   *)


val seq_engine : 'a #engine -> ('a -> 'b #engine) -> 'b engine
  (** Same as function.
   *
   * After opening {!Uq_engines.Operators}, this is also available
   * as operator [++], e.g.
   * {[ e1 ++ (fun r1 -> e2) ]}
   * (when [e1] and [e2] are engines, and [r1] is the result of [e1]).
   *)

class ['a, 'b] qseq_engine : 'a #engine -> ('a -> 'b #engine) -> ['b] engine
val qseq_engine : 'a #engine -> ('a -> 'b #engine) -> 'b engine
  (** Almost the same as [seq_engine], but this version does not
      propagate working state (i.e. no progress reporting).

      [qseq_engine] should be preferred for recursive chains of engines.
   *)

class ['a] stream_seq_engine : 'a -> ('a -> 'a #engine) Stream.t -> 
                               Unixqueue.event_system -> ['a] engine
  (** [let se = new stream_seq_engine x0 s esys]: The constructed engine [se]
    * fetches functions [f : 'a -> 'a #engine] from the stream [s], and
    * runs the engines obtained by calling these functions [e = f x] one
    * after the other. Each function call gets the result of the previous
    * engine as argument. The first call gets [x0] as argument.
    *
    * If one of the engines [e] transitions into an error or aborted state,
    * [se] will also do that. If [se] is aborted, this is passed down to
    * the currently running engine [e].
   *)


val stream_seq_engine : 'a -> ('a -> 'a #engine) Stream.t -> 
                         Unixqueue.event_system -> 'a engine
  (** Same as function *)


class ['a, 'b] sync_engine : 'a #engine -> 'b #engine -> ['a * 'b] engine
  (** This engine runs two engines in parallel, and waits until both
   * are [`Done] (synchronization). The product of the two [`Done] arguments 
   * is taken as the combined result.
   *
   * If one of the engines goes to the states [`Aborted] or [`Error],
   * the combined engine will follow this transition. The other,
   * non-aborted and non-errorneous engine is aborted in this case.
   * [`Error] has higher precedence than [`Aborted].
   *
   * If the combined engine is aborted, this request is forwarded
   * to both member engines.
   *)

val sync_engine : 'a #engine -> 'b #engine -> ('a * 'b) engine
  (** Same as function *)


class ['a,'b] msync_engine : 'a #engine list -> 
                             ('a -> 'b -> 'b) ->
                             'b ->
                             Unixqueue.event_system -> 
                             ['b] engine
  (** Multiple synchronization: 
      [let me = new msync_engine el f x0 esys] - Runs the engines in [el] in
      parallel, and waits until all are [`Done]. The result of [me] is
      then computed by folding the results of the part engines using
      [f], with an initial accumulator [x0].

      If one of the engines goes to the states [`Aborted] or [`Error],
      the combined engine will follow this transition. The other,
      non-aborted and non-errorneous engines are aborted in this case.
      [`Error] has higher precedence than [`Aborted].

      If calling [f] results in an exception, this is handled as if
      the part engine signals an error.

      If the combined engine is aborted, this request is forwarded
      to all member engines.
   *)

val msync_engine : 'a #engine list -> 
                   ('a -> 'b -> 'b) ->
                   'b ->
                   Unixqueue.event_system ->
                      'b engine
  (** Same as function *)			


class ['a ] delay_engine : float -> (unit -> 'a #engine) -> 
                           Unixqueue.event_system ->
                             ['a] engine
  (** [let de = delay_engine d f esys]: The engine [e = f()] is created
      after [d] seconds, and the result of [e] becomes the result of [de].
   *)


val delay_engine : float -> (unit -> 'a #engine) -> 
                   Unixqueue.event_system ->
                     'a engine
  (** Same as function *)

class ['a] timeout_engine : float -> exn -> 'a engine -> ['a] engine
  (** [timeout_engine d x e]: If the engine [e] finishes within [d]
      seconds, the result remains unchanged. If the engine takes longer,
      though, it is aborted, and the state transitions to
      [`Error x]
   *)

val timeout_engine : float -> exn -> 'a engine -> 'a engine
  (** Same as function *)

class watchdog : float -> 
                 'a #engine ->
                   [unit] engine
  (** A watchdog engine checks whether the argument engine makes
   * progress, and if there is no progress for the passed number of
   * seconds, the engine is aborted, and the watchdog state changes
   * to [`Error Watchdog_timeout].
   *
   * The current implementation is not very exact, and it may take
   * a little longer than the passed period of inactivity until the
   * watchdog recognizes inactivity.
   * 
   * If the argument engine terminates, the watchdog changes its state to
   * [`Done ()]
   *
   * Important note: The watchdog assumes that the [`Working] state 
   * of the target engine really counts events that indicate progress.
   * This does not work for:
   * - [poll_process_engine]: there is no way to check whether a subprocess
   *   makes progress
   * - [connector]: It is usually not possible to reflect the progress
   *   on packet level
   * - [listener]: It is usually not possible to reflect the progress
   *   on packet level
   *)

val watchdog : float -> 'a #engine -> unit engine
  (** Same as function *)


  (** A serializer queues up engines, and starts the next engine when the
      previous one finishes.
   *)
class type ['a] serializer_t =
object

  method serialized : (Unixqueue.event_system -> 'a engine) -> 'a engine
    (** [let se = serialized f]: Waits until all the previous engines reach
	a final state, and then runs [e = f esys].

        [se] enters a final state when [e] does.
     *)
end

class ['a] serializer : Unixqueue.event_system -> ['a] serializer_t
  (** Creates a serializer *)

val serializer : Unixqueue.event_system -> 'a serializer_t
  (** Same as function *)


(** A prioritizer allows to prioritize the execution of engines: At any
    time, only engines of a certain priority [p] can be executed. If an
    engine with a higher priority [ph] wants to start, it prevents further
    engines with priority level [p] from being started until the higher
    prioritized engines with level [ph] are done. On the same priority level,
    there is no limit for the number of executed engines.

    Here, higher priorities have lower numbers.
 *)
class type ['a] prioritizer_t =
object
  method prioritized : (Unixqueue.event_system -> 'a engine) -> int -> 'a engine
    (** [let pe = prioritized f p]: Queues up [f] on priority level [p].
	The engine  [e = f esys] can start when there is no waiting
	engine on a higher priority level (i.e. with a number less than
	[p]), and all running engines on lower priority levels are done.

	[pe] enters a final state when [e] does.
     *)
end

class ['a] prioritizer : Unixqueue.event_system -> ['a] prioritizer_t
  (** Creates a prioritizer *)

val prioritizer : Unixqueue.event_system -> 'a prioritizer_t
  (** Same as function *)



(** A cache contains a mutable value that is obtained by running an
    engine.
 *)
class type ['a] cache_t =
object
  method get_engine : unit -> 'a engine
    (** Requests the value. If it is not already in the cache, 
        the engine for getting the value is started, and it is waited
	until the value is available.
     *)
  method get_opt : unit -> 'a option
    (** Returns the cached value if available *)
  method put : 'a -> unit
    (** Puts a value immediately into the cache. It replaces an existing
	value. If it is currently tried to obtain a new value by running
	an engine, this engine is kept running, and [get_engine] will
	return its result. Only future calls of [get_engine] will return
	the value just put into the cache.
     *)
  method invalidate : unit -> unit
    (** Invalidates the cache - if a value exists in the cache, it is removed.
	If in the future the cache value is requested via [get_engine] 
        the engine will be started anew to get the value.

        Note that (as for [put]) any already running [get_engine] is not
	interrupted.
     *)
  method abort : unit -> unit
    (** Any engine running to get the cache value is aborted, and the contents
	of the cache are invalidated. Note that also the engines returned
	by [get_engine] are aborted.
     *)
end

class ['a] cache : (Unixqueue.event_system -> 'a engine) ->
                   Unixqueue.event_system ->
                     ['a] cache_t
  (** [new cache f esys]: A cache that runs [f esys] to obtain values *)

val cache : (Unixqueue.event_system -> 'a engine) ->
            Unixqueue.event_system ->
              'a cache_t
  (** Same as function *)


class ['t] engine_mixin : 't engine_state -> Unixqueue.event_system ->
object
  method state : 't engine_state
  method private set_state : 't engine_state -> unit
  method request_notification : (unit -> bool) -> unit
  method request_proxy_notification : ('t engine -> bool) -> unit
  method private notify : unit -> unit
  method event_system : Unixqueue.event_system
end
  (** A useful class fragment that implements [state] and 
    * [request_notification].
   *)							     

(** Handy operators: [++], [>>], and [eps_e] *)
module Operators : sig
  (** The most important operators. This module should be opened. *)

  val ( ++ ) : 'a #engine -> ('a -> 'b #engine) -> 'b engine
    (** Another name for [qseq_engine]. Use this operator to run engines in
	sequence:

	{[
	    e1 ++ (fun r1 -> e2) ++ (fun r2 -> e3) ++ ...
	]}

	Here [rK] is the result of engine [eK].

        Change in OCamlnet-3.6.4: [++] is now [qseq_engine], and no longer
        [seq_engine], and hence it does not support progress reporting anymore.
        Redefine [++] as [seq_engine] in your own code if you need the old
        behavior.
     *)

  val ( >> ) : 'a #engine -> 
                   ('a final_state -> 'b final_state) -> 
                     'b engine
    (** Another name for [fmap_engine]. Use this operator to map the
	final value of an engine:

	{[
	    e >> (function `Done x -> ... | `Error e -> ... | `Aborted -> ...)
	]}

     *)

  val eps_e : 't engine_state -> Unixqueue.event_system -> 't engine
    (** Same as [epsilon_engine] *)

end


(** {1 Basic I/O engines} *)

class poll_engine : ?extra_match:(exn -> bool) ->
                    (Unixqueue.operation * float) list -> 
		    Unixqueue.event_system ->
object
  inherit [Unixqueue.event] engine

  (** {1 Additional methods} *)

  method restart : unit -> unit
    (** Activate the engine again when it is already in a final state.
     * This method violates the engine protocol, and should be used
     * with care; it is not allowed to leave a final state.
     *
     * The notification lists are kept, but note that observers often
     * detach when final states are reached. This may cause problems.
     *)

  method group : Unixqueue.group
    (** Returns the group the engine is member of *)

end ;;
  (** This engine waits until one of the passed operations can be 
   * carried out, or until one of the operations times out. 
   * In these cases, the state of the engine  changes to [`Done ev], where 
   * [ev] is the corresponding event.
   *
   * The argument list enumerates the operations to watch for. For every
   * operation there may be a positive timeout value, or a negative number
   * to indicate that no timeout is specified.
   * 
   * After one event has been caught, the engine terminates operation.
   * The method [restart] can be called to activate it again (with the
   * same event condition, and the same notification list). See the
   * description of [restart] for possible problems.
   *
   * @param extra_match This function is called when an [Extra] event is
   *   found. If the function returns [true] for the argument exception
   *   of [Extra], the event is caught; otherwise it is rejected.
   *)


class ['a] input_engine : (Unix.file_descr -> 'a) ->
                          Unix.file_descr -> float -> Unixqueue.event_system ->
                          ['a] engine
  (** Generic input engine for reading from a file descriptor:
      [let e = new input_engine f fd tmo] - Waits until the file descriptor
      becomes readable, and calls then [let x = f fd] to read from the
      descriptor. The result [x] is the result of the engine.

      If the file descriptor does not become readable within [tmo] seconds,
      the resulting engine transitions to [`Error Timeout].

      Use this class to construct engines reading via [Unix.read] or
      comparable I/O functions:

      {[
      let read_engine fd tmo esys =
        new input_engine (fun fd ->
                            let buf = String.create 4096 in
                            let n = Unix.read fd buf 0 (String.length buf) in
                            String.sub buf 0 n
                         )
                         fd tmo esys
      ]}

      This engine returns the read data as string.

      See also {!Uq_io.input_e} for a more generic way of reading with
      engines.
   *)

class ['a] output_engine : (Unix.file_descr -> 'a) ->
                           Unix.file_descr -> float -> Unixqueue.event_system ->
                           ['a] engine
  (** Generic output engine for writing to a file descriptor:
      [let e = new output_engine f fd tmo] - Waits until the file descriptor
      becomes writable, and calls then [let x = f fd] to write to the
      descriptor. The result [x] is the result of the engine.

      If the file descriptor does not become writable within [tmo] seconds,
      the resulting engine transitions to [`Error Timeout].

      Use this class to construct engines writing via [Unix.single_write] or
      comparable I/O functions:

      {[
      let write_engine fd s tmo esys =
        new output_engine (fun fd ->
                             Unix.single_write fd s 0 (String.length s)
                          )
                          fd tmo esys
      ]}

      This engine returns the number of written bytes.

      See also {!Uq_io.output_e} for a more generic way of writing with
      engines.
   *)

class poll_process_engine : ?period:float ->
                            pid:int -> 
                            Unixqueue.event_system ->
			      [Unix.process_status] engine ;;
  (** {b This class is deprecated!} Use the classes in {!Shell_uq} instead.
   * 
   * This engine waits until the process with the ID [pid] terminates.
   * When this happens, the state of the engine changes to 
   * [`Done], and the argument of [`Done] is the process status.
   *
   * The engine does not catch stopped processes.
   *
   * The engine checks the process status every [period] seconds, and
   * whenever there is a [Signal] event on the queue. The idea of the
   * latter is that the user of this engine can increase the responsiveness
   * by defining a signal handler for SIGCHLD signals (the handler need
   * not to perform any special action, it must just be defined). When
   * the sub process terminates, a SIGCHLD signal is sent to the current
   * process. If the event loop happens to wait for new conditions (which
   * is usually very likely), a [Signal] event will be generated, and
   * the engine will check the process status very soon. Note that it is
   * not guaranteed that a terminating process triggers a [Signal] event,
   * although it is very likely.
   *
   * You can define an empty SIGCHLD handler with:
   * 
   * {[ Sys.set_signal Sys.sigchld (Sys.Signal_handle (fun _ -> ())) ]}
   *
   * @param period Every [period] seconds the process status is checked.
   *   Defaults to 0.1 seconds.
   *)

(** {2 More I/O}

    The module {!Uq_io} provides a bunch of functions to read and write
    data via various "devices". All these functions return engines, and
    are easy to use. Devices can be file descriptors, but also other
    data structures. In particular, there is also support for buffered I/O
    and for reading line-by-line from an input device.

 *)


(** {1 Recursion} *)

(** When programming with engines, it is normal to use recursion for any
    kind of loops. For example, to read the lines from a file:

    {[
      open Uq_engines.Operators  (* for ">>" and "++" *)

      let fd = 
        Unix.openfile filename [Unix.O_RDONLY] 0 in
      let d = 
        `Buffer_in(Uq_io.create_in_buffer(`Polldescr(`Read_write,fd,esys))) in

      let rec read_lines acc =
        Uq_io.input_line_e d >>
          (function                       (* catch exception End_of_file *)
            | `Done line -> `Done(Some line)
            | `Error End_of_file -> `Done None
            | `Error error -> `Error error
            | `Aborted -> `Aborted
          ) ++
          (function
            | Some line ->
                read_lines (line :: acc)
            | None ->
                eps_e (`Done (List.rev acc)) esys
          ) in

      let e = read_lines []
    ]}

    There is generally the question whether this style leads to stack
    overflows. This depends on the mechanisms that come into play:

    - The engine mechanism passing control from one engine to the next is
      not tail-recursive, and thus the stack can overflow when the
      recursion becomes too deep
    - The event queue mechanism, however, does not have this problem.
      Control falls automatically back to the event queue whenever I/O
      needs to be done.

    In this example, this means that only the engine mechanism is used
    as long as the data is read from the buffer. When the buffer needs
    to be refilled, however, control is passed back to the event queue
    (so the stack is cleaned), and the continuation of the execution
    is only managed via closures (which only allocate memory on the
    heap, not on the stack). Usually, this is a good compromise: The
    engine mechnism is a lot faster, but I/O is an indicator for using
    the better but slower technique.

    Also note another difference: The event queue mechanism allows that
    other asynchronous code attached to the same event queue may run
    (control maybe yielded to unrelated execution contexts). The
    pure engine mechanism does not allow that. This may be handy when
    exclusive access to variables is needed. (But be careful here -
    this is very sensitive to minimal changes of the implementation.)

    Certain engines enforce using the event queue mechanisms although they
    are unrelated to I/O. Especially {!Uq_engines.delay_engine} is
    useful here: A "delay" of 0 seconds is already sufficient to
    go back to the event queue. If recursions sometimes lead to
    stack overflows the solution is to include such a zero delay
    before doing the self call.
 *)

(** {1 More Engines} *)

(**
  Pointers to other modules related to engines:

  - {!Uq_client}
  - {!Uq_server}
  - {!Uq_multiplex}
  - {!Uq_transfer}
  - {!Uq_datagram}
  - {!Uq_io}
  - RPC clients: The function {!Rpc_proxy.ManagedClient.rpc_engine} allows
    to call an RPC via an engine. When the call is done, the engine transitions
    to [`Done r], and [r] is the result of the remote call.
  - Subprograms: The class {!Shell_uq.call_engine} allows to start an
    external program, and to monitor it via an engine.
 *)

(** {1 Moved} *)

(** OCamlnet-4.0 moves a number of definitions to the modules
     - {!Uq_transfer}
     - {!Uq_multiplex}

    For convenience, the types are still also exported here, but
    functions and classes are now defined in these modules.
    See also the module {!Uq_engines_compat}.
 *)

(** Moved to {!Uq_transfer.async_out_channel} *)
class type async_out_channel = object
  method output : Bytes.t -> int -> int -> int
  method close_out : unit -> unit
  method pos_out : int
  method flush : unit -> unit
  method can_output : bool
  method request_notification : (unit -> bool) -> unit
end


(** Moved to {!Uq_transfer.async_in_channel} *)
class type async_in_channel = object
  method input : Bytes.t -> int -> int -> int
  method close_in : unit -> unit
  method pos_in : int
  method can_input : bool
  method request_notification : (unit -> bool) -> unit
end


(** Moved to {!Uq_transfer.async_out_channel_engine} *)
class type async_out_channel_engine = object
  inherit [ unit ] engine
  inherit async_out_channel
end


(** Moved to {!Uq_transfer.copy_task} *)
type copy_task =
    [ `Unidirectional of (Unix.file_descr * Unix.file_descr)
    | `Uni_socket of (Unix.file_descr * Unix.file_descr)
    | `Bidirectional of (Unix.file_descr * Unix.file_descr)
    | `Tridirectional of (Unix.file_descr * Unix.file_descr * Unix.file_descr) 
    ]


(** Moved to {!Uq_transfer.async_in_channel_engine} *)
class type async_in_channel_engine = object
  inherit [ unit ] engine
  inherit async_in_channel
end


(** This definition has now been moved to {!Uq_multiplex.multiplex_controller}
 *)
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
  (** Moved to {!Uq_multiplex.Mem_not_supported} *)


  (** Moved to {!Uq_multiplex.datagram_multiplex_controller} *)
class type datagram_multiplex_controller =
object
  inherit multiplex_controller

  method received_from : Unix.sockaddr
  method send_to : Unix.sockaddr -> unit
end


(** Moved to {!Uq_transfer.onshutdown_out_spec} *)
type onshutdown_out_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_out_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]

(** Moved to {!Uq_transfer.onshutdown_in_spec} *)
type onshutdown_in_spec =
    [ `Ignore
    | `Initiate_shutdown
    | `Action of async_in_channel_engine -> multiplex_controller -> 
                   unit engine_state -> unit
    ]

(** Moved to {!Uq_client.inetspec} *)
type inetspec =
  [ `Sock_inet of (Unix.socket_type * Unix.inet_addr * int)
  | `Sock_inet_byname of (Unix.socket_type * string * int)
  ]

(** Moved to {!Uq_client.sockspec} *)
type sockspec =
  [ inetspec
  | `Sock_unix of (Unix.socket_type * string)
  ]

(** Moved to {!Uq_client.connect_address} *)
type connect_address =
    [ `Socket of sockspec * connect_options
    | `Command of string * (int -> Unixqueue.event_system -> unit)
    | `W32_pipe of Netsys_win32.pipe_mode * string
    ]

and connect_options =
    { conn_bind : sockspec option;
        (** Bind the connecting socket to this address (same family as the
	 * connected socket required). [None]: Use an anonymous port.
	 *)
    }

(** Moved to {!Uq_client.connect_status} *)
type connect_status =
    [ `Socket of Unix.file_descr * sockspec
    | `Command of Unix.file_descr * int
    | `W32_pipe of Unix.file_descr
    ]


(** Moved to {!Uq_client.client_endpoint_connector} *)
class type client_endpoint_connector = object
  method connect : connect_address -> 
                   Unixqueue.event_system ->
		     connect_status engine
end


(** Moved to {!Uq_server.listen_address} *)
type listen_address =
    [ `Socket of sockspec * listen_options
    | `W32_pipe of Netsys_win32.pipe_mode * string * listen_options
    ]

and listen_options =
    { lstn_backlog : int;
      lstn_reuseaddr : bool;
    }


(** Moved to {!Uq_server.server_endpoint_acceptor} *)
class type server_endpoint_acceptor = object
  method server_address : connect_address
  method multiple_connections : bool
  method accept : unit -> (Unix.file_descr * inetspec option) engine
  method shut_down : unit -> unit
end


(** Moved to {!Uq_server.server_endpoint_listener} *)
class type server_endpoint_listener = object
  method listen : listen_address ->
                  Unixqueue.event_system ->
		    server_endpoint_acceptor engine
end


(** Moved to {!Uq_datagram.datagram_type} *)
type datagram_type =
    [ `Unix_dgram
    | `Inet_udp
    | `Inet6_udp
    ]


(** Moved to {!Uq_datagram.datagram_type} *)
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
end;;


(** Moved to {!Uq_datagram.datagram_type} *)
class type datagram_socket_provider =
object
  method create_datagram_socket : datagram_type ->
                                  Unixqueue.event_system ->
                                    wrapped_datagram_socket engine
end




(** {1 Debugging} *)

module Debug : sig
  val enable : bool ref
    (** Enables {!Netlog}-style debugging *)

end
