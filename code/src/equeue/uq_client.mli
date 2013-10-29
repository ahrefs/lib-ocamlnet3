(* $Id$ *)

(** Support for socket clients *)

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

val client_endpoint : Uq_engines.connect_status -> Unix.file_descr
  (** Returns the client endpoint contained in the [connect_status] *)


val client_channel : Uq_engines.connect_status -> float -> 
                       Netchannels.raw_io_channel
  (** [client_channel st timeout]: returns a bidirectional channel for [st]
      that times out after [timeout] seconds of waiting.
   *)
