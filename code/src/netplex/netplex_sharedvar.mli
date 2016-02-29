(* $Id$ *)

(** Netplex-wide variables *)

(** This plugin allows to have Netplex-global variables that can be read
    and written by all components. These variables are useful to communicate
    names and other small pieces of information across the whole Netplex.
    For instance, one component could allocate a shared memory object, and
    put its name into a variable to make it known to other components.

    This implementation works in both multi-processing and
    multi-threading netplex environments. It is, however, not very
    fast, because the variables live in the controller, and the
    access operations are realized by RPC's. It is good
    enough when these operations are only infrequently called, e.g. in
    the post-start and pre-finish processor callbacks.

    Furthermore, note that it is unwise to put large values into
    variables when using them in multi-processing contexts. The controller
    process is also the parent process of all [fork]ed children, and
    when a lot of memory is allocated in the controller, all
    this memory needs to be copied when the [fork] is done. As workaround,
    put such values into temporary files, and only pass the names of the
    files around via variables.

    Variables come in two flavors:
     - String variables
     - Encapsulated variables (see {!Netplex_encap})

    A string variable cannot be accessed as encapsulated variable, and
    vice versa.

    The latter kind is useful to safely store structured ocaml values in
    Netplex variables.

    More documentation can also be found here:
    {!Netplex_advanced.sharedvars}

    {b Thread safety:} Full. The functions can be called from any thread.
 *)

open Netplex_types

exception Sharedvar_type_mismatch of string
  (** The (dynamically typed) variable has the wrong type (string/exn) *)

exception Sharedvar_no_permission of string
  (** It is not allowed to set the value *)

exception Sharedvar_not_found of string
  (** The variable does not exist. Only used by [Make_var_type] *)

exception Sharedvar_null
  (** The initial value of a shared exception variable *)


val plugin : plugin
  (** To enable shared variables, call the controller's [add_plugin] method
      with this object as argument. This can e.g. be done in the
      [post_add_hook] of the processor.
   *)


(** {2 Classical API} *)

(** Most of the folloing functions can be invoked in both container
    and controller contexts, with the notable exception of
    [wait_for_value].
 *)

val create_var : ?own:bool -> ?ro:bool -> ?enc:bool -> ?timeout:float ->
                 ?ssn:string -> string -> bool
  (** Create the variable with the passed name with an empty string
      (or the exception [Sharedvar_null]) as
      initial value. If the creation is possible (i.e. the variable did
      not exist already), the function returns [true], otherwise 
      the already existing variable is left unchanged, and [false] is
      passed back. By default, the variable can be modified and deleted
      by any other container. Two options allow you to change that:

      - [own]: If true, the created variable is owned by the calling
        socket service. Only the caller can delete it, and when the 
        last component of the socket service terminates, the variable is
        automatically deleted. The deletion happens after the
        [post_finish_hook] is executed, so the variable is still accessible
        from this hook. Note that the controller has unlimited access anyway.
      - [ro]: if true, only the owner can set the value
      - [enc]: if true, the variable stores encapsulated values, otherwise
        strings
        (defaults to false)
      - [timeout]: if passed, the variable will be automatically deleted
        after this number of seconds. The timeout starts anew with every
        read or write of the variable.
      - [ssn]: If called from the controller and [own], this must be set to the
        socket service name of the owner

      Variable names are global to the whole netplex system. By convention,
      these names are formed like ["service_name.local_name"], i.e. they
      are prefixed by the socket service to which they refer.
   *)

val delete_var : string -> bool
  (** [delete_var name]: Deletes the variable [name]. Returns [true] if
      the deletion could be carried out, and [false] when the variable
      does not exist, or the container does not have permission to delete
      the variable.
   *)

val set_value : string -> string -> bool
  (** [set_value name value]: Sets the variable [name] to [value]. This
      is only possible when the variable exists, and is writable.
      Returns [true] if the function is successful, and [false] when
      the variable does not exist.

      Raises [Sharedvar_no_permission] if the variable cannot be modified.

      Raises [Sharedvar_type_mismatch] if the variable is not a string
      variable.
   *)

val set_enc_value : string -> encap -> bool
  (** [set_enc_value name value]: Sets the variable [name] to [value].
      Return value as for [set_value].

      Raises [Sharedvar_no_permission] if the variable cannot be modified.

      Raises [Sharedvar_type_mismatch] if the variable is not encapsulated
   *)

val get_value : string -> string option
  (** [get_value name]: Gets the value of the variable [name]. If the
      variable does not exist, [None] is returned.

      Raises [Sharedvar_type_mismatch] if the variable is not a string
      variable.
   *)

val get_enc_value : string -> encap option
  (** [get_enc_value name]: Gets the value of the variable [name]. If the
      variable does not exist, [None] is returned.

      Raises [Sharedvar_type_mismatch] if the variable is not encapsulated
   *)

val wait_for_value : string -> string option
  (** [wait_for_value name]: If the variable exists and [set_value] has
      already been called at least once, the current value is returned. 
      If the variable exists, but [set_value] has not yet been called at all,
      the function waits until [set_value] is called, and returns the value
      set then. If the variable does not exist, the function immediately
      returns [None].

      An ongoing wait is interrupted when the variable is deleted. In this
      case [None] is returned.

      {b This function can only be invoked from container context!}
   *)

val wait_for_enc_value : string -> encap option
  (** Same for encapsulated variables *)


val get_lazily : string -> (unit -> string) -> string option
  (** [get_lazily name f]: Uses the variable [name] to ensure that [f]
      is only invoked when [get_lazily] is called for the first time,
      and that the value stored in the variable is returned the
      next times. This works from whatever component [get_lazily]
      is called.

      If [f()] raises an exception, the exception is suppressed, and
      [None] is returned as result of [get_lazily]. Exceptions are not
      stored in the variable, so the next time [get_lazily] is called
      it is again tried to compute the value of [f()]. If you want to
      catch the exception this must done in the body of [f].

      No provisions are taken to delete the variable. If [delete_var]
      is called by user code (which is allowed at any time), and
      [get_lazily] is called again, the lazy value will again be computed.

      {b This function can only be invoked from container context!}
   *)

val get_enc_lazily : string -> (unit -> encap) -> encap option
  (** Same for encapsulated values *)

val dump : string -> Netlog.level -> unit
  (** Dumps the access counter of this variable to {!Netlog}. The
      string argument "*" dumps all variables.
   *)

(** {2 API with versioned access} *)

(** The API with versioned values can very quickly check whether newer
    values are available (the check consists just of a memory read). If a newer
    version is avaiable, the value still needs to be retrieved with an
    RPC call, though.

    The central function is [vv_update]. See also the limitations mentioned
    there.
 *)

type 'a versioned_value
  (** Cache for the current value *)

val vv_access : string -> string versioned_value
  (** Get the current value of this variable. This succeeds even when the
      variable does not exist.
   *)

val vv_access_enc : string -> encap versioned_value
  (** Same for encapsulated variables *)

val vv_get : 'a versioned_value -> 'a option
  (** Extract the current value, or [None] if the variable cannot be found. *)

val vv_version : _ versioned_value -> int64
  (** Get the current version number.  The version number is increased by
      every "set" operation. Raised [Not_found] if the variable cannot be
      found.
   *)

val vv_update : _ versioned_value -> bool
  (** Check whether there is a new version of the value, and update the
      cache. Return whether the update occurred.

      Note that there is a limitation on the number of variables that can
      use [vv_update]. For every [versioned_value] a slot in a shared memory
      segment is allocated. However, there is only a limited number of such
      slots (currently 1023). If more slots are needed, the performance will
      be degraded.
   *)

val vv_set : 'a versioned_value -> 'a -> bool
  (** Set the current value. Return whether successful *)


(** {2 Classical functor} *)

module Make_var_type(T:Netplex_cenv.TYPE) : 
          Netplex_cenv.VAR_TYPE with type t = T.t
  (** Creates a module with [get] and [set] functions to access variables
      of type [T.t]. Call it like

      {[
         module Foo_var = 
           Make_var_type(struct type t = foo end)
      ]}

      and use [Foo_var.get] and [Foo_var.set] to access the shared
      variables of type [foo]. These functions can also raise the exception
      [Sharedvar_not_found] (unlike the primitive accessors above).

      The variable must have been created with [enc:true], e.g.

      {[
          let ok = create_var ~enc:true "name"
      ]}
   *)

(** {2 Functor with versioned access} *)

module type VV_TYPE =
  sig
    type t
    type var
    val access : string -> var
    val get : var -> t
    val set : var -> t -> unit
    val version : var -> int64
    val update : var -> bool
  end

module Make_vv(T:Netplex_cenv.TYPE) : 
          VV_TYPE with type t = T.t


(** {2 Netsys_global} *)

(** This is a propagator for {!Netsys_global}. It is automatically activated
    when the Netplex controller is started.
 *)

val global_propagator : unit -> Netsys_global.propagator
(** Create a new propagator, and initialize {!Netplex_sharedvar}
    with the current variables from {!Netsys_global}. Note that a
    global variable with name [n] appears in Netplex as variable
    ["global." ^ n].

    The version numbers appearing in both modules are unrelated.

    This function must be called from controller context.
  *)

val propagate_back : Netplex_types.controller -> unit
  (** Copy the global variables from {!Netplex_sharedvar} (with prefix
      "global.") back to {!Netsys_global}
   *)

(** {2 Examples} *)

(** Example code:

    Here, one randomly chosen container computes [precious_value], and
    makes it available to all others, so the other container can simply
    grab the value. This is similar to what [get_lazily] does internally:

    {[
      let get_precious_value() =
        let container = Netplex_cenv.self_cont() in
        let var_name = "my_service.precious" in
        if Netplex_sharedvar.create_var var_name then (
          let precious_value = 
            try ...    (* some costly computation *)
            with exn ->
              ignore(Netplex_sharedvar.delete_var var_name);
              raise exn in
          let b = Netplex_sharedvar.set_value var_name precious_value in
          assert b;
          precious_value
        )
        else (
          match Netplex_sharedvar.wait_for_value var_name with
           | Some v -> v
           | None -> failwith "get_precious_value"
                       (* or do plan B, e.g. compute the value *)
        )
    ]}

    We don't do anything here for deleting the value when it is no longer
    needed. Finding a criterion for that is very application-specific. 
    If the variable can be thought as being another service endpoint
    of a socket service, it is a good idea to acquire the ownership
    (by passing [~own:true] to [create_var]), so the variable is automatically
    deleted when the socket service stops.

    Of course, the plugin must be enabled, e.g. by overriding the 
    [post_add_hook] processor hook:

   {[ 
    method post_add_hook sockserv ctrl =
      ctrl # add_plugin Netplex_sharedvar.plugin
   ]}

 *)

