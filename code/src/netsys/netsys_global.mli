(* $Id$ *)

(** Global variables

    This module provides a place to store global variables that work
    across subprocess boundaries. In order to push values to related processes
    it needs a [propagator]. The propagator is not included here. The
    Netplex library implements a propagator that is automatically activated.

    Variables are limited to string type.
 *)

type variable

val access : string -> variable
  (** [access name]: Create or look up a variable with this name *)

val get : variable -> string
  (** Get the value of the variable (after checking for an update) *)

val set : variable -> string -> unit
  (** Set the value of the variable *)

val get_v : variable -> string * int64
  (** Get the value and the version number of the variable *)

val set_v : variable -> string -> int64
  (** Set the value and get the new version number *)

val iter : (string -> string -> int64 -> unit) -> unit
  (** [iter f]: for every variable call [f name value version] *)

class type propagator =
  object
    method propagate : string -> string -> int64
      (** [propagate name value version]: push the new [value] of the variable
          called [name] to other processes. The version of the new value is
          returned.
       *)

    method update : string -> int64 -> (string * int64) option
      (** [update name version]: checks whether there is a new value of
          the variable [name] with a version higher than the passed
          [version]. If not, [None] is returned. If so, [Some(val,vers)]
          is returned where [val] is the value with version [vers].
       *)
  end

val get_propagator : unit -> propagator option
  (** Get the current propagator or return [None] *)

val set_propagator : propagator option -> unit
  (** Set the current propagator to [Some p], or remove the propagator with
      [None]
   *)

(**/**)

val internal_set : string -> string -> int64 -> unit
  (* Set the variable without propagation *)
