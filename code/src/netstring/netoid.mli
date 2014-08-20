(* $Id$ *)

(** X.500 Object Identifiers  *)

type t = int array

val equal : t -> t -> bool
  (** Whether two OIDs are equal *)

val compare : t -> t -> int
  (** Lexicographic ordering of OIDs *)

val of_string : string -> t
  (** Parses an OID in dot notation, e.g. 
      [of_string "2.3.4" = [| 2; 3; 4 |]]
   *)

val to_string : t -> string
  (** Returns the OID in dot notation, e.g.
      [to_string [| 2; 3; 4 |] = "2.3.4"]
   *)

val of_string_curly : string -> t
  (** Parses an OID in curly brace notation, e.g. 
      [of_string "{2 3 4}" = [| 2; 3; 4 |]]
   *)

val to_string_curly : t -> string
  (** Returns the OID in curly brace notation, e.g.
      [to_string [| 2; 3; 4 |] = "{2 3 4}"]
   *)

