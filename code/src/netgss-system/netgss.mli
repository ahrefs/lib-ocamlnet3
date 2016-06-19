(* $Id$ *)

(** This is the system-wide version of GSSAPI *)

(**
{b OPAM users}: Note that the OPAM package for OCamlnet does not
build with GSSAPI support by default. The trigger for this is the presence
of the [conf-gssapi] OPAM package, i.e. do [opam install conf-gssapi]
to include the [netgss-system] library in a rebuild.
 *)

module System : Netsys_gssapi.GSSAPI
  (** This is the system-wide version of GSSAPI *)
