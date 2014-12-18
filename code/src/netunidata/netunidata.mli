(* $Id$ *)

(** Configure how to load Unicode tables *)

(** The {!Netconversion} module implements the conversion between
    various character sets. By default, this module knows only a few
    built-in characters sets (in particular ISO-8859-1 and US-ASCII).
    Conversions to other character sets can be enabled by linking in
    the [netunidata] library.

    There are two options to load the required tables. First, the table
    can be linked with the executable (static table). Second, the table
    can be loaded at runtime when needed (dynamic table).

    For getting static tables, just specify one or several of the following
    findlib packages:

     - netunidata.iso: Links in the whole ISO-8859 series
     - netunidata.jp: Links in Japanese character sets (JIS-X-0201 and
       EUC-JP)
     - netunidata.kr: Links in Korean character sets (EUC-KR)
     - netunidata.other: Links in other characters sets (e.g. the whole
       Windows series)
     - netunidata.all: Links in all

    If static tables are linked in, this does not automatically disable
    that remaining tables are dynamically loaded. You need to explicitly
    disable this: {!Netunidata.disable}.

    If you want to load all tables dynamically, just specify this package:

     - netunidata: Only links in the dynamic loaders for the tables
 *)

val load : string -> unit
  (** [load key]: Loads the table for this key, if not already loaded or
      statically linked in. The key is the internal name of the mapping
      table (e.g. "cmapf.koi8r")
   *)

val load_charset : Netconversion.charset -> unit
  (** [load_charset enc]: Loads the forward and backward mapping tables for
      this charset.
   *)

val enable : unit -> unit
  (** Enables the dynamic loader. This is the default. *)

val disable : unit -> unit
  (** Disables the dynamic loader *)

val net_db_dir : unit -> string
  (** Returns the directory where the dynamic tables can be found *)

val set_net_db_dir : string -> unit
  (** Change the directory where the dynamic tables can be found *)

(**/**)

val load_file : string -> string
  (* load a file from the netdb directory. Fails if disabled *)
