(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

(** Portmapper version 2, and limited support for version 3 *)

(** Call the portmapper version 2. Note that version 2 is an older version
 * (version 3 and 4 are called 'rpcbind'), but it is normally available.
 * There are also some rpcbind functions, but its presence is not required.
 * For IPv6 support, you need to call the rpcbind functions.
 *
 * The task of the portmapper is to map program numbers to port numbers.
 * A RPC service that should be available in the whole network should:
 * - on startup: call the [set] procedure to establish a mapping of the
 *   own program number to the port that has been allocated previously
 * - on shutdown: call the [unset] procedure to remove the mapping
 *   (this is NEVER done automatically!)
 *
 * To call an RPC service which is only known by its program number one should
 * contact the portmapper using [getport] to find out the port where the
 * service is actually listening.
 *)

open Netnumber
open Rpc
open Netxdr

type t
  (** represents a client for the portmapper *)

val create : ?esys:Unixqueue.event_system -> Rpc_client.connector -> t
  (** Connects to the portmapper service listening on the given connector. *)

val create_inet : ?esys:Unixqueue.event_system -> string -> t
  (** Connects to a portmapper listening on an Internet port. The argument
   * is the hostname where the portmapper is running or its internet
   * address. This function connects always to the port 111 on the given
   * host; this is the standard for portmapper daemons.
   *)

val create_local : ?esys:Unixqueue.event_system -> unit -> t
  (** Connects to the local portmapper/rpcbind daemon. Such a client must
      only be used for setting and unsetting entries.
   *)

val shut_down : t -> unit
  (** Shuts down the connection to the portmapper. *)

val null : t -> unit
  (** Calls the 'NULL' procedure of the portmapper. This procedure has no
   * effect. You can use 'null' to determine whether a procedure call is
   * possible or not.
   *)

val null'async : t -> ((unit -> unit) -> unit) -> unit

val set : t -> uint4 -> uint4 -> protocol -> int -> bool
  (** [set pm_client program_nr version_nr protocol port_nr]:
   * Extends the mapping managed by the portmapper: The triple
   * [(program_nr, version_nr, protocol)] is mapped to the given
   * [port_nr].
   * It is not allowed to overwrite an existing mapping.
   * The procedure returns [true] if the mapping has been extended
   * and [false] otherwise.
   * Note that it usually only possible to [set] a mapping on the local
   * host.
   *)

val set'async : t -> uint4 -> uint4 -> protocol -> int -> 
                ((unit -> bool) -> unit) -> unit

val set_rpcbind : t -> uint4 -> uint4 -> string -> string -> string -> bool
  (** [set_rpcbind pm_client program_nr version_nr netid uaddr owner]:

      The triple [(program_nr, version_nr, netid)] is mapped to
      [(uaddr,owner)]. Netids can be:
       - tcp
       - tcp6
       - udp
       - udp6
       - local
      
      For uaddr see RFC 5665.

      If rpcbind version 3 isn't available, this call falls back to
      version 2. This works, however, only for the netids "tcp" and
      "udp".
   *)

val set_rpcbind'async : t -> uint4 -> uint4 -> string -> string -> string ->
                        ((unit -> bool) -> unit) -> unit

val unset : t -> uint4 -> uint4 -> protocol -> int -> bool
  (** [unset pm_client program_nr version_nr protocol port_nr]:
   * removes the mapping.
   * The procedure returns [true] if the mapping has been removed
   * and [false] otherwise.
   * Note that it usually only possible to [unset] a mapping on the local
   * host.
   *)

val unset'async : t -> uint4 -> uint4 -> protocol -> int -> 
                ((unit -> bool) -> unit) -> unit

val unset_rpcbind : t -> uint4 -> uint4 -> string -> string -> string -> bool
  (** [set_rpcbind pm_client program_nr version_nr netid uaddr owner] *)

val unset_rpcbind'async : t -> uint4 -> uint4 -> string -> string -> string ->
                          ((unit -> bool) -> unit) -> unit

val getport : t -> uint4 -> uint4 -> protocol -> int
  (** [getport pm_client program_nr version_nr protocol]:
   * finds out the port where the given service runs. Returns 0 if the
   * service is not registered.
   *)

val getport'async : t -> uint4 -> uint4 -> protocol -> 
                    ((unit -> int) -> unit) -> unit

val getaddr_rpcbind : t -> uint4 -> uint4 -> string -> string -> string option
  (** [getaddr_rpcbind pm_client program_nr version_nr netid caller_uaddr]:
      returns the universal address (None on error).

      Normally you can set [netid=""] and [caller_uaddr=""].

      Falls back to portmapper version 2 if rpcbind isn't available.
   *)

val getaddr_rpcbind'async : t -> uint4 -> uint4 -> string -> string ->
                            ((unit -> string option) -> unit) -> unit

val dump : t -> (uint4 * uint4 * protocol * int) list
  (** returns the list of known mappings. The quadrupels have the meaning
   * [(program_nr, version_nr, protocol, port)]
   *)

val dump'async : t -> 
                 ((unit -> (uint4 * uint4 * protocol * int) list) -> unit) ->
                 unit

val port_of_program : Rpc_program.t -> string -> protocol -> int
  (** [port_of_program program host protocol]:
   * queries the portmapper running on [host] for the [program] registered
   * for [protocol].
   * Returns the port number or fails if the number is not known.
   *)

val sockaddr_of_program_rpcbind : Rpc_program.t -> string -> string ->
                                    (Unix.sockaddr * protocol)
  (** [sockaddr_of_program program host netid]: gets the sockaddr
      for this program.

      Falls back to portmapper version 2 if rpcbind isn't available.
   *)

