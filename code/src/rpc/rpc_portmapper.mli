(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

(** Portmapper/RPCBIND interface *)

(** RPC programs are usually registered with a daemon that is known under
    two names: Portmapper or RPCBIND. The name Portmapper normally refers
    to version 2 of the registry, whereas RPCBIND refers to versions 3 and
    4. Version 2 is limited to IPv4 whereas the newer versions also support
    IPv6 and Unix Domain sockets.

    Recent Linux and BSD distributions deploy a version of RPCBIND that
    is a port of Sun's original RPCBIND software. Older distributions only
    support Portmapper.

    Most of the following calls invoke Portmapper procedures only. The
    calls with the suffix [_rpcbind] first invoked RPCBIND procedures,
    and if there is no support for RPCBIND, these calls fall back to
    Portmapper (and limited functionality).
 *)

open Netnumber
open Rpc
open Netxdr

type t
  (** represents a client for the Portmapper/RPCBIND daemon *)

val create : ?esys:Unixqueue.event_system -> Rpc_client.connector -> t
  (** Connects to the Portmapper/RPCBIND service listening on the given
      connector. *)

val create_inet : ?esys:Unixqueue.event_system -> string -> Rpc.protocol -> t
  (** Connects to a Portmapper/RPCBIND listening on an Internet port. The 
     argument
     is the hostname where the portmapper is running or its internet
     address. This function connects always to the port 111 on the given
     host; this is the standard for portmapper daemons.
   *)

val create_local : ?esys:Unixqueue.event_system -> unit -> t
  (** Connects to the local Portmapper/RPCBIND daemon. Such a client must
      only be used for setting and unsetting entries.
   *)

val shut_down : t -> unit
  (** Shuts down the connection*)

val null : t -> unit
  (** Calls the 'NULL' procedure of the portmapper. This procedure has no
   * effect. You can use 'null' to determine whether a procedure call is
   * possible or not.
   *)

val null'async : t -> ((unit -> unit) -> unit) -> unit

val set : t -> uint4 -> uint4 -> protocol -> int -> bool
  (** [set pm_client program_nr version_nr protocol port_nr]:
   * Extends the mapping managed by the Portmapper: The triple
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

      Sets an RPCBIND mapping, and if RPCBIND is not supported, the
      corresponding Portmapper mapping so far possible (when netid is
      "tcp" or "udp").

      The triple [(program_nr, version_nr, netid)] is mapped to
      [(uaddr,owner)]. Netids can be:
       - "tcp" (only IPv4)
       - "tcp6"
       - "udp" (only IPv4)
       - "udp6"
       - "local"
      
      For uaddr see RFC 5665 and {!Rpc.create_inet_uaddr}, 
      {!Rpc.parse_inet_uaddr}.
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
  (** [set_rpcbind pm_client program_nr version_nr netid uaddr owner].

      Unsets an RPCBIND mapping, and if RPCBIND is not supported, the
      corresponding Portmapper mapping so far possible (when netid is
      "tcp" or "udp").

      Note that it is unspecified what to do with [uaddr] and [owner].
      These arguments appear in the formal specification but are not
      described in the RFC. It is probably best to pass empty strings.

      You can call this function with [netid=""] to remove all entries
      for the pair [(program_nr,version_nr)].
   *)

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

      Gets the uaddr for the triple [(program_nr,version_nr,netid)] (or ""
      if not found). You can pass [netid=""] to get the uaddr for the
      netid of the transport on which RPCBIND is invoked (e.g. if you call
      RPCBIND on TCP/IPv6 you get the uaddr for netid="tcp6").

      Experimentation shows that the RPCBIND daemon on Linux does not
      correctly respond when netid is not the empty string. Because of this
      it is recommended to set netid always to the empty string.

      You can pass the uaddr of the caller as [caller_uaddr] to get a more
      precise response. Normally set [caller_uaddr=""], though.

      Falls back to Portmapper version 2 if RPCBIND isn't available. In
      this case you cannot retrieve IPv6 entries even if you contact
      Portmapper via IPv6.
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

