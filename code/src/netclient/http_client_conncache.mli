(* $Id$ *)

(** Connection cache *)

(** This module allows one to create special connection caches, e.g.
    by deriving from the official ones
 *)

type channel_binding_id = int
    (** Same as in {!Http_client.channel_binding_id} *)

type inactive_data =
    { conn_cb : channel_binding_id;
      tls_stashed_endpoint : exn option;
    }

type conn_state = [ `Inactive of inactive_data | `Active of < > ]
  (** A TCP connection may be either [`Inactive], i.e. it is not used
    * by any pipeline, or [`Active obj], i.e. it is in use by the pipeline
    * [obj] (this is the {!Http_client.pipeline} coerced to [< >]).
    *
    * Since Ocamlnet-4, [`Inactive] connections carry an [inactive_data]
    * record (was a [channel_binding_id] before).
   *)

type peer =
    [ `Direct of string * int
    | `Direct_name of string * int
    | `Http_proxy of string * int
    | `Http_proxy_connect of (string * int) * (string * int)
    | `Socks5 of (string * int) * (string * int)
    ]

class type connection_cache =
object
  method get_connection_state : Unix.file_descr -> conn_state
    (** Returns the state of the file descriptor, or raises [Not_found] *)
  method set_connection_state : Unix.file_descr -> peer -> conn_state -> unit
    (** Sets the state of the file descriptor. It is allowed that
      * inactive descriptors are simply closed and forgotten. It is
      * also possible that this method raises [Not_found], leaving it
      * to the caller to close the connection.
     *)
  method find_inactive_connection : peer -> channel_binding_id ->
                                     Unix.file_descr * inactive_data
    (** Returns an inactive connection to the passed peer, or raise
      * [Not_found]. Since Ocamlnet-3.3, the required channel binding ID
      * is also an argument of this method. Since Ocamlnet-4, the
      * [inactive_data] record is also returned.
     *)
  method find_my_connections : < > -> Unix.file_descr list
    (** Returns all active connections owned by the object *)
  method close_connection : Unix.file_descr -> unit
    (** Deletes the connection from the cache, and closes it *)
  method close_all : unit -> unit
    (** Closes all descriptors known to the cache *)
end


class restrictive_cache : unit -> connection_cache
  (** A restrictive cache closes connections as soon as there are no
    * pending requests.
   *)

class aggressive_cache : unit -> connection_cache
  (** This type of cache tries to keep connections as long open as
    * possible. The consequence is that users are responsible for
    * closing the descriptors (by calling [close_connection_cache]) when the
    * cache is no longer in use. It is also possible to derive a special
    * version of the cache from this class, e.g. for closing descriptors
    * when they are idle for some time.
   *)
