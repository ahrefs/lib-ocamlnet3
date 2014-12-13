(* $Id$ *)

(** Authentication helpers for GSSAPI *)

open Netsys_gssapi

module type CONFIG = sig
    val raise_error : string -> 'a
end

module Manage(G:GSSAPI) : sig
  (** General management *)

  val delete_context : G.context option -> unit -> unit
    (** Deletes the context, ignoring any error *)

  val format_status : ?fn:string -> 
                      ?minor_status:int32 -> major_status ->
                      string
  
end

module Auth (G:GSSAPI)(C:CONFIG) : sig
  (** Status *)

  val check_status : ?fn:string -> 
                     ?minor_status:int32 -> major_status ->
                     unit
    (** If the [major_status] indicates an error, an error string is formed,
        optionally including the function name [fn] and the detailed information
        derived from [minor_status]. Then, the function [C.raise_error] is
        called with the string as argument.
     *)

  (** Client configuration *)

  val get_initiator_name : client_config -> G.name
  val get_initiator_cred : initiator_name:G.name -> 
                           client_config -> G.credential
  val acquire_initiator_cred : initiator_name:G.name -> 
                               client_config -> G.credential
  val get_target_name : ?default:(string * oid) ->
                        client_config -> G.name
  val get_client_flags : client_config ->
                         req_flag list
  val check_client_flags : client_config -> 
                           ret_flag list -> unit
  val init_sec_context :
         initiator_cred:G.credential ->
         context:G.context option ->
         target_name:G.name ->
         req_flags:req_flag list ->
         chan_bindings:channel_bindings option ->
         input_token:token option ->
         client_config -> 
           (G.context * token * ret_flag list * client_props option)
    (** Calls [G.init_sec_context], and returns
        [(out_context,out_token,flags,props_opt)]. If [props_opt] is returned
        the context setup is done.

        Checks already for errors, and client flags.
     *)

  (** Server configuration *)

  val get_acceptor_name : server_config -> G.name
  val get_acceptor_cred : acceptor_name:G.name ->
                          server_config -> G.credential
  val get_server_flags : server_config ->
                         req_flag list
  val check_server_flags : server_config -> 
                           ret_flag list -> unit

  val accept_sec_context :
        acceptor_cred:G.credential -> 
        context:G.context option ->
        chan_bindings:channel_bindings option ->
        input_token:token ->
        server_config ->
          (G.context * token * ret_flag list * server_props option)
    (** Calls [G.accept_sec_context], and returns
        [(out_context,out_token,flags,props_opt)]. If [props_opt] is returned
        the context setup is done.

        Checks already for errors, and server flags.
     *)

  (** Helpers *)

  val get_display_name : G.name -> string * oid
  val get_exported_name : G.name -> string


end
