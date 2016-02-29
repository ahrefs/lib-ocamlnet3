(* $Id$ *)

module type USE_CLIENT = sig
  type t
  val use : t -> Rpc_program.t -> unit
  val unbound_sync_call : 
        t -> Rpc_program.t -> string -> Netxdr.xdr_value -> Netxdr.xdr_value
  val unbound_async_call :
        t -> Rpc_program.t -> string -> Netxdr.xdr_value -> 
        ((unit -> Netxdr.xdr_value) -> unit) -> unit
  val xdr_ctx : t -> Netxdr.ctx
end
