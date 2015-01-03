(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

module C = struct
  include Rpc_client

  let create_inet esys host port proto =
    let cf = Rpc_client.default_socket_config in
    let conn = Rpc_client.Inet(host,port) in
    Rpc_client.unbound_create (`Socket(proto,conn,cf)) esys

  let create_unix esys path =
    let proto = Rpc.Tcp in
    let cf = Rpc_client.default_socket_config in
    let conn = Rpc_client.Unix path in
    Rpc_client.unbound_create (`Socket(proto,conn,cf)) esys
end


module Impl = Rpc_portmapper_impl.PM(C)

include Impl


let create ?(esys = Unixqueue.create_unix_event_system()) conn =
  let proto = Rpc.Tcp in
  let cf = Rpc_client.default_socket_config in
  let client = C.unbound_create (`Socket(proto,conn,cf)) esys in
  create_for client


