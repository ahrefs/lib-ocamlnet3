(* $Id$ *)

include Uq_engines

class type server_socket_listener = server_endpoint_listener
class type server_socket_acceptor = server_endpoint_acceptor
class type client_socket_connector = client_endpoint_connector
          

(* exception Mem_not_supported = Uq_multiplex.Mem_not_supported *)
(* already included from Uq_engines *)

let create_multiplex_controller_for_connected_socket =
  Uq_multiplex.create_multiplex_controller_for_connected_socket

let create_multiplex_controller_for_datagram_socket =
  Uq_multiplex.create_multiplex_controller_for_datagram_socket

let default_listen_options =
  Uq_server.default_listen_options

class direct_acceptor =
  Uq_server.direct_acceptor

class direct_socket_acceptor fd esys =
  Uq_server.direct_acceptor fd esys

let listener =
  Uq_server.listener

let sockspec_of_sockaddr =
  Uq_client.sockspec_of_sockaddr

let sockspec_of_socksymbol =
  Uq_client.sockspec_of_socksymbol

let default_connect_options =
  Uq_client.default_connect_options

let client_endpoint =
  Uq_client.client_endpoint

let client_socket =
  Uq_client.client_endpoint

let connector =
  Uq_client.connect_e

class pseudo_async_out_channel =
  Uq_transfer.pseudo_async_out_channel

class pseudo_async_in_channel =
  Uq_transfer.pseudo_async_in_channel

class receiver =
  Uq_transfer.receiver

class sender =
  Uq_transfer.sender

class output_async_descr =
  Uq_transfer.output_async_descr

class input_async_descr =
  Uq_transfer.input_async_descr

class copier =
  Uq_transfer.copier

class output_async_mplex =
  Uq_transfer.output_async_mplex

class input_async_mplex =
  Uq_transfer.input_async_mplex

let datagram_provider =
  Uq_datagram.datagram_provider
