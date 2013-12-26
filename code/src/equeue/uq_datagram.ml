(* $Id$ *)

open Uq_engines

type datagram_type =
  Uq_engines.datagram_type

class type wrapped_datagram_socket =
  Uq_engines.wrapped_datagram_socket

class type datagram_socket_provider =
  Uq_engines.datagram_socket_provider


let addr_of_name name =
  let entry = Uq_resolver.get_host_by_name name in
  entry.Unix.h_addr_list.(0)
;;


class direct_datagram_socket dgtype (sdom,stype,sproto) 
      : wrapped_datagram_socket =
  let sock = Unix.socket sdom stype sproto in
  let _ = 
    Unix.set_nonblock sock;
    Netsys.set_close_on_exec sock in
object(self)
  method descriptor = sock
  method sendto s p n flags spec = 
    let sockaddr =
      match spec with
	  `Sock_unix(stype', path) ->
	    if stype <> stype' then invalid_arg "Socket type mismatch";
	    Unix.ADDR_UNIX path
	| `Sock_inet(stype', addr, port) ->
	    if stype <> stype' then invalid_arg "Socket type mismatch";
	    Unix.ADDR_INET(addr,port)
	| `Sock_inet_byname(stype', name, port) ->
	    if stype <> stype' then invalid_arg "Socket type mismatch";
	    let addr = addr_of_name name in
	    Unix.ADDR_INET(addr,port)
    in
    Unix.sendto sock s p n flags sockaddr

  method recvfrom s p n flags =
    let (n, sockaddr) = Unix.recvfrom sock s p n flags in
    let sockspec = 
      match sockaddr with
	  Unix.ADDR_UNIX path ->
	    `Sock_unix(stype, path)
	| Unix.ADDR_INET(addr,port) ->
	    `Sock_inet(stype, addr, port)
    in
    (n,sockspec)

  method shut_down() =
    Unix.close sock

  method datagram_type = dgtype
  method socket_domain = sdom
  method socket_type = stype
  method socket_protocol = sproto
end ;;


let datagram_provider ?proxy dgtype ues = 
  match proxy with
      Some p ->
	( p :> datagram_socket_provider ) # create_datagram_socket dgtype ues
    | None   -> 
	let (sdom,stype,sproto) =
	  match dgtype with
	      `Unix_dgram -> (Unix.PF_UNIX, Unix.SOCK_DGRAM, 0)
	    | `Inet_udp   -> (Unix.PF_INET, Unix.SOCK_DGRAM, 0)
	    | `Inet6_udp  -> (Unix.PF_INET6, Unix.SOCK_DGRAM, 0)
	in
	let wsock =
	  new direct_datagram_socket dgtype (sdom,stype,sproto) in
	let eng = new epsilon_engine (`Done wsock) ues in

	when_state
	  ~is_aborted:(fun () -> wsock # shut_down())
	  ~is_error:(fun _ -> wsock # shut_down())
	  eng;

	eng
;;
