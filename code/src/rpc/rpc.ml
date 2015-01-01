(* $Id$
 * ----------------------------------------------------------------------
 *
 *)

open Netnumber
open Printf

type protocol =
    Tcp          (* means: stream-oriented connection *)
  | Udp;;        (* means: datagram exchange *)

type mode =
    Socket     (* classical server socket *)
  | BiPipe     (* server is endpoint of a bidirectional pipe *)



(* these are error conditions sent to the client: *)

type server_error =
    Unavailable_program                      (* accepted call! *)
  | Unavailable_version of (uint4 * uint4)   (* accepted call  *)
  | Unavailable_procedure                    (* accepted call  *)
  | Garbage                                  (* accepted call  *)
  | System_err
  | Rpc_mismatch of (uint4 * uint4)          (* rejected call  *)
  | Auth_bad_cred                            (* rejected call  *)
  | Auth_rejected_cred                       (* rejected call  *)
  | Auth_bad_verf                            (* rejected call  *)
  | Auth_rejected_verf                       (* rejected call  *)
  | Auth_too_weak                            (* rejected call  *)
  | Auth_invalid_resp                        (* rejected call  *)
  | Auth_failed                              (* rejected call  *)
  | RPCSEC_GSS_credproblem                   (** rejected call  *)
  | RPCSEC_GSS_ctxproblem                    (** rejected call  *)
;;


let string_of_server_error =
  function
    | Unavailable_program -> 
	"Unavailable_program"
    | Unavailable_version(v1,v2) ->
	"Unavailable_version(" ^ 
	  Int64.to_string(Netnumber.int64_of_uint4 v1) ^ ", " ^ 
	  Int64.to_string(Netnumber.int64_of_uint4 v2) ^ ")"
    | Unavailable_procedure ->
	"Unavailable_procedure"
    | Garbage ->
	"Garbage"
    | System_err ->
	"System_err"
    | Rpc_mismatch(v1,v2) ->
	"Rpc_mismatch(" ^ 
	  Int64.to_string(Netnumber.int64_of_uint4 v1) ^ ", " ^ 
	  Int64.to_string(Netnumber.int64_of_uint4 v2) ^ ")"
    | Auth_bad_cred ->
	"Auth_bad_cred"
    | Auth_rejected_cred ->
	"Auth_rejected_cred"
    | Auth_bad_verf ->
	"Auth_bad_verf"
    | Auth_rejected_verf ->
	"Auth_rejected_verf"
    | Auth_too_weak ->
	"Auth_too_weak"
    | Auth_invalid_resp ->
	"Auth_invalid_resp"
    | Auth_failed ->
	"Auth_failed"
    | RPCSEC_GSS_credproblem ->
	"RPCSEC_GSS_credproblem"
    | RPCSEC_GSS_ctxproblem ->
	"RPCSEC_GSS_ctxproblem"


exception Rpc_server of server_error;;

exception Rpc_cannot_unpack of string;;


let () =
  Netexn.register_printer
    (Rpc_server Unavailable_program)
    (fun e ->
       match e with
	 | Rpc_server code ->
	     "Rpc.Rpc_server(" ^ string_of_server_error code ^ ")"
	 | _ ->
	     assert false
    )


let create_inet_uaddr ip port =
  sprintf "%s.%d.%d"
          (Unix.string_of_inet_addr ip)
          ((port land 0xff00) lsr 8)
          (port land 0xff)


let parse_inet_uaddr s =
  let l = String.length s in
  try
    let k2 = String.rindex s '.' in
    let s2 = String.sub s (k2+1) (l-k2-1) in
    if k2 = 0 then raise Not_found;
    let k1 = String.rindex_from s (k2-1) '.' in
    let s1 = String.sub s (k1+1) (k2-k1-1) in
    let s0 = String.sub s 0 k1 in
    let port = (int_of_string s1 lsl 8) lor (int_of_string s2) in
    let ip = Unix.inet_addr_of_string s0 in
    (ip, port)
  with
    | Not_found
    | Failure _ ->
        failwith "Rpc.parse_inet_uaddr"


let parse_inet_uaddr_dom s dom =
  let (ip, port) = parse_inet_uaddr s in
  if Netsys.domain_of_inet_addr ip <> dom then
    failwith "Rpc.sockaddr_of_uaddr";
  (ip,port)


let sockaddr_of_uaddr netid uaddr =
  match netid with
    | "tcp" -> 
        let (ip,port) = parse_inet_uaddr_dom uaddr Unix.PF_INET in
        Some (Unix.ADDR_INET(ip,port), Tcp)
    | "tcp6" ->
        let (ip,port) = parse_inet_uaddr uaddr in
        Some (Unix.ADDR_INET(Netsys.ipv6_inet_addr ip,port), Tcp)
    | "udp" ->
        let (ip,port) = parse_inet_uaddr_dom uaddr Unix.PF_INET in
        Some (Unix.ADDR_INET(ip,port), Udp)
    | "udp6" ->
        let (ip,port) = parse_inet_uaddr uaddr in
        Some (Unix.ADDR_INET(Netsys.ipv6_inet_addr ip,port), Udp)
    | "local" | "unix" ->
        Some (Unix.ADDR_UNIX uaddr, Tcp)
    | _ ->
        None

let netid_of_inet_addr ip proto =
  match Netsys.domain_of_inet_addr ip, proto with
    | Unix.PF_INET, Tcp -> "tcp"
    | Unix.PF_INET, Udp -> "udp"
    | Unix.PF_INET6, Tcp -> "tcp6"
    | Unix.PF_INET6, Udp -> "udp6"
    | Unix.PF_UNIX, _ -> "local"
