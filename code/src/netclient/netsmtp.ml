(* $Id$
 * ----------------------------------------------------------------------
 *
 * This is an implementation of the Simple Mail Transfer Protocol (SMTP) 
 * as specifed by RFC-2821.
 *)

open Netchannels
open Unix

exception Protocol_error
exception Transient_error of int * string
exception Permanent_error of int * string

let tcp_port = 25

(* Helpers *)

let trim s l r = String.sub s l (String.length s - r - l)

let join = String.concat "\n"

let none = function _ -> false
let void  = function _ -> ()

let ok2 i j x = x = i || x = j
let okl l x = List.mem x l

let read_status ic =
  let rec read acc =
    let l = ic # input_line () in
    if l.[3] = '-' then
      read ((trim l 4 1)::acc)
    else
      (int_of_char l.[0] - int_of_char '0') ,
      int_of_string (String.sub l 0 3) ,
      List.rev ((trim l 4 1)::acc)
  in read []

let handle_answer ic =
  let flag, code, msg = read_status ic in
  match flag with
    | 2 | 3 -> code, msg
    | 4 -> raise (Transient_error (code, join msg))
    | 5 -> raise (Permanent_error (code, join msg))
    | _ -> raise Protocol_error

let ignore_answer ic = ignore (handle_answer ic)

(* class *)

class client
  (ic0 : in_obj_channel)
  (oc0 : out_obj_channel) =
object (self)
  val mutable ic = ic0
  val mutable oc = oc0
  val mutable tls_endpoint = None

  initializer
    ignore_answer ic

  method private smtp_cmd cmd =
    oc # output_string cmd;
    oc # output_string "\r\n";
    oc # flush ()

  method helo ?host () =
    try
      oc # output_string "EHLO ";
      self # smtp_cmd (
        match host with
          | None -> (Uq_resolver.get_host_by_name (gethostname ())).h_name
          | Some s -> s
      );
      snd (handle_answer ic)
    with
      | Permanent_error _ ->
          oc # output_string "HELO ";
          self # smtp_cmd (
            match host with
              | None -> (Uq_resolver.get_host_by_name (gethostname ())).h_name
              | Some s -> s
          );
          snd (handle_answer ic)


  method mail email =
    self # smtp_cmd (Printf.sprintf "MAIL FROM: <%s>" email);
    ignore_answer ic
   
  method rcpt email =
    self # smtp_cmd (Printf.sprintf "RCPT TO: <%s>" email);
    try  ignore_answer ic
    with Permanent_error (551, msg) -> self # rcpt msg

  method data (chan:in_obj_channel) =
    self # smtp_cmd "DATA";
    ignore_answer ic;
    ( try
	while true do
          let l = chan # input_line () in
            if String.length l > 0 && l.[0] = '.' then oc # output_char '.';
            oc # output_string l;
            oc # output_string 
	      (if String.length l > 0 && 
		 l.[String.length l - 1] = '\r' then "\n" else "\r\n")
	done;
	assert false
      with End_of_file -> () );
    self # smtp_cmd ".";
    ignore_answer ic
   
  method rset () =
    self # smtp_cmd "RSET";
    ignore_answer ic

  method expn ml =
    oc # output_string "EXPN ";
    self # smtp_cmd ml;
    match handle_answer ic with
      | 250, msg -> Some msg
      | _ -> None

  method help () =
    self # smtp_cmd "HELP";
    snd (handle_answer ic)
      
  method noop () =
    self # smtp_cmd "NOOP";
    ignore_answer ic

  method quit () =
    self # smtp_cmd "QUIT";
    ignore_answer ic

  method close () = 
    oc # close_out();
    ic # close_in();
 
  method command cmd =
    self # smtp_cmd cmd;
    handle_answer ic

  method starttls ~peer_name (tls_config : Netsys_crypto_types.tls_config) =
    if tls_endpoint <> None then
      failwith "Netsmtp: TLS already negotiated";
    self # smtp_cmd "STARTTLS";
    ignore_answer ic;
    let tls_ch =
      new Netchannels_crypto.tls_layer
        ~role:`Client
        ~rd:(ic0 :> Netchannels.raw_in_channel)
        ~wr:(oc0 :> Netchannels.raw_out_channel)
        ~peer_name
        tls_config in
    tls_endpoint <- Some tls_ch#tls_endpoint;
    tls_ch # flush();   (* This enforces the TLS handshake *)
    ic <- Netchannels.lift_in (`Raw (tls_ch :> Netchannels.raw_in_channel));
    oc <- Netchannels.lift_out (`Raw (tls_ch :> Netchannels.raw_out_channel))


  method tls_endpoint = tls_endpoint

  method tls_session_props =
    match tls_endpoint with
      | None -> None
      | Some ep ->
           Some(Nettls_support.get_tls_session_props ep)

end


class connect ?proxy addr timeout =
  let st = Uq_client.connect ?proxy addr timeout in
  let bi = Uq_client.client_channel st timeout in
  let ic = Netchannels.lift_in (`Raw (bi :> Netchannels.raw_in_channel)) in
  let oc = Netchannels.lift_out (`Raw (bi :> Netchannels.raw_out_channel)) in
  client ic oc


(*
#use "topfind";;
#require "smtp,nettls-gnutls";;
let addr = `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "localhost", 25), Uq_engines.default_connect_options);;
let tls = Netsys_crypto.current_tls();;
let tc = Netsys_tls.create_x509_config ~trust:[`PEM_file "/etc/ssl/certs/ca-certificates.crt" ] ~peer_auth:`None tls;;
let c  = new Netsmtp.connect addr 300.0;;
c#helo();;
c#starttls tc;;

 *)
