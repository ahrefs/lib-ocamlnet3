(* $Id$
 * ----------------------------------------------------------------------
 *
 * This is an implementation of the Post Office Protocol - Version 3 (POP3) 
 * as specifed by RFC-1939.
 *)

open Netchannels
open Printf

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netpop" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netpop" Debug.enable

let () =
  Netlog.Debug.register_module "Netpop" Debug.enable

type state =
  [ `Authorization
  | `Transaction
  | `Update
  ]

exception Protocol_error
exception Authentication_error
exception Err_status of string
exception Bad_state

let tcp_port = 110

(* Compute the MD5 digest of a string as as a lowercase 
     hexadecimal string *)

let hex_digits = [| '0'; '1'; '2'; '3'; '4'; '5'; '6'; '7'; '8'; '9';
		    'a'; 'b'; 'c'; 'd'; 'e'; 'f' |]

let md5_string s =
  Digest.to_hex (Digest.string s)

(* Sending Commands *)
let send_command oc line =
  dlogr (fun () -> sprintf "C: %s" line);
  oc # output_string line;
  oc # output_string "\r\n";
  oc # flush ();
;;  

(* Receiving Responses *)

let trim s l =
  if l >= String.length s then
    ""
  else
    let r =
      if s.[String.length s-1] = '\r' then 1 else 0 in
    String.sub s l (String.length s - r - l)

let word s p0 =
  let len = String.length s in
  let rec skip p =
    if p >= len then raise Not_found
    else
      if s.[p] = ' ' then skip (p + 1)
      else collect p p
  and collect p0 p1 =
    if p1 >= len || s.[p1] = ' ' || s.[p1] = '\r' then
      String.sub s p0 (p1 - p0), p1
    else
      collect p0 (p1 + 1)
  in
  skip p0

let map_fst f (x,y) = (f x, y)

let int s p = map_fst int_of_string (word s p)

let status_response (ic : in_obj_channel) f =
  let line = ic # input_line () in
  dlogr (fun () -> sprintf "S: %s" (trim line 0));
  match word line 0 with
    | "+OK", p  -> f line p
    | "-ERR", p -> raise (Err_status (trim line p))
    | _         -> raise Protocol_error
;;

let ignore_status ic = status_response ic (fun _ _ -> ())

let sasl_response (ic : in_obj_channel) =
  let line = ic # input_line () in
  dlogr (fun () -> sprintf "S: %s" (trim line 0));
  match word line 0 with
    | "+OK", _ -> `Ok
    | "-ERR", _ -> raise Authentication_error
    | "+", p ->
        let s = trim line (p+1) in
        `Challenge (Netencoding.Base64.decode s)
    | _ -> raise Protocol_error


let multiline_response ic f init = 
  let rec loop acc = 
    let line = ic # input_line () in
(*    Printf.printf "S: %s\n" (trim line 0); flush stdout; *)
    let len = String.length line in
    if len = 0 then raise Protocol_error
    else
      if line.[0] = '.' then begin
	if len = 2 then acc
	else loop (f line 1 acc)
      end else
	loop (f line 0 acc)
  in loop init
;;    

let body_response ic =
  (* make a more efficient implementation *)
  let lines = multiline_response ic (fun s p acc ->
    (trim s p) :: acc
  ) [] in
  new input_string (String.concat "\n" (List.rev lines))
;;

let space_re = Netstring_str.regexp " "

let is_final_sasl_states =
  function 
    | `OK
    | `Auth_error _ -> true
    | _ -> false

class client
  (ic0 : in_obj_channel)
  (oc0 : out_obj_channel) =
  let greeting = status_response ic0 (fun s p -> trim s p) in
object (self)
  val mutable ic = ic0
  val mutable oc = oc0
  val mutable tls_endpoint = None
  val mutable gssapi_props = None
  val mutable state : state = `Authorization
  val mutable capabilities = []

  (* Current State *)
  
  method state = state
  method private check_state state' =
    if state <> state' then raise Bad_state
  method private transition state' =
    state <- state'

  method capabilities = capabilities

  (* General Commands *)

  method quit () =
    send_command oc "QUIT";
    ignore_status ic;

  method close () =
    oc # close_out();
    ic # close_in();

  method capa() =
    send_command oc "CAPA";
    try
      ignore_status ic;  (* or raise Err_status *)
      let lines =
        List.rev
          (multiline_response
             ic
             (fun line p acc -> 
                trim line p :: acc)
             []
          ) in
      let capas =
        List.map
          (fun line -> 
             let l = Netstring_str.split space_re line in
             (List.hd l, List.tl l)
          )
          lines in
      capabilities <- capas;
      capas
    with
      | Err_status _ -> []

  (* Authorization Commands *)

  method user ~user =
    self#check_state `Authorization;
    send_command oc (sprintf "USER %s" user);
    ignore_status ic;

  method pass ~pass =
    self#check_state `Authorization;
    send_command oc (sprintf "PASS %s" pass);
    ( try
        ignore_status ic;
      with Err_status _ -> raise Authentication_error
    );
    self#transition `Transaction;

  method apop ~user ~pass =
    self#check_state `Authorization;
    let digest = try
      let p0 = String.index_from greeting 0 '<' in
      let p1 = String.index_from greeting (p0+1) '>' in
      let timestamp = String.sub greeting p0 (p1-p0+1) in
      md5_string (timestamp ^ pass)
    with Not_found -> raise Protocol_error
    in
    send_command oc (sprintf "APOP %s %s" user digest);
    ( try 
        ignore_status ic
      with Err_status _ -> raise Authentication_error
    );
    self#transition `Transaction;

  method auth mech user authz creds params =
    self#check_state `Authorization;
    let sess =
      ref
        (Netsys_sasl.Client.create_session
           ~mech ~user ~authz ~creds ~params ()) in
    let first = ref true in
    let state = ref  (Netsys_sasl.Client.state !sess) in
    while not (is_final_sasl_states !state) do
      let msg =
        match Netsys_sasl.Client.state !sess with
          | `Emit | `Stale -> 
               let sess2, msg = Netsys_sasl.Client.emit_response !sess in
               sess := sess2;
               Some msg
          | `Wait | `OK -> None
          | _ -> assert false in
      let command =
        if !first then 
          "AUTH " ^
            Netsys_sasl.Info.mechanism_name mech ^
              ( match msg with
                  | Some "" -> " ="
                  | Some s -> " " ^ Netencoding.Base64.encode s
                  | None -> ""
              )
        else
          match msg with
            | Some s -> Netencoding.Base64.encode s
            | None -> "" in
      send_command oc command;
      first := false;
      match sasl_response ic with
        | `Challenge data ->
            ( match Netsys_sasl.Client.state !sess with
                | `OK | `Auth_error _ -> ()
                | `Emit | `Stale -> assert false
                | `Wait ->
                    sess := Netsys_sasl.Client.process_challenge !sess data
            );
            state := Netsys_sasl.Client.state !sess;
            if !state = `OK then state := `Wait  (* we cannot stop now *)
        | `Ok ->
            state := Netsys_sasl.Client.state !sess;
            if !state <> `OK then state := `Auth_error "unspecified"
        | _ ->
            raise Protocol_error
    done;
    ( match !state with
        | `Auth_error msg -> 
            dlog ("Auth error: " ^ msg);
            raise Authentication_error
        | _ -> ()
    );
    assert(!state = `OK);
    gssapi_props <- (try Some(Netsys_sasl.Client.gssapi_props !sess)
                     with Not_found -> None);
    self#transition `Transaction;

  (* Transaction Commands *)

  method list ?msgno () =
    self#check_state `Transaction;
    let parse_line s p set =
      let mesg_num, p  = int s p in
      let mesg_size, p = int s p in
      let ext          = trim s p in
      Hashtbl.add set mesg_num (mesg_size, ext);
      set
    in
    try
      match msgno with
      | None ->
	  send_command oc "LIST";
	  ignore_status ic;
	  multiline_response ic parse_line (Hashtbl.create 1)
	    
      | Some n ->
	  send_command oc (sprintf "LIST %d" n);
	  status_response ic parse_line (Hashtbl.create 31)
    with _ -> raise Protocol_error

  method retr ~msgno =
    self#check_state `Transaction;
    send_command oc (sprintf "RETR %d" msgno);
    ignore_status ic;
    body_response ic;

  method dele ~msgno =
    self#check_state `Transaction;
    send_command oc (sprintf "DELE %d" msgno);
    ignore_status ic;

  method noop () =
    self#check_state `Transaction;
    send_command oc "NOOP";
    ignore_status ic;

  method rset () =
    self#check_state `Transaction;
    send_command oc "RSET";
    ignore_status ic;

  method top ?(lines = 0) ~msgno () =
    self#check_state `Transaction;
    send_command oc (sprintf "TOP %d %d" msgno lines);
    ignore_status ic;
    body_response ic;

  method uidl ?msgno () =
    self#check_state `Transaction;
    let parse_line s p set =
      let mesg_num, p  = int s p in
      let unique_id    = trim s p in
      Hashtbl.add set mesg_num unique_id;
      set
    in
    try
      match msgno with
      | None ->
	  send_command oc "UIDL";
	  ignore_status ic;
	  multiline_response ic parse_line (Hashtbl.create 31)
      | Some n ->
	  send_command oc (sprintf "UIDL %d" n);
	  status_response ic parse_line (Hashtbl.create 1)
    with _ -> raise Protocol_error

  method stat () =
    self#check_state `Transaction;
    send_command oc "STAT";
    try 
      status_response ic (fun s p ->
	let count, p = int s p in
	let size, p  = int s p in
	let ext      = trim s p in
	(count, size, ext)
      )
    with _ -> raise Protocol_error;


  method stls ~peer_name (tls_config : Netsys_crypto_types.tls_config) =
    if tls_endpoint <> None then
      failwith "Netpop: TLS already negotiated";
    send_command oc "STLS";
    ignore_status ic;
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


  method gssapi_props = gssapi_props
end

class connect ?proxy addr timeout =
  let st = Uq_client.connect ?proxy addr timeout in
  let bi = Uq_client.client_channel st timeout in
  let ic = Netchannels.lift_in (`Raw (bi :> Netchannels.raw_in_channel)) in
  let oc = Netchannels.lift_out (`Raw (bi :> Netchannels.raw_out_channel)) in
  client ic oc


let authenticate ?tls_config ?(tls_required=false) ?tls_peer
                 ?(sasl_mechs=[]) ?(sasl_params=[]) ?(user="") ?(authz="")
                 ?(creds=[])
                 (client : client) =
  ignore(client # capa());
  if List.mem_assoc "STLS" client#capabilities && 
     client#tls_endpoint=None &&
     tls_config <> None
  then (
    match tls_config with
      | None -> assert false
      | Some config -> 
          client # stls ~peer_name:tls_peer config;
          ignore(client # capa())
  );
  if tls_required && client#tls_endpoint=None then
    raise
      (Netsys_types.TLS_error "TLS required by SMTP client but not avalable");
  let srv_mechs = 
    try
      List.assoc
        "SASL"
        client#capabilities
    with Not_found -> [] in
  if sasl_mechs <> [] && srv_mechs <> [] then (
    let sel_mech =
      try
        List.find
          (fun mech ->
             let name = Netsys_sasl.Info.mechanism_name mech in
             List.mem name srv_mechs
          )
          sasl_mechs
      with
        | Not_found ->
            dlog "None of the server's AUTH mechanisms is supported by us";
            raise Authentication_error in
    let peer =
      match tls_peer with Some s -> s | None -> "" in
    let auto_params =
      [ "digest-uri", "pop/" ^ peer;     (* for DIGEST-MD5 *)
        "gssapi-acceptor", "pop"         (* for Kerberos *)
      ] in
    let x_sasl_params =
      List.fold_left
        (fun acc (n,v) ->
           if List.exists (fun (p,_,_) -> p = n) acc then
             acc
           else
             (n,v,false) :: acc
        )
        sasl_params
        auto_params in
    client # auth sel_mech user authz creds x_sasl_params;
  )


(*
#use "topfind";;
#require "netclient,nettls-gnutls";;
Netpop.Debug.enable := true;;
let addr = `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "localhost", 110), Uq_client.default_connect_options);;
let tls = Netsys_crypto.current_tls();;
let tc = Netsys_tls.create_x509_config ~system_trust:true ~peer_auth:`Required tls;;
let c  = new Netpop.connect addr 300.0;;
c#stls ~peer_name:(Some "gps.dynxs.de") tc;;
c#stat();;

Netpop.authenticate ~sasl_mechs:[ (module Netmech_digestmd5_sasl.DIGEST_MD5) ] ~user:"gerd" ~creds:["password", "secret", []] c;;

module K = Netmech_krb5_sasl.Krb5_gs1(Netgss.System);;
module K = Netmech_krb5_sasl.Krb5_gs2(Netgss.System);;

Netpop.authenticate ~sasl_mechs:[ (module K) ] c;;
Netpop.authenticate ~sasl_mechs:[ (module K) ] ~sasl_params:["mutual", "true", false] c;;


 *)
