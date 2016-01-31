(* $Id$
 * ----------------------------------------------------------------------
 *
 * This is an implementation of the Simple Mail Transfer Protocol (SMTP) 
 * as specifed by RFC-2821.
 *)

open Netchannels
open Unix
open Printf

exception Protocol_error
exception Authentication_error
exception Transient_error of int * string
exception Permanent_error of int * string

let tcp_port = 25

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netsmtp" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netsmtp" Debug.enable

let () =
  Netlog.Debug.register_module "Netsmtp" Debug.enable

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
  in
  let (flag,code,msgs) = read [] in
  List.iter
    (fun msg ->
       dlogr (fun () -> sprintf "S: %d %s" code msg)
    )
    msgs;
    (flag,code,msgs)

let handle_answer ic =
  let flag, code, msg = read_status ic in
  match flag with
    | 2 | 3 -> code, msg
    | 4 -> raise (Transient_error (code, join msg))
    | 5 -> raise (Permanent_error (code, join msg))
    | _ -> raise Protocol_error

let ignore_answer ic = ignore (handle_answer ic)

let is_final_sasl_states = 
  function
  | `OK
  | `Auth_error _ -> true
  | _ -> false

(* class *)

class client
  (ic0 : in_obj_channel)
  (oc0 : out_obj_channel) =
object (self)
  val mutable ic = ic0
  val mutable oc = oc0
  val mutable tls_endpoint = None
  val mutable gssapi_props = None
  val mutable ehlo = []
  val mutable authenticated = false

  initializer
    ignore_answer ic

  method private smtp_cmd cmd =
    dlogr (fun () -> sprintf "C: %s" cmd);
    oc # output_string cmd;
    oc # output_string "\r\n";
    oc # flush ()

  method helo ?host () =
    try
      self # smtp_cmd (
       "EHLO " ^ 
        match host with
          | None -> (Uq_resolver.get_host_by_name (gethostname ())).h_name
          | Some s -> s
      );
      ehlo <- snd (handle_answer ic);
      ehlo
    with
      | Permanent_error _ ->
          self # smtp_cmd (
            "HELO " ^ 
            match host with
              | None -> (Uq_resolver.get_host_by_name (gethostname ())).h_name
              | Some s -> s
          );
          ehlo <- snd (handle_answer ic);
          ehlo

  method helo_response = ehlo

  method auth mech user authz creds params =
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
               let sess2, msg =
                 Netsys_sasl.Client.emit_response !sess in
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
      self # smtp_cmd command;
      first := false;
      match handle_answer ic with
        | 334, challenge ->
            let s =
              try 
                match challenge with
                  | [] -> ""
                  | [s1] -> Netencoding.Base64.decode s1
                  | _ -> raise Protocol_error
              with Invalid_argument _ -> raise Protocol_error in
            ( match Netsys_sasl.Client.state !sess with
                | `OK | `Auth_error _ -> ()
                | `Emit | `Stale -> assert false
                | `Wait ->
                    sess := Netsys_sasl.Client.process_challenge !sess s
            );
            state := Netsys_sasl.Client.state !sess;
            if !state = `OK then state := `Wait  (* we cannot stop now *)
        | 235, _ ->
            state := Netsys_sasl.Client.state !sess;
            if !state <> `OK then state := `Auth_error "unexpected 235"
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
    authenticated <- true

  method authenticated = authenticated

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

  method gssapi_props = gssapi_props

end


class connect ?proxy addr timeout =
  let st = Uq_client.connect ?proxy addr timeout in
  let bi = Uq_client.client_channel st timeout in
  let ic = Netchannels.lift_in (`Raw (bi :> Netchannels.raw_in_channel)) in
  let oc = Netchannels.lift_out (`Raw (bi :> Netchannels.raw_out_channel)) in
  client ic oc


let space_re = Netstring_str.regexp " "

let auth_mechanisms l =
  let l_split =
    List.map
      (fun s ->
         Netstring_str.split space_re s
      )
      l in
  try
    let tokens =
      try List.find (fun toks -> toks <> [] && List.hd toks = "AUTH") l_split
      with Not_found -> ["AUTH"] in
    List.tl tokens
  with Not_found -> []
  


let authenticate ?host ?tls_config ?(tls_required=false) ?tls_peer
                 ?(sasl_mechs=[]) ?(sasl_params=[]) ?(user="") ?(authz="")
                 ?(creds=[])
                 (client : client) =
  ignore(client # helo ?host());
  if List.mem "STARTTLS" client#helo_response && 
     client#tls_endpoint=None &&
     tls_config <> None
  then (
    match tls_config with
      | None -> assert false
      | Some config -> 
          client # starttls ~peer_name:tls_peer config;
          ignore(client # helo ?host())
  );
  if tls_required && client#tls_endpoint=None then
    raise
      (Netsys_types.TLS_error "TLS required by SMTP client but not avalable");
  let srv_mechs = auth_mechanisms client#helo_response in
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
      [ "digest-uri", "smtp/" ^ peer;     (* for DIGEST-MD5 *)
        "gssapi-acceptor", "smtp"         (* for Kerberos *)
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


let sendmail client msg =
  let (hdr, _) = msg in
  let senders =
    hdr # multiple_field "from" in
  let parsed_senders =
    List.flatten
      (List.map Netaddress.parse senders) in
  let parsed_sender =
    match parsed_senders with
      | [sender] -> Some sender
      | [] -> None
      | _ -> failwith "Netsmtp.sendmail: multiple senders (From header)" in
  let sender_mbox =
    match parsed_sender with
      | Some(`Mailbox mbox) -> mbox
      | Some (`Group _) -> failwith "Netsmtp.sendmail: sender is a group"
      | None -> new Netaddress.mailbox [] ("",None) in
  let sender_mbox_s =
    match sender_mbox # spec with
      | (local, None) -> local
      | (local, Some domain) -> local ^ "@" ^ domain in
  let receivers =
    hdr # multiple_field "to" @
      hdr # multiple_field "cc" @
        hdr # multiple_field "bcc" in
  let parsed_receivers =
    List.flatten
      (List.map Netaddress.parse receivers) in
  let mailboxes =
    List.flatten
      (List.map
         (fun addr ->
            match addr with
              | `Mailbox mbox -> [mbox]
              | `Group g -> g#mailboxes
         )
         parsed_receivers
      ) in
  if mailboxes = [] then
    failwith "Netsmtp.sendmail: no receivers (To/Cc/Bcc headers)";
  
  client # mail sender_mbox_s;
    
  List.iter
    (fun mbox ->
       let (local,domain) = mbox#spec in
       let s =
         match domain with
           | None -> local
           | Some dom -> local ^ "@" ^ dom in
       client # rcpt s
    )
    mailboxes;

  let buf = Netbuffer.create 1000 in
  let ch1 = new Netchannels.output_netbuffer buf in
  Netmime_channels.write_mime_message ch1 msg;
  let ch2, set_eof = Netchannels.create_input_netbuffer buf in
  set_eof();

  client # data ch2



(*
#use "topfind";;
#require "netclient,nettls-gnutls";;
Netsmtp.Debug.enable := true;;
let addr = `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "localhost", 25), Uq_client.default_connect_options);;
let tls = Netsys_crypto.current_tls();;
let tc = Netsys_tls.create_x509_config ~trust:[`PEM_file "/etc/ssl/certs/ca-certificates.crt" ] ~peer_auth:`None tls;;
let c  = new Netsmtp.connect addr 300.0;;
c#helo();;
c#starttls tc;;
c # auth (module Netmech_digestmd5_sasl.DIGEST_MD5) "gerd" "" [ "password", "secret", [] ] [ "digest-uri", "smtp/smtp", true];;


Netsmtp.authenticate ~tls_config:tc ~sasl_mechs:[ (module Netmech_digestmd5_sasl.DIGEST_MD5); (module Netmech_crammd5_sasl.CRAM_MD5) ] ~user:"gerd" ~creds:["password", "secret", []] c ;;

 *)
