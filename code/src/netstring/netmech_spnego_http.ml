(* $Id$ *)

(* see RFC 4559 for SPNEGO for HTTP *)

(* SPNEGO authenticates the whole TCP connection, and not the individual
   request. Our design how to handle this:

    - There is a new transport_layer_id: spnego_trans_id. This implies
      SPNEGO with "default configuration" and https.
    - If we get a www-authenticate: negotiate header from a server,
      and the current connection isn't for spnego_trans_id, we return
      a special code so that the request is re-routed to a new connection
      which is then bound to spnego_trans_id.
    - Type changes:
       * client_match may return a new tag for re-routing to a different
         trans_id: `Reroute.
    - Changes in Http_client:
       * pass trans_id as part of client_match call
       * what to do for `Reroute: we always follow this. Check whether
         a connection with the new trans_id exists. If yes, use it. If not,
         create a new one.

         Trace for `Reroute:
         - new case for auth_state: `Resubmit of trans_id
         - generic_auth_session_for_challenge: test for `Reroute condition
           in initializer. If so, we still create the session, but 
           [authenticate] immediately returns `Reroute.
           If the user has set the trans_id we MUST reject this auth method.
         - postprocess_complete_message_e: check whether 
           content_response=`Reroute. set_auth_state `Resubmit.
         - From that point on, the request is handled as a special
           redirect
         - add_with_callback: check whether auth_state=`Resubmit. 
           In this case, set the trans_id of the request and re-add

 *)

(* Re-auth:

   Better: SPNEGO indicates `Accept on client_match, and reroutes the second
   request

   New auth_status:
     - `Continue_reroute. Returned for the first request.

   client_domain: return [ "/" ]

 *)


open Printf

let spnego_oid = [| 1;3;6;1;5;5;2 |]

let spnego_trans_id = Nethttp.spnego_trans_id


module type PROFILE =
  sig
    val acceptable_transports : Nethttp.transport_layer_id list
    val https_required : bool

    (* future: configure SPNEGO *)

  end


module Default : PROFILE =
  struct
    let acceptable_transports = [ spnego_trans_id ]
    let https_required = true
  end


module SPNEGO(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : Nethttp.HTTP_MECHANISM = 
  struct
    let mechanism_name = "Negotiate"

    let available() = true
      (* FIXME: check whether spnego supported *)                       
 
    let restart_supported = true
                              
    type credentials = unit
                         
    let init_credentials _ = ()

    let client_match ~params (challenge : Nethttp.Header.auth_challenge) =
      let param name =
        let (_, v, _) =
          List.find (fun (n, _, _) -> n = name) params in
        v in
      try
        let trans_id = int_of_string (param "trans_id") in
        let https = bool_of_string (param "https") in
        if not (List.mem trans_id P.acceptable_transports) then
          match P.acceptable_transports with
            | [] -> raise Not_found
            | pref_id :: _ -> 
                 `Reroute("SPNEGO", pref_id)
        else (
          if P.https_required && not https then raise Not_found;
          let (ch_name, ch_params) = challenge in
          if String.lowercase ch_name = "negotiate" then
            `Accept("SPNEGO", Some "SPNEGO_ID" )
            (* We use always a the same dummy ID. An ID is needed because
               Http_client is mostly written for per-message authentication,
               and this works only when follow-up messages of an auth attempt
               are tagged with the same ID.
             *)
          else
            raise Not_found
        )
      with
        | Not_found -> `Reject

    type client_sub_state =
        [ `Pre_init_context | `Init_context | `Established
        ]

    type client_session =
        { mutable ccontext : G.context option;
          mutable cstate : Netsys_sasl_types.client_state;
          mutable csubstate : client_sub_state;
          mutable ctoken : string;
          ctarget_name : G.name;
        }

    let client_state cs = cs.cstate

    let check_gssapi_status fn_name 
                            ((calling_error,routine_error,_) as major_status)
                            minor_status =
      if calling_error <> `None || routine_error <> `None then (
        let error = Netsys_gssapi.string_of_major_status major_status in
        let minor_s =
          G.interface # display_minor_status
            ~mech_type:[||]
            ~status_value:minor_status
            ~out:(fun ~status_strings ~minor_status ~major_status () ->
                    String.concat "; " status_strings
                 )
            () in
        (* eprintf "STATUS: %s %s %s\n%!" fn_name error minor_s; *)
        failwith ("Unexpected major status for " ^ fn_name ^ ": " ^ 
                    error ^ " (minor: " ^ minor_s ^ ")")
      )

    let call_init_sec_context cs input_token =
      G.interface # init_sec_context
         ~initiator_cred:G.interface#no_credential
         ~context:cs.ccontext
         ~target_name:cs.ctarget_name
         ~mech_type:spnego_oid
         ~req_flags:[ `Integ_flag; `Mutual_flag ]
         ~time_req:None
         ~chan_bindings:None
         ~input_token
         ~out:(fun ~actual_mech_type ~output_context ~output_token 
                   ~ret_flags ~time_rec ~minor_status ~major_status () -> 
                 let (_,_,suppl) = major_status in
                 check_gssapi_status
                   "init_sec_context" major_status minor_status;
                 assert(output_context <> None);
                 cs.ccontext <- output_context;
                 cs.ctoken <- output_token;
                 let auth_done = (suppl = []) in
                 if auth_done then (
                   cs.cstate <- if output_token = "" then `OK else `Emit;
                   cs.csubstate <- `Established;
                 )
                 else (
                   assert(suppl = [`Continue_needed]);
                   cs.cstate <- `Emit;
                   cs.csubstate <- `Init_context
                 )
              )
         ()

    let create_client_session ~user ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          [ "realm"; "id"; "target-host"; "trans_id"; "https" ]
          params in
      let https =
        try List.assoc "https" params = "true"
        with Not_found -> false in
      let acceptor_name =
        try
          "HTTP@" ^ List.assoc "target-host" params
        with
          | Not_found -> failwith "missing parameter 'target-host'" in
      let acceptor_name_type =
        Netsys_gssapi.nt_hostbased_service in
      let ctarget_name =
        G.interface # import_name
          ~input_name:acceptor_name
          ~input_name_type:acceptor_name_type
          ~out:(fun ~output_name ~minor_status ~major_status () ->
                  check_gssapi_status "import_name" major_status minor_status;
                  output_name
               )
          () in
      let cstate =
        if not P.https_required || https then
          `Wait (* HTTP auth is always "server-first" *)
        else 
          `Auth_error "HTTPS required" in
      let cs =
        { ccontext = None;
          cstate;
          csubstate = `Pre_init_context;
          ctoken = "";
          ctarget_name;
        } in
      cs

    let client_configure_channel_binding cs cb =
      if cb <> `None then
        failwith "Netmech_spnego_http.client_configure_channel_binding: \
                  not supported"
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = `None

    let client_restart cs =
      (* There is actually no restart protocol. As we authenticate the TCP
         connection, we just claim we can restart.
       *)
      (* FIXME: how do we check that the cbid is the same? *)
      if cs.cstate <> `OK then
        failwith "Netmech_spnego_http.client_restart: unfinished auth";
      cs.ccontext <- None;
      cs.cstate <- `Emit;
      cs.csubstate <- `Established;
      cs.ctoken <- ""

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs meth uri hdr challenge =
      try
        if cs.cstate <> `Wait then
          failwith "protocol error";
        let (ch_name, ch_params) = challenge in
        if String.lowercase ch_name <> "negotiate" then
          failwith "bad auth scheme";
        let msg =
          match ch_params with
            | [ "credentials", `V msg ] -> msg
            | [] -> ""
            | _ -> failwith "bad www-authenticate header" in
        let msg =
          try
            Netencoding.Base64.decode msg
          with 
            | Invalid_argument _ -> failwith "Base64 error" in
        match cs.csubstate with
          | `Pre_init_context ->
               call_init_sec_context cs None  (* sets cs.cstate to `Emit *)
          | `Init_context ->
               call_init_sec_context cs (Some msg)
          | `Established ->
               failwith "unexpected token"
      with
        | Failure msg ->
             cs.cstate <- `Auth_error msg

    let client_emit_response cs meth uri hdr =
      if cs.cstate <> `Emit then
        failwith "Netmech_spnego_http.client_emit_response: bad state";
      ( match cs.csubstate with
          | `Pre_init_context ->
               assert false
          | `Established ->
              cs.cstate <- `OK
          | _ ->
              cs.cstate <- `Wait
      );
      let b64 = Netencoding.Base64.encode cs.ctoken in
      let creds =
        ( "Negotiate", [ "credentials", `Q b64 ] ) in
      (creds, [])

    let client_session_id cs =
      None
      
    let client_prop cs key =
      raise Not_found

    let client_user_name cs =
      ""

    let client_authz_name cs =
      ""

    let client_stash_session cs =
      (* GSSAPI does not support that unfinished contexts are exported.
         We do not need the context anyway after session establishment,
         so we don't save it at all.
       *)
      if cs.cstate <> `OK then
        failwith "Netmech_spnego_http.client_stash_session: the session \
                  must be established (implementation restriction)";
      "client,t=SPNEGO;"

    let client_resume_session s =
      if s <> "client,t=SPNEGO;" then
        failwith "Netmech_spnego_http.client_resume_session";
      { ccontext = None;
        cstate = `OK;
        csubstate = `Established;
        ctoken = "";
        ctarget_name = G.interface # no_name;
      }

    let client_domain s = []

  end

(*
#use "topfind";;
#require "netclient,netgss-system,nettls-gnutls";;
module A = Netmech_spnego_http.SPNEGO(Netmech_spnego_http.Default)(Netgss.System);;
open Http_client;;
Debug.enable := true;;
let keys = new key_ring ();;
keys # add_key (key ~user:"krb" ~password:"" ~realm:"SPNEGO" ~domain:[]);;
let a = new generic_auth_handler keys [ (module A : Nethttp.HTTP_MECHANISM) ];;
let p = new pipeline;;
p # add_auth_handler a;;
let c1 = new get "https://gps.dynxs.de/krb/";;
let c2 = new get "https://gps.dynxs.de/krb/index.html";;
p # add c1;;
p # add c2;;
p # run();;

 *)
