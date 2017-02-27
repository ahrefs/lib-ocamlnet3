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
    - Changes in Nethttp_client:
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

let map_opt f =
  function
  | None -> None
  | Some x -> Some(f x)


module type PROFILE =
  sig
    val acceptable_transports_http : Nethttp.transport_layer_id list
    val acceptable_transports_https : Nethttp.transport_layer_id list
    val enable_delegation : bool
    val deleg_credential : exn option

    (* future: configure SPNEGO *)

  end


module Default : PROFILE =
  struct
    let acceptable_transports_http = [ ]
    let acceptable_transports_https = [ spnego_trans_id ]
    let enable_delegation = true
    let deleg_credential = None
  end


module SPNEGO(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : Nethttp.HTTP_CLIENT_MECHANISM = 
  struct
    module M = Netgssapi_auth.Manage(G)
    module C = struct
      let raise_error = failwith
    end
    module A = Netgssapi_auth.Auth(G)(C)

    let mechanism_name = "Negotiate"

    let available() = true
      (* FIXME: check whether spnego supported *)                       
 
    let restart_supported = true
                              
    type credentials = unit
                         
    let init_credentials _ = ()

    let realm = "SPNEGO"

    let client_match ~params (challenge : Nethttp.Header.auth_challenge) =
      let param name =
        let (_, v, _) =
          List.find (fun (n, _, _) -> n = name) params in
        v in
      try
        let (ch_name, ch_params) = challenge in
        if STRING_LOWERCASE ch_name <> "negotiate" then raise Not_found;
        let trans_id = int_of_string (param "trans_id") in
        let https = bool_of_string (param "https") in
        let acceptable_transports =
          if https then
            P.acceptable_transports_https
          else
            P.acceptable_transports_http in
        let is_acceptable_trans =
          List.mem trans_id acceptable_transports in
        if is_acceptable_trans then
          `Accept(realm, None)
        else
          match acceptable_transports with
            | [] -> raise Not_found
            | pref_id :: _ -> 
                 `Accept_reroute(realm, None, pref_id)
      with
        | Not_found -> `Reject

    type client_sub_state =
        [ `Pre_init_context | `Init_context | `Established | `Restart
        ]

    type client_session =
        { mutable ccontext : G.context option;
          cstate : Netsys_sasl_types.client_state;
          csubstate : client_sub_state;
          ctoken : string;
          cconn : int;
          cconf : Netsys_gssapi.client_config;
          ctarget_name : G.name;
          ccred : G.credential;
          cprops : Netsys_gssapi.client_props option;
        }

    let client_state cs = cs.cstate

    let client_del_ctx cs =
      match cs.ccontext with
        | None -> cs
        | Some ctx ->
            M.delete_context cs.ccontext ();
            { cs with ccontext = None }

    let cvalidity cs0 =
      let cs1 = {cs0 with ccontext = cs0.ccontext} in
      cs0.ccontext <- None;
      cs1
                 

    let check_gssapi_status fn_name 
                            ((calling_error,routine_error,_) as major_status)
                            minor_status =
      if calling_error <> `None || routine_error <> `None then (
        let msg =
          M.format_status ~fn:fn_name ~minor_status major_status in
        failwith msg
      )

    let client_check_gssapi_status cs fn_name major_status minor_status =
      try
        check_gssapi_status fn_name major_status minor_status
      with
        | error ->
            ignore(client_del_ctx cs);
            raise error
           

    let call_init_sec_context cs input_token =
      let (out_context, out_token, ret_flags, props_opt) =
        A.init_sec_context
          ~initiator_cred:cs.ccred
          ~context:cs.ccontext
          ~target_name:cs.ctarget_name
          ~req_flags:(A.get_client_flags cs.cconf)
          ~chan_bindings:None
          ~input_token
          cs.cconf in
      let cs =
        { cs with
          ccontext = Some out_context;
          ctoken = out_token;
          cprops = props_opt;
        } in
      let auth_done = (props_opt <> None) in
      if auth_done then (
        let cs =
          { cs with
            cstate = if out_token = "" then `OK else `Emit;
            csubstate = `Established;
          } in
        client_del_ctx cs;  (* no longer needed *)
      )
      else
        { cs with
          cstate = `Emit;
          csubstate = `Init_context
        }

    let create_client_session ~user ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          [ "realm"; "id"; "target-host"; "trans_id"; "conn_id"; "https" ]
          params in
      let conn_id =
        try int_of_string (List.assoc "conn_id" params)
        with Not_found -> failwith "missing parameter: conn_id" in

      let acceptor_name =
        try
          "HTTP@" ^ List.assoc "target-host" params
        with
          | Not_found -> failwith "missing parameter 'target-host'" in
      let acceptor_name_type =
        Netsys_gssapi.nt_hostbased_service in
      let cconf =
        Netsys_gssapi.create_client_config
          ~mech_type:spnego_oid
          ~target_name:(acceptor_name, acceptor_name_type)
          ~privacy:`If_possible
          ~integrity:`Required
          ~flags:( [ `Mutual_flag, `Required ] @
                     ( if P.enable_delegation then [`Deleg_flag, `Required] 
                       else [] ) )
          () in
      let ctarget_name =
        A.get_target_name cconf in
      let ccred =
        match P.deleg_credential with
          | Some (G.Credential c) -> c
          | _ -> G.interface # no_credential in
      let cstate = `Wait (* HTTP auth is always "server-first" *) in
      let cs =
        { ccontext = None;
          cstate;
          csubstate = `Pre_init_context;
          ctoken = "";
          ctarget_name;
          cconf;
          cconn = conn_id;
          ccred;
          cprops = None;
        } in
      cs

    let client_configure_channel_binding cs cb =
      if cb <> `None then
        failwith "Netmech_spnego_http.client_configure_channel_binding: \
                  not supported"
      else
        cs
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = `None

    let client_restart ~params cs =
      (* There is actually no restart protocol. As we authenticate the TCP
         connection, we just claim we can restart.
       *)
      if cs.cstate <> `OK then
        failwith "Netmech_spnego_http.client_restart: unfinished auth";
      let cs = cvalidity cs in
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          [ "realm"; "id"; "target-host"; "trans_id"; "conn_id"; "https" ]
          params in
      let conn_id =
        try int_of_string (List.assoc "conn_id" params)
        with Not_found -> failwith "missing parameter: conn_id" in
      let cs =
        { cs with
          ccontext = None;
          cstate = `Emit;
          ctoken = "";
          csubstate = `Pre_init_context;
          cconn = conn_id;
        } in
      call_init_sec_context cs None
        

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs meth uri hdr challenge =
      let cs = cvalidity cs in
      try
        if cs.cstate <> `Wait then
          failwith "protocol error";
        let (ch_name, ch_params) = challenge in
        if STRING_LOWERCASE ch_name <> "negotiate" then
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
               if msg <> "" then failwith "unexpected token";
               call_init_sec_context cs None  (* sets cs.cstate to `Emit *)
          | `Init_context ->
               call_init_sec_context cs (Some msg)
          | `Restart ->
               (* THIS PATH IS CURRENTLY NOT TAKEN: on restart, we directly
                  enter `Pre_init_context state, and generate the token
                *)
               (* As SPNEGO authenticates the connection and not the message,
                  we are done when
                  the server responds with a non-401 message, and there is
                  no www-authenticate (here: ch_params=[]). Otherwise,
                  handle it like `Pre_init_context, and re-run the protocol.
                *)
               if ch_params = [] then (
                 { cs with
                   cstate = `OK;
                   csubstate = `Established
                 }
               ) else
                 call_init_sec_context cs None  (* sets cs.cstate to `Emit *)
          | `Established ->
               failwith "unexpected token"
      with
        | Failure msg ->
             let cs = client_del_ctx cs in
             { cs with cstate = `Auth_error msg }

    let client_emit_response cs meth uri hdr =
      if cs.cstate <> `Emit then
        failwith "Netmech_spnego_http.client_emit_response: bad state";
      let cs =
        match cs.csubstate with
          | `Pre_init_context ->
               assert false
          | `Established ->
              let cs = client_del_ctx cs in
              { cs with cstate = `OK }
          | _ ->
              { cs with cstate = `Wait } in
      let b64 = Netencoding.Base64.encode cs.ctoken in
      let creds =
        ( "Negotiate", 
          if cs.ctoken="" then [] else [ "credentials", `Q b64 ] ) in
      (* NB. The case creds=(something,[]) is special-cased in the http client,
         so that no auth header is added at all
       *)
      (cs, creds, [])

    let client_session_id cs =
      None
      
    let client_prop cs key =
      raise Not_found

    let client_gssapi_props cs =
      match cs.cprops with
        | None -> raise Not_found
        | Some p -> p

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
      "client,t=SPNEGO;" ^
        Marshal.to_string
          (map_opt Netsys_gssapi.marshal_client_props cs.cprops)
          []

    let cs_re = 
      Netstring_str.regexp "client,t=SPNEGO;"

    let client_resume_session s =
      match Netstring_str.string_match cs_re s 0 with
        | None ->
            failwith "Netmech_spnego_http.client_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (mprops) = Marshal.from_string data 0 in
            { ccontext = None;
              cstate = `OK;
              csubstate = `Established;
              ctoken = "";
              ctarget_name = G.interface # no_name;
              cconn = 0;  (* FIXME *)
              cconf = Netsys_gssapi.create_client_config();
              ccred =  G.interface # no_credential;
              cprops = map_opt Netsys_gssapi.unmarshal_client_props mprops;
            }

    let client_domain s = [ "/" ]
      (* This way the auth sessions get cached *)

  end

(*
#use "topfind";;
#require "netclient,netgss-system,nettls-gnutls";;

module D = Netmech_spnego_http.Default;;
module D = 
  struct include Netmech_spnego_http.Default let enable_delegation=true end;;

module A = Netmech_spnego_http.SPNEGO(D)(Netgss.System);;

open Nethttp_client;;
Debug.enable := true;;
let keys = new key_ring ~no_invalidation:true ();;
keys # add_key (key ~user:"krb" ~password:"" ~realm:"SPNEGO" ~domain:[]);;
let a = new generic_auth_handler keys [ (module A : Nethttp.HTTP_CLIENT_MECHANISM) ];;
let p = new pipeline;;
p # add_auth_handler a;;
let c1 = new get "https://gps.dynxs.de/krb/";;
let c2 = new get "https://gps.dynxs.de/krb/index.html";;

p # add c1;;
p # add c2;;
p # run();;

p # add_with_callback c1 (fun _ -> p # add c2);;
p # run();;

c2 # set_transport_layer Nethttp_client.spnego_trans_id;;
p # add_with_callback c1 (fun _ -> p # add c2);;
p # run();;


 *)
