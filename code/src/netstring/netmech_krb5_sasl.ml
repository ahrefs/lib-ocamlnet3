(* $Id$ *)

open Printf

module KRB5(G:Netsys_gssapi.GSSAPI) : Netsys_sasl_types.SASL_MECHANISM =
  struct
    let mechanism_name = "GSSAPI"
    let client_first = `Required
    let server_sends_final_data = true
    let supports_authz = false

    let available() = true
      (* Well, let's assume this. We don't know yet whether we can get
         credentials, and we don't know yet whether we are acting as client
         or as server.
       *)

    type credentials = unit

    let init_credentials _ = ()

    (* ------------------------ *)
    (*          Client          *)
    (* ------------------------ *)


    type sub_state =
        [ `Init_context | `Skip_empty | `Neg_security | `Established ]

    type client_session =
        { cauthz : string;
          mutable ccontext : G.context option;
          mutable cstate : Netsys_sasl_types.client_state;
          mutable csubstate : sub_state;
          mutable ctoken : string;
          ctarget_name : G.name;
          cmutual : bool;
        }

    let krb5_oid =
      [| 1;2;840;113554;1;2;2 |]

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
        failwith ("Unexpected major status for " ^ fn_name ^ ": " ^ 
                    error ^ " (minor: " ^ minor_s ^ ")")
      )

    let call_init_sec_context cs input_token =
      G.interface # init_sec_context
         ~initiator_cred:G.interface#no_credential
         ~context:cs.ccontext
         ~target_name:cs.ctarget_name
         ~mech_type:krb5_oid
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
                 if cs.cmutual && not(List.mem `Mutual_flag ret_flags) then
                   failwith "mutual authentication requested but not available";
                 cs.ccontext <- output_context;
                 cs.ctoken <- output_token;
                 cs.cstate <- `Emit;
                 if suppl = [] then
                   cs.csubstate <- 
                     if input_token=None then `Skip_empty else`Neg_security
              )
         ()

    let create_client_session ~user ~authz ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          [ "gssapi-acceptor"; "mutual"; "secure" ]
          params in
      let acceptor_name =
        try List.assoc "gssapi-acceptor" params
        with Not_found ->
          failwith "Netmech_krb5_sasl.create_client_session: \
                    missing parameter 'gssapi-acceptor'" in
      let ctarget_name =
        G.interface # import_name
          ~input_name:acceptor_name
          ~input_name_type:Netsys_gssapi.nt_hostbased_service
          ~out:(fun ~output_name ~minor_status ~major_status () ->
                  check_gssapi_status "import_name" major_status minor_status;
                  output_name
               )
          () in
      let req_mutual =
        try List.assoc "mutual" params = "true" with Not_found -> false in
      let cs =
        { cauthz = authz;
          ccontext = None;
          cstate = `Emit;
          csubstate = `Init_context;
          ctoken = "";
          ctarget_name;
          cmutual = req_mutual
        } in
      ( try
          call_init_sec_context cs None
        with
          | Failure _ -> cs.cstate <- `Auth_error
      );
      cs

    let client_configure_channel_binding cs cb =
      if cb <> `None then
        failwith "Netmech_krb5_sasl.client_configure_channel_binding: \
                  not supported"
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = `None

    let client_restart cs =
      if cs.cstate <> `OK then
        failwith "Netmech_krb5_sasl.client_restart: unfinished auth";
      cs.ccontext <- None;
      cs.cstate <- `Emit;
      cs.csubstate <- `Init_context;
      cs.ctoken <- "";
      call_init_sec_context cs None

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs msg =
      if cs.cstate <> `Wait then
        cs.cstate <- `Auth_error
      else
        match cs.csubstate with
          | `Init_context ->
               ( try
                   call_init_sec_context cs (Some msg)
                 with
                   | Failure _ ->
                        cs.cstate <- `Auth_error
               )
          | `Skip_empty ->
               if msg = "" then (
                 cs.cstate <- `Emit;
                 cs.ctoken <- "";
                 cs.csubstate <- `Neg_security;
               )
               else
                 cs.cstate <- `Auth_error
          | `Neg_security ->
               ( try
                   let input_message = [ Xdr_mstring.string_to_mstring msg ] in
                   let context = client_context cs in
                   let msg_unwrapped =
                     G.interface # unwrap
                       ~context ~input_message
                       ~output_message_preferred_type:`String
                       ~out:(fun ~output_message ~conf_state ~qop_state
                                 ~minor_status ~major_status () ->
                               check_gssapi_status
                                 "unwrap" major_status minor_status;
                               Xdr_mstring.concat_mstrings output_message
                            )
                       () in
                   if String.length msg_unwrapped <> 4 then
                     failwith "bad message";
                   let out_msg =
                     "\001\000\000\000" ^ cs.cauthz in
                   let out_message =
                     [ Xdr_mstring.string_to_mstring out_msg ] in
                   let out_msg_wrapped =
                     G.interface # wrap
                       ~context ~conf_req:false ~qop_req:0l
                       ~input_message:out_message
                       ~output_message_preferred_type:`String
                       ~out:(fun ~conf_state ~output_message 
                                 ~minor_status ~major_status () ->
                               check_gssapi_status
                                 "wrap" major_status minor_status;
                               Xdr_mstring.concat_mstrings output_message
                            )
                       () in
                   cs.ctoken <- out_msg_wrapped;
                   cs.cstate <- `Emit;
                   cs.csubstate <- `Established
                 with
                   | Failure _ ->
                        cs.cstate <- `Auth_error
               )
          | `Established ->
               cs.cstate <- `Auth_error

    let client_emit_response cs =
      if cs.cstate <> `Emit then
        failwith "Netmech_krb5_sasl.client_emit_response: bad state";
      cs.cstate <- (if cs.csubstate = `Established then `OK else `Wait);
      cs.ctoken

    let client_session_id cs =
      None
      
    let client_prop cs key =
      raise Not_found

    let client_user_name cs =
      ""

    let client_authz_name cs =
      cs.cauthz

    let client_stash_session cs =
      failwith "Netmech_krb5_sasl.client_stash_session: not supported"

    let client_resume_session s =
      failwith "Netmech_krb5_sasl.client_resume_session: not supported"

  (*
#use "topfind";;
#require "netclient,netgss-system";;
Netpop.Debug.enable := true;;
let addr =
    `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "office1", 110),
            Uq_client.default_connect_options);;
let client = new Netpop.connect addr 60.0;;
module S = Netmech_krb5_sasl.KRB5(Netgss.System);;
Netpop.authenticate
  ~sasl_mechs:[ (module S)
              ]
  ~user:""
  ~creds:[]
  ~sasl_params:["gssapi-acceptor", "pop@office1.lan.sumadev.de", false]
  client;;
   *)



    (* ------------------------ *)
    (*          Server          *)
    (* ------------------------ *)

    type server_session = unit

    let server_state ss = assert false
    let create_server_session ~lookup ~params () = assert false
    let server_process_response ss msg = assert false
    let server_process_response_restart ss msg set_stale = assert false
    let server_emit_challenge ss = assert false
    let server_channel_binding ss =
      `None
    let server_stash_session ss = assert false
    let server_resume_session ~lookup s = assert false
    let server_session_id ss =
      None
    let server_prop ss key =
      raise Not_found

    let server_user_name ss = assert false
    let server_authz_name ss = assert false
  end
