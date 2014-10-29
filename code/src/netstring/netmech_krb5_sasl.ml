(* $Id$ *)

open Printf

module KRB5(G:Netsys_gssapi.GSSAPI) : Netsys_sasl_types.SASL_MECHANISM =
  struct
    let mechanism_name = "GSSAPI"
    let client_first = `Required
    let server_sends_final_data = true
    let supports_authz = true

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


    type client_sub_state =
        [ `Init_context | `Skip_empty | `Neg_security | `Established ]

    type client_session =
        { cauthz : string;
          mutable ccontext : G.context option;
          mutable cstate : Netsys_sasl_types.client_state;
          mutable csubstate : client_sub_state;
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
        (* eprintf "STATUS: %s %s %s\n%!" fn_name error minor_s; *)
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
      (* GSSAPI does not support that unfinished contexts are exported.
         We do not need the context anyway after session establishment,
         so we don't save it at all.
       *)
      if cs.cstate <> `OK then
        failwith "Netmech_krb5_sasl.client_stash_session: the session \
                  must be established (implementation restriction)";
      "client,t=GSSAPI;" ^ 
        Marshal.to_string (cs.cauthz, cs.cmutual) []

    let cs_re = 
      Netstring_str.regexp "client,t=GSSAPI;"
           
    let client_resume_session s =
      match Netstring_str.string_match cs_re s 0 with
        | None ->
            failwith "Netmech_krb5_sasl.client_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (cauthz, cmutual) = Marshal.from_string data 0 in
            { cauthz;
              ccontext = None;
              cstate = `OK;
              csubstate = `Established;
              ctoken = "";
              ctarget_name = G.interface # no_name;
              cmutual
            }

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

    type server_sub_state =
        [ `Acc_context | `Neg_security1 | `Neg_security2 | `Established ]

    type server_session =
        { mutable scontext : G.context option;
          mutable sstate : Netsys_sasl_types.server_state;
          mutable ssubstate : server_sub_state;
          mutable stoken : string;
          mutable suser : string option;
          mutable sauthz : string option;
          scred : G.credential;
          slookup : (string -> string -> credentials option);
          smutual : bool;
          sservice : string;
          srealm : string option;
        }


    let server_state ss = ss.sstate

    let create_server_session ~lookup ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_server_session:"
          [ "gssapi-acceptor-service"; "realm"; "mutual"; "secure" ]
          params in
      let sservice =
        try List.assoc "gssapi-acceptor-service" params
        with Not_found ->
          failwith "Netmech_krb5_sasl.create_server_session: \
                    missing parameter 'gssapi-acceptor-service'" in
      let srealm =
        try Some(List.assoc "realm" params)
        with Not_found -> None in
      let smutual =
        try List.assoc "mutual" params = "true" with Not_found -> false in
      let scred =
        G.interface # acquire_cred
          ~desired_name:G.interface#no_name
          ~time_req:`Indefinite
          ~desired_mechs:[ krb5_oid ]
          ~cred_usage:`Accept
          ~out:(fun ~cred ~actual_mechs ~time_rec ~minor_status ~major_status
                    () ->
                   check_gssapi_status
                     "acquire_cred" major_status minor_status;
                   cred
               )
          () in
      { scontext = None;
        sstate = `Wait;
        ssubstate = `Acc_context;
        stoken = "";
        suser = None;
        sauthz = None;
        slookup = lookup;
        smutual = smutual;
        sservice;
        srealm;
        scred;
      }

    let server_context ss =
      match ss.scontext with
        | None -> assert false
        | Some c -> c


    let  server_set_neg_security_token ss =
      (* we do not offer any security layer *)
      let context = server_context ss in
      let out_msg = "\001\000\000\000" in
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
      ss.stoken <- out_msg_wrapped


    let server_process_response_accept_context ss msg =
      let cont =
        G.interface # accept_sec_context
          ~context:ss.scontext
          ~acceptor_cred:ss.scred
          ~input_token:msg
          ~chan_bindings:None
          ~out:(fun ~src_name ~mech_type ~output_context ~output_token
                    ~ret_flags ~time_rec ~delegated_cred 
                    ~minor_status ~major_status () ->
                   check_gssapi_status
                     "accept_sec_context" major_status minor_status;
                   assert(output_context <> None);
                   let (_,_,suppl) = major_status in
                   let cont = List.mem `Continue_needed suppl in
                   ss.scontext <- output_context;
                   ss.stoken <- output_token;
                   ss.sstate <- `Emit;  (* even an empty token *)
                   if not cont then (
                     if ss.smutual && not(List.mem `Mutual_flag ret_flags) then
                       failwith "mutual auth requested but not available";
                   );
                   cont
               )
          () in
      if not cont then (
        let src_name, targ_name =
          G.interface # inquire_context
            ~context:(server_context ss)
            ~out:(fun ~src_name ~targ_name ~lifetime_req ~mech_type ~ctx_flags
                      ~locally_initiated ~is_open ~minor_status ~major_status
                      ()  ->
                    check_gssapi_status
                      "inquire_context" major_status minor_status;
                    if mech_type <> krb5_oid then
                      failwith "the mechanism is not Kerberos 5";
                    src_name, targ_name
                 )
            () in
        G.interface # display_name
          ~input_name:targ_name
          ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status
                    () ->
                  check_gssapi_status
                    "display_name" major_status minor_status;
                  if output_name_type = Netsys_gssapi.nt_hostbased_service ||
                       output_name_type = Netsys_gssapi.nt_hostbased_service_alt
                  then(
                    let service, _ =
                      Netsys_gssapi.parse_hostbased_service output_name in
                    if service <> ss.sservice then
                      failwith "unexpected service"
                  )
                  else
                    if output_name_type = Netsys_gssapi.nt_krb5_principal_name
                    then
                      let components, _ =
                        Netgssapi_support.parse_kerberos_name output_name in
                      match components with
                        | [service;_] ->
                            if service <> ss.sservice then
                              failwith "unexpected service"
                        | _ ->
                            failwith "unexpected target krb5 principal"
                    else
                      failwith "unexpected target name"
               )
          ();
        G.interface # display_name
          ~input_name:src_name
          ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status
                    () ->
                  check_gssapi_status
                    "display_name" major_status minor_status;
                  if output_name_type <> Netsys_gssapi.nt_krb5_principal_name
                  then
                    failwith "unexpected client name type";
                  match ss.srealm with
                    | None ->
                        ss.suser <- Some output_name
                    | Some r ->
                        let components, realm =
                          Netgssapi_support.parse_kerberos_name output_name in
                        if realm <> Some r then
                          failwith "bad realm";
                        ( match components with
                            | [ name ] ->
                                ss.suser <- Some name
                            | _ ->
                                failwith "unexpected form of client principal"
                        )
               )
          ();
        if ss.stoken = "" then (
          server_set_neg_security_token ss;
          ss.ssubstate <- `Neg_security2
        )
        else
          ss.ssubstate <- `Neg_security1
      )


    let server_process_response_neg_security1 ss msg =
      (* any msg is acceptable *)
      server_set_neg_security_token ss;
      ss.ssubstate <- `Neg_security2;
      ss.sstate <- `Emit
      
    let server_process_response_neg_security2 ss msg =
      let input_message = [ Xdr_mstring.string_to_mstring msg ] in
      let context = server_context ss in
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
      if String.length msg_unwrapped < 4 then
        failwith "bad security token";
      if String.sub msg_unwrapped 0 4 <> "\001\000\000\000" then
        failwith "bad security token";
      let authz =
        String.sub msg_unwrapped 4 (String.length msg_unwrapped - 4) in
      ss.sauthz <- Some authz;
      let user =
        match ss.suser with
          | None -> raise Not_found
          | Some u -> u in
      let user_cred_opt =
        ss.slookup user authz in
      if user_cred_opt = None then
        failwith "unauthorized user";
      ss.ssubstate <- `Established;
      ss.sstate <- `OK


    let server_process_response ss msg =
      try
        if ss.sstate <> `Wait then raise Not_found;
        match ss.ssubstate with
          | `Acc_context ->
              server_process_response_accept_context ss msg
          | `Neg_security1 ->
              server_process_response_neg_security1 ss msg
          | `Neg_security2 ->
              server_process_response_neg_security2 ss msg
          | `Established ->
              raise Not_found
      with
        | Not_found
        | Failure _ ->
            ss.sstate <- `Auth_error


    let server_process_response_restart ss msg set_stale =
      failwith "Netmech_krb5_sasl.server_process_response_restart: \
                not available"

    let server_emit_challenge ss =
      if ss.sstate <> `Emit then
        failwith "Netmech_krb5_sasl.server_emit_challenge: bad state";
      ss.sstate <- `Wait;
      ss.stoken

    let server_channel_binding ss =
      `None

    let server_stash_session ss =
      (* GSSAPI does not support that unfinished contexts are exported.
         We do not need the context anyway after session establishment,
         so we don't save it at all.
       *)
      if ss.sstate <> `OK then
        failwith "Netmech_krb5_sasl.server_stash_session: the session \
                  must be established (implementation restriction)";
      "server,t=GSSAPI;" ^ 
        Marshal.to_string (ss.suser, ss.sauthz, ss.smutual,
                           ss.sservice, ss.srealm) []

    let ss_re = 
      Netstring_str.regexp "server,t=GSSAPI;"
           

    let server_resume_session ~lookup s =
      match Netstring_str.string_match ss_re s 0 with
        | None ->
            failwith "Netmech_krb5_sasl.server_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (suser, sauthz, smutual, sservice, srealm) =
              Marshal.from_string data 0 in
            { scontext = None;
              sstate = `OK;
              ssubstate = `Established;
              stoken = "";
              suser;
              sauthz;
              slookup = lookup;
              smutual;
              sservice;
              srealm;
              scred = G.interface#no_credential
            }
              
 
    let server_session_id ss =
      None

    let server_prop ss key =
      raise Not_found

    let server_user_name ss =
      if ss.sstate <> `OK then raise Not_found;
      match ss.suser with
        | None -> assert false
        | Some u -> u

    let server_authz_name ss =
      if ss.sstate <> `OK then raise Not_found;
      match ss.sauthz with
        | None -> assert false
        | Some u -> u
  end


(*
Works only when "test" is added to /etc/services!

KRB5_KTNAME=test.keytab OCAMLPATH=src ledit ocaml
#use "topfind";;
#require "netstring,netgss-system";;
open Printf;;
module S = Netmech_krb5_sasl.KRB5(Netgss.System);;
let no_creds = S.init_credentials [];;
let cs = S.create_client_session ~user:"" ~authz:"foo" ~creds:no_creds ~params:[ "gssapi-acceptor", "test@office1.lan.sumadev.de", false ] ();;
let lookup user authz = eprintf "user=%S authz=%S\n%!" user authz; Some no_creds;;
let ss = S.create_server_session ~lookup ~params:["gssapi-acceptor-service", "test", false ] ();;

let msg1 = S.client_emit_response cs;;
S.server_process_response ss msg1;;
let msg2 = S.server_emit_challenge ss;;
S.client_process_challenge cs msg2;;
let msg3 = S.client_emit_response cs;;
S.server_process_response ss msg3;;
let msg4 = S.server_emit_challenge ss;;
S.client_process_challenge cs msg4;;
let msg5 = S.client_emit_response cs;;
assert(S.client_state cs = `OK);;
S.server_process_response ss msg5;;
assert(S.server_state ss = `OK);;
 *)
