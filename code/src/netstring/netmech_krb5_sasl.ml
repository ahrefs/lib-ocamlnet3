(* $Id$ *)

open Printf

let krb5_oid =
  [| 1;2;840;113554;1;2;2 |]

let map_opt f =
  function
  | None -> None
  | Some x -> Some(f x)
                  


module Krb5_gs2_profile = struct
  let mechanism_name = "GS2-KRB5"
  let announce_channel_binding = false
  let mechanism_oid = krb5_oid
  let client_additional_params = [ "gssapi-acceptor" ]
  let server_additional_params = [ "gssapi-acceptor-service"; "realm" ]

  let client_map_user_name ~params user =
    ("", [| |])

  let server_map_user_name ~params (name,name_type) =
    if name_type <> Netsys_gssapi.nt_krb5_principal_name then
      raise Not_found;
    let realm_opt =
      try Some(List.assoc "realm" params) with Not_found -> None in
    match realm_opt with
      | None ->
          name
      | Some r ->
          let components, name_realm =
            Netgssapi_support.parse_kerberos_name name in
          if name_realm <> Some r then
            raise Not_found;
          ( match components with
              | [ n ] ->
                  n
              | _ ->
                  raise Not_found
          )

  let client_get_target_name ~params =
    try
      (List.assoc "gssapi-acceptor" params, Netsys_gssapi.nt_hostbased_service)
    with
      | Not_found -> failwith "missing parameter 'gssapi-acceptor'"

  let server_bind_target_name ~params =
    None

  let server_check_target_name ~params (name,name_type) =
    try
      let expected_service =
        List.assoc "gssapi-acceptor-service" params in
      if name_type = Netsys_gssapi.nt_hostbased_service ||
           name_type = Netsys_gssapi.nt_hostbased_service_alt
      then (
        let service, _ =
          Netsys_gssapi.parse_hostbased_service name in
        if service <> expected_service then raise Not_found;
      )
      else (
        if name_type = Netsys_gssapi.nt_krb5_principal_name then (
          let components, _ =
            Netgssapi_support.parse_kerberos_name name in
          match components with
            | [service;_] ->
                if service <> expected_service then
                  raise Not_found
            | _ ->
                raise Not_found
        )
        else
          raise Not_found
      );
      true
    with
      | Not_found
      | Failure _ ->
          false


  let client_flags ~params = []
  let server_flags ~params = []

  let client_credential = None
    (* Anybody who wants to pass in a client credential should do so this way:
       module My_profile =
         struct
            include Netmech_krb5_sasl.Krb5_gs2_profile
            let client_credential = ...
         end
       module Krb5_gs2(G:Netsys_gssapi.GSSAPI) =
         Netmech_gs2_sasl.GS2(My_profile)(G)
     *)
end


module Krb5_gs2(G:Netsys_gssapi.GSSAPI) =
  Netmech_gs2_sasl.GS2(Krb5_gs2_profile)(G)


module Krb5_gs1(G:Netsys_gssapi.GSSAPI) : Netsys_sasl_types.SASL_MECHANISM =
  struct
    module M = Netgssapi_auth.Manage(G)
    module C = struct
      let raise_error = failwith
    end
    module A = Netgssapi_auth.Auth(G)(C)

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
        [ `Pre_init_context | `Init_context | `Skip_empty | `Neg_security 
        | `Established
        ]

    type client_session =
        { mutable ccontext : G.context option;
          cauthz : string;
          cstate : Netsys_sasl_types.client_state;
          csubstate : client_sub_state;
          ctoken : string;
          cconf : Netsys_gssapi.client_config;
          ctarget_name : G.name;
          cprops : Netsys_gssapi.client_props option;
        }

    let cvalidity cs0 =
      let cs1 = { cs0 with ccontext = cs0.ccontext } in
      cs0.ccontext <- None;
      cs1

    let client_state cs = cs.cstate

    let client_del_ctx cs =
      match cs.ccontext with
        | None -> cs
        | Some ctx ->
            M.delete_context cs.ccontext ();
            { cs with ccontext = None }

    let check_gssapi_status fn_name 
                            ((calling_error,routine_error,_) as major_status)
                            minor_status =
      if calling_error <> `None || routine_error <> `None then (
        let msg =
          M.format_status ~fn:fn_name ~minor_status major_status in
        (* eprintf "STATUS: %s %s %s\n%!" fn_name error minor_s; *)
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
          ~initiator_cred:G.interface#no_credential
          ~context:cs.ccontext
          ~target_name:cs.ctarget_name
          ~req_flags:(A.get_client_flags cs.cconf)
          ~chan_bindings:None
          ~input_token
          cs.cconf in
      { cs with
        ccontext = Some out_context;
        ctoken = out_token;
        cprops = props_opt;
        cstate = `Emit;
        csubstate =
          ( if props_opt <> None then
              `Skip_empty
            else
              `Init_context
          )
      }

    let create_client_session ~user ~authz ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          [ "gssapi-acceptor"; "mutual"; "secure" ]
          params in
      let mutual_flag =
        try if List.assoc "mutual" params = "true" 
            then [`Mutual_flag,`Required] else []
        with Not_found -> [] in
      let cconf =
        Netsys_gssapi.create_client_config
          ~mech_type:krb5_oid
          ~target_name:(Krb5_gs2_profile.client_get_target_name ~params)
          ~privacy:`None
          ~integrity:`Required
          ~flags:( [ `Integ_flag, `Required ] @ mutual_flag )
          () in
      let ctarget_name =
        A.get_target_name cconf in
      let cs =
        { cauthz = authz;
          ccontext = None;
          cstate = `Emit;
          csubstate = `Pre_init_context;
          ctoken = "";
          ctarget_name;
          cconf;
          cprops = None;
        } in
      cs

    let client_configure_channel_binding cs cb =
      if cb <> `None then
        failwith "Netmech_krb5_sasl.client_configure_channel_binding: \
                  not supported"
      else
        cs
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = `None

    let client_restart cs =
      if cs.cstate <> `OK then
        failwith "Netmech_krb5_sasl.client_restart: unfinished auth";
      { (cvalidity cs) with
        ccontext = None;
        cstate = `Emit;
        csubstate = `Pre_init_context;
        ctoken = ""
      }

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs msg =
      let cs = cvalidity cs in
      if cs.cstate <> `Wait then (
        let cs = client_del_ctx cs in
        { cs with cstate = `Auth_error "protocol error" }
      )
      else
        match cs.csubstate with
          | `Pre_init_context ->
              assert false
          | `Init_context ->
               ( try
                   call_init_sec_context cs (Some msg)
                 with
                   | Failure msg ->
                        let cs = client_del_ctx cs in
                        { cs with cstate = `Auth_error msg }
               )
          | `Skip_empty when msg="" ->
               { cs with
                 cstate = `Emit;
                 ctoken = "";
                 csubstate = `Neg_security;
               }
          | `Neg_security
          | `Skip_empty ->
               ( try
                   let input_message = [ Netxdr_mstring.string_to_mstring msg ] in
                   let context = client_context cs in
                   let msg_unwrapped =
                     G.interface # unwrap
                       ~context ~input_message
                       ~output_message_preferred_type:`Bytes
                       ~out:(fun ~output_message ~conf_state ~qop_state
                                 ~minor_status ~major_status () ->
                               client_check_gssapi_status
                                 cs "unwrap" major_status minor_status;
                               Netxdr_mstring.concat_mstrings output_message
                            )
                       () in
                   if String.length msg_unwrapped <> 4 then
                     failwith "bad message";
                   let out_msg =
                     "\001\000\000\000" ^ cs.cauthz in
                   let out_message =
                     [ Netxdr_mstring.string_to_mstring out_msg ] in
                   let out_msg_wrapped =
                     G.interface # wrap
                       ~context ~conf_req:false ~qop_req:0l
                       ~input_message:out_message
                       ~output_message_preferred_type:`Bytes
                       ~out:(fun ~conf_state ~output_message 
                                 ~minor_status ~major_status () ->
                               client_check_gssapi_status
                                 cs "wrap" major_status minor_status;
                               Netxdr_mstring.concat_mstrings output_message
                            )
                       () in
                   let cs =
                     { cs with
                       ctoken = out_msg_wrapped;
                       cstate = `Emit;
                       csubstate = `Established;
                     } in
                   client_del_ctx cs;   (* no longer needed *)
                 with
                   | Failure msg ->
                       let cs = client_del_ctx cs in
                       { cs with cstate = `Auth_error msg }
               )
          | `Established ->
               let cs = client_del_ctx cs in
               { cs with cstate = `Auth_error "unexpected token" }

    let client_emit_response cs =
      if cs.cstate <> `Emit then
        failwith "Netmech_krb5_sasl.client_emit_response: bad state";
      let cs = cvalidity cs in
      let cs =
        match cs.csubstate with
          | `Pre_init_context ->
              ( try
                  let cs = call_init_sec_context cs None in
                  { cs with cstate = `Wait }
                with
                  | Failure msg -> 
                      let cs = client_del_ctx cs in
                      { cs with cstate = `Auth_error msg }
              )
          | `Established ->
              let cs = client_del_ctx cs in   (* no longer needed *)
              { cs with cstate = `OK }
          | _ ->
              { cs with cstate = `Wait } in
      (cs, cs.ctoken)

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
        Marshal.to_string (cs.cauthz, 
                           map_opt Netsys_gssapi.marshal_client_props cs.cprops
                          ) []

    let cs_re = 
      Netstring_str.regexp "client,t=GSSAPI;"
           
    let client_resume_session s =
      match Netstring_str.string_match cs_re s 0 with
        | None ->
            failwith "Netmech_krb5_sasl.client_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (cauthz, mprops) = Marshal.from_string data 0 in
            { cauthz;
              ccontext = None;
              cstate = `OK;
              csubstate = `Established;
              ctoken = "";
              cconf = Netsys_gssapi.create_client_config();
              ctarget_name = G.interface # no_name;
              cprops = map_opt Netsys_gssapi.unmarshal_client_props mprops;
            }

  (*
#use "topfind";;
#require "netclient,netgss-system";;
Netpop.Debug.enable := true;;
let addr =
    `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "office1", 110),
            Uq_client.default_connect_options);;
let client = new Netpop.connect addr 60.0;;

module S = Netmech_krb5_sasl.Krb5_gs1(Netgss.System);;
module S = Netmech_krb5_sasl.Krb5_gs2(Netgss.System);;

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
          sstate : Netsys_sasl_types.server_state;
          ssubstate : server_sub_state;
          stoken : string;
          suser : string option;
          sauthz : string option;
          sconf : Netsys_gssapi.server_config;
          scred : G.credential;
          slookup : (string -> string -> credentials option);
          sservice : string;
          srealm : string option;
          sprops : Netsys_gssapi.server_props option;
        }


    let svalidity ss0 =
      let ss1 = { ss0 with scontext = ss0.scontext } in
      ss0.scontext <- None;
      ss1

    let server_state ss = ss.sstate

    let server_del_ctx ss =
      match ss.scontext with
        | None -> ss
        | Some ctx ->
            M.delete_context ss.scontext ();
            { ss with scontext = None }

    let server_check_gssapi_status ss fn_name major_status minor_status =
      try
        check_gssapi_status fn_name major_status minor_status
      with
        | error ->
            ignore(server_del_ctx ss);
            raise error

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
      let mutual_flag =
        try if List.assoc "mutual" params = "true" 
            then [`Mutual_flag, `Required] else []
        with Not_found -> [] in
      let sconf =
        Netsys_gssapi.create_server_config
          ~mech_types:[ krb5_oid ]
          ~acceptor_name:(sservice, Netsys_gssapi.nt_hostbased_service)
          ~privacy:`None
          ~integrity:`Required
          ~flags:( [`Integ_flag, `Required ] @ mutual_flag )
          () in
      let scred = 
        A.get_acceptor_cred ~acceptor_name:G.interface#no_name sconf in
      { scontext = None;
        sstate = `Wait;
        ssubstate = `Acc_context;
        stoken = "";
        suser = None;
        sauthz = None;
        slookup = lookup;
        sservice;
        srealm;
        scred;
        sconf;
        sprops = None
      }

    let server_configure_channel_binding ss cb_list =
      failwith "Netmech_krb5_sasl.Krb5_gs1.server_configure_channel_binding: \
                not supported"

    let server_context ss =
      match ss.scontext with
        | None -> assert false
        | Some c -> c


    let server_set_neg_security_token ss =
      (* we do not offer any security layer *)
      let context = server_context ss in
      let out_msg = "\001\000\000\000" in
      let out_message =
        [ Netxdr_mstring.string_to_mstring out_msg ] in
      let out_msg_wrapped =
        G.interface # wrap
          ~context ~conf_req:false ~qop_req:0l
          ~input_message:out_message
          ~output_message_preferred_type:`Bytes
          ~out:(fun ~conf_state ~output_message 
                    ~minor_status ~major_status () ->
                  server_check_gssapi_status
                    ss "wrap" major_status minor_status;
                  Netxdr_mstring.concat_mstrings output_message
               )
          () in
      { ss with stoken = out_msg_wrapped }


    let server_process_response_accept_context ss msg =
      let (out_context, out_token, ret_flags, props_opt) =
        A.accept_sec_context
          ~context:ss.scontext
          ~acceptor_cred:ss.scred
          ~input_token:msg
          ~chan_bindings:None
          ss.sconf in
      let ss =
        { ss with
          scontext = Some out_context;
          stoken = out_token;
          sprops = props_opt;
          sstate = `Emit;  (* even an empty token *)
        } in
      
      if props_opt <> None then (
        let src_name, targ_name =
          G.interface # inquire_context
            ~context:(server_context ss)
            ~out:(fun ~src_name ~targ_name ~lifetime_req ~mech_type ~ctx_flags
                      ~locally_initiated ~is_open ~minor_status ~major_status
                      ()  ->
                    server_check_gssapi_status
                      ss "inquire_context" major_status minor_status;
                    if mech_type <> krb5_oid then
                      failwith "the mechanism is not Kerberos 5";
                    src_name, targ_name
                 )
            () in
        try
          let (targ_disp_name, targ_disp_name_type) =
            A.get_display_name targ_name in
          let ok =
            Krb5_gs2_profile.server_check_target_name
              ~params:["gssapi-acceptor-service", ss.sservice]
              (targ_disp_name, targ_disp_name_type) in
          if not ok then
            failwith "unexpected target or decoding error";
          let (src_disp_name, src_disp_name_type) =
            A.get_display_name src_name in
          let n =
            try
              Krb5_gs2_profile.server_map_user_name
                ~params:( match ss.srealm with
                            | None -> []
                            | Some r -> ["realm", r]
                        )
                (src_disp_name,src_disp_name_type)
            with
              | Not_found ->
                  failwith "cannot parse client name" in
          let ss = { ss with suser = Some n } in
          if ss.stoken = "" then (
            let ss = server_set_neg_security_token ss in
            { ss with ssubstate = `Neg_security2 }
          )
          else
            { ss with ssubstate = `Neg_security1 }
        with error ->
          ignore(server_del_ctx ss);
          raise error
      )
      else ss
                                  

    let server_process_response_neg_security1 ss msg =
      (* any msg is acceptable *)
      let ss = server_set_neg_security_token ss in
      { ss with
        ssubstate = `Neg_security2;
        sstate = `Emit
      }
      
    let server_process_response_neg_security2 ss msg =
      let input_message = [ Netxdr_mstring.string_to_mstring msg ] in
      let context = server_context ss in
      let msg_unwrapped =
        G.interface # unwrap
          ~context ~input_message
          ~output_message_preferred_type:`Bytes
          ~out:(fun ~output_message ~conf_state ~qop_state
                    ~minor_status ~major_status () ->
                  server_check_gssapi_status
                    ss "unwrap" major_status minor_status;
                  Netxdr_mstring.concat_mstrings output_message
               )
          () in
      if String.length msg_unwrapped < 4 then
        failwith "bad security token";
      if String.sub msg_unwrapped 0 4 <> "\001\000\000\000" then
        failwith "bad security token";
      let authz =
        String.sub msg_unwrapped 4 (String.length msg_unwrapped - 4) in
      let ss = { ss with sauthz = Some authz } in
      let user =
        match ss.suser with
          | None -> raise Not_found
          | Some u -> u in
      let user_cred_opt =
        ss.slookup user authz in
      if user_cred_opt = None then
        failwith "unauthorized user";
      let ss = server_del_ctx ss in   (* no longer needed *)
      { ss with
        ssubstate = `Established;
        sstate = `OK
      }


    let server_process_response ss msg =
      let ss = svalidity ss in
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
        | Not_found ->
            let ss = server_del_ctx ss in
            { ss with sstate = `Auth_error "unspecified" }
        | Failure msg ->
            let ss = server_del_ctx ss in
            { ss with sstate = `Auth_error msg }


    let server_process_response_restart ss msg set_stale =
      failwith "Netmech_krb5_sasl.server_process_response_restart: \
                not available"

    let server_emit_challenge ss =
      if ss.sstate <> `Emit then
        failwith "Netmech_krb5_sasl.server_emit_challenge: bad state";
      ( { (svalidity ss) with sstate = `Wait },
        ss.stoken
      )

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
        Marshal.to_string (ss.suser, ss.sauthz,
                           ss.sservice, ss.srealm,
                           map_opt Netsys_gssapi.marshal_server_props ss.sprops
                          ) []

    let ss_re = 
      Netstring_str.regexp "server,t=GSSAPI;"
           

    let server_resume_session ~lookup s =
      match Netstring_str.string_match ss_re s 0 with
        | None ->
            failwith "Netmech_krb5_sasl.server_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (suser, sauthz, sservice, srealm, mprops) =
              Marshal.from_string data 0 in
            { scontext = None;
              sstate = `OK;
              ssubstate = `Established;
              stoken = "";
              suser;
              sauthz;
              slookup = lookup;
              sservice;
              srealm;
              scred = G.interface#no_credential;
              sconf = Netsys_gssapi.create_server_config();
              sprops = map_opt Netsys_gssapi.unmarshal_server_props mprops;
            }
              
 
    let server_session_id ss =
      None

    let server_prop ss key =
      raise Not_found

    let server_gssapi_props ss =
      match ss.sprops with
        | None -> raise Not_found
        | Some p -> p

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
module S = Netmech_krb5_sasl.Krb5_gs1(Netgss.System);;
let no_creds = S.init_credentials [];;
let cs = S.create_client_session ~user:"" ~authz:"foo" ~creds:no_creds ~params:[ "gssapi-acceptor", "test@office1.lan.sumadev.de", false ] ();;
let lookup user authz = eprintf "user=%S authz=%S\n%!" user authz; Some no_creds;;
let ss = S.create_server_session ~lookup ~params:["gssapi-acceptor-service", "test", false ] ();;

let cs, msg1 = S.client_emit_response cs;;
let ss = S.server_process_response ss msg1;;
let ss, msg2 = S.server_emit_challenge ss;;
let cs = S.client_process_challenge cs msg2;;
let cs, msg3 = S.client_emit_response cs;;
let ss = S.server_process_response ss msg3;;
let ss, msg4 = S.server_emit_challenge ss;;
let cs = S.client_process_challenge cs msg4;;
let cs, msg5 = S.client_emit_response cs;;
assert(S.client_state cs = `OK);;
let ss = S.server_process_response ss msg5;;
assert(S.server_state ss = `OK);;
 *)
