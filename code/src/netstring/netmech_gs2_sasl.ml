(* $Id$ *)

open Printf

module type PROFILE =
  sig
    val mechanism_name : string
    val announce_channel_binding : bool
    val mechanism_oid : Netsys_gssapi.oid
    val client_additional_params : string list
    val server_additional_params : string list
    val client_map_user_name : 
           params:(string * string) list ->
           string -> 
             string * Netsys_gssapi.oid
    val server_map_user_name : 
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) ->
             string
    val client_get_target_name :
           params:(string * string) list ->
             (string * Netsys_gssapi.oid)
    val server_bind_target_name :
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) option
    val server_check_target_name :
           params:(string * string) list ->
           (string * Netsys_gssapi.oid) ->
             bool
    val client_flags :
           params:(string * string) list ->
           ( Netsys_gssapi.req_flag * bool ) list
    val server_flags :
           params:(string * string) list ->
           Netsys_gssapi.req_flag list
    val client_credential : exn option
  end



module GS2(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : 
         Netsys_sasl_types.SASL_MECHANISM =
  struct
    module M = Netgssapi_auth.Manage(G)
    module C = struct
      let raise_error msg =
        failwith msg
    end
    module A = Netgssapi_auth.Auth(G)(C)

    let mechanism_name = 
      P.mechanism_name ^ (if P.announce_channel_binding then "-PLUS" else "")
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

    let map_opt f =
      function
      | None -> None
      | Some x -> Some(f x)

    (* ------------------------ *)
    (*          Client          *)
    (* ------------------------ *)


    type client_sub_state =
        [ `Pre_init_context | `Init_context | `Established ]

    type client_session =
        { mutable ccontext : G.context option;
          cuser : string;
          cauthz : string;
          cstate : Netsys_sasl_types.client_state;
          csubstate : client_sub_state;
          ctoken : string;
          cparams : (string * string) list;
          cconf : Netsys_gssapi.client_config;
          ctarget_name : G.name;
          ccred : G.credential;
          ccb_data : string;
          ccb : Netsys_sasl_types.cb;
          cprops : Netsys_gssapi.client_props option;
        }

    let client_state cs = cs.cstate

    let cvalidity cs0 =
      let cs1 = { cs0 with ccontext = cs0.ccontext } in
      cs0.ccontext <- None;
      cs1

    let client_del_ctx cs =
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

    let call_init_sec_context cs input_token =
      let (out_context, out_token, ret_flags, props_opt) =
        A.init_sec_context
          ~initiator_cred:cs.ccred
          ~context:cs.ccontext
          ~target_name:cs.ctarget_name
          ~req_flags:(A.get_client_flags cs.cconf)
          ~chan_bindings:(Some(`Unspecified "", `Unspecified "", cs.ccb_data))
          ~input_token
          cs.cconf in
      { cs with
        ccontext = Some out_context;
        ctoken = out_token;
        cprops = props_opt;
        cstate = `Emit;
        csubstate = 
          ( if props_opt = None then
              `Init_context
            else 
              if out_token = "" then `Established 
              else`Init_context
          )
      }

    let client_cb_string cs =
      match cs.ccb with
        | `None -> "n,"
        | `SASL_none_but_advertise -> "y,"
        | `SASL_require(ty,data) -> "p=" ^ ty ^ ","
        | `GSSAPI _ ->
            failwith "GSSAPI channel binding not supported"


    let client_rewrite_initial_token cs token =
      let (non_std, token_no_header) =
        try
          let p = ref 0 in
          let (_,token') = Netgssapi_support.wire_decode_token token p in
          if !p <> String.length token then failwith "bad token";
          (false, token')
        with
          | Failure _ ->
              (true, token) in
      String.concat
        ""
        [ if non_std then "F," else "";
          client_cb_string cs;
          ( if cs.cauthz = "" then
              ""
            else
              "a=" ^ Netgssapi_support.gs2_encode_saslname cs.cauthz
          );
          ",";
          token_no_header
        ]

    let client_create_cb_data cs =
      (* RFC 5801, section 5.1 *)
      { cs with
        ccb_data =
          String.concat
            ""
            [ client_cb_string cs;
              ( if cs.cauthz = "" then
                  ""
                else
                  "a=" ^ Netgssapi_support.gs2_encode_saslname cs.cauthz
              );
              ",";
              ( match cs.ccb with
                  | `SASL_require(_,data) -> data
                  | _ -> ""
              )
            ]
      }
          
    let create_client_session ~user ~authz ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          ([ "mutual"; "secure" ] @ P.client_additional_params)
          params in

      let (targ_name, target_name_type) = P.client_get_target_name ~params in
      let (init_name, init_name_type) = P.client_map_user_name ~params user in
      let flags =
        List.map
          (fun (flag, is_required) ->
             (flag, (if is_required then `Required else `If_possible))
          )
          (P.client_flags ~params) 
          @ [ `Mutual_flag, `Required ]
          @ [ `Sequence_flag, `If_possible ] in
      let integrity =
        try List.assoc `Integ_flag flags with Not_found -> `None in
      let privacy =
        try List.assoc `Conf_flag flags with Not_found -> `None in
      let cconf =
        Netsys_gssapi.create_client_config
          ~mech_type:P.mechanism_oid
          ?initiator_name:(if init_name_type = [| |] then
                             None
                           else
                             Some(init_name,init_name_type))
          ?initiator_cred:P.client_credential
          ?target_name:(if target_name_type = [| |] then
                          None
                        else
                          Some(targ_name, target_name_type))
          ~flags
          ~privacy
          ~integrity
          () in
      let initiator_name = A.get_initiator_name cconf in
      let ccred = A.get_initiator_cred ~initiator_name cconf in
      let ctarget_name = A.get_target_name cconf in
      let cs =
        { cuser = user;
          cauthz = authz;
          ccontext = None;
          cstate = `Emit;
          csubstate = `Pre_init_context;
          ctoken = "";
          cconf;
          ctarget_name;
          ccred;
          cparams = params;
          ccb_data = "";
          ccb = `None;
          cprops = None;
        } in
      let cs = client_create_cb_data cs in
      cs

    let client_configure_channel_binding cs cb =
      { (cvalidity cs) with ccb = cb }
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = cs.ccb

    let client_restart cs =
      if cs.cstate <> `OK then
        failwith "Netmech_gs2_sasl.client_restart: unfinished auth";
      { (cvalidity cs) with
        ccontext = None;
        cstate = `Emit;
        csubstate = `Pre_init_context;
        ctoken = "";
      }

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs msg =
      let cs = cvalidity cs in
      if cs.cstate <> `Wait then
        { cs with cstate = `Auth_error "protocol error" }
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
          | `Established ->
               let cs = client_del_ctx cs in
               { cs with cstate = `Auth_error "unexpected challenge" }

    let client_emit_response cs =
      let cs = cvalidity cs in
      if cs.cstate <> `Emit then
        failwith "Netmech_gs2_sasl.client_emit_response: bad state";
      let cs =
        match cs.csubstate with
          | `Pre_init_context ->
              ( try
                  let cs = call_init_sec_context cs None in
                  { cs with
                    cstate = `Wait;
                    ctoken = client_rewrite_initial_token cs cs.ctoken;
                  }
                with
                  | Failure msg ->
                      let cs = client_del_ctx cs in
                      { cs with cstate = `Auth_error msg }
              )
          | `Init_context ->
              { cs with cstate = `Wait }
          | `Established ->
              let cs = client_del_ctx cs in  (* no longer needed *)
              { cs with cstate = `OK } in
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
        failwith "Netmech_gs5_sasl.client_stash_session: the session \
                  must be established (implementation restriction)";
      "client,t=GS2;" ^ 
        Marshal.to_string (cs.cuser, cs.cauthz, cs.cparams, cs.ccb,
                           map_opt Netsys_gssapi.marshal_client_props cs.cprops)
                          []

    let cs_re = 
      Netstring_str.regexp "client,t=GS2;"
           
    let client_resume_session s =
      match Netstring_str.string_match cs_re s 0 with
        | None ->
            failwith "Netmech_gs2_sasl.client_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (cuser, cauthz, cparams, ccb, mprops) =
              Marshal.from_string data 0 in
            { cuser;
              cauthz;
              ccontext = None;
              cstate = `OK;
              csubstate = `Established;
              ctoken = "";
              cparams;
              cconf = Netsys_gssapi.create_client_config();
              ctarget_name = G.interface # no_name;
              ccred = G.interface # no_credential;
              ccb_data = "";
              ccb;
              cprops = map_opt Netsys_gssapi.unmarshal_client_props mprops;
            }


    (* ------------------------ *)
    (*          Server          *)
    (* ------------------------ *)


    type server_sub_state =
        [ `Acc_context | `Skip_empty | `Established ]

    type server_session =
        { mutable scontext : G.context option;
          sstate : Netsys_sasl_types.server_state;
          ssubstate : server_sub_state;
          stoken : string;
          suser : string option;
          sauthz : string option;
          scb_data : string;
          sconf : Netsys_gssapi.server_config;
          scred : G.credential;
          slookup : (string -> string -> credentials option);
          sparams : (string * string) list;
          scb : (string * string) list;
          sprops : Netsys_gssapi.server_props option;
        }


    let svalidity ss0 =
      let ss1 = { ss0 with scontext = ss0.scontext } in
      ss0.scontext <- None;
      ss1

    let server_state ss = ss.sstate

    let server_del_ctx ss =
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
          ( [ "mutual"; "secure" ] @ P.server_additional_params )
          params in

      let flags =
        List.map
          (fun (flag, is_required) ->
             (flag, (if is_required then `Required else `If_possible))
          )
          (P.client_flags ~params) 
          @ [ `Mutual_flag, `Required ]
          @ [ `Sequence_flag, `If_possible ] in
      let integrity =
        try List.assoc `Integ_flag flags with Not_found -> `None in
      let privacy =
        try List.assoc `Conf_flag flags with Not_found -> `None in
      let sconf =
        Netsys_gssapi.create_server_config
          ~mech_types:[ P.mechanism_oid ]
          ?acceptor_name:(P.server_bind_target_name ~params)
          ~flags
          ~integrity
          ~privacy
          () in
      let scred_name = A.get_acceptor_name sconf in
      let scred = A.get_acceptor_cred ~acceptor_name:scred_name sconf in
      { scontext = None;
        sstate = `Wait;
        ssubstate = `Acc_context;
        stoken = "";
        suser = None;
        sauthz = None;
        slookup = lookup;
        sparams = params;
        sconf;
        scred;
        scb_data = "";
        scb = [];
        sprops = None;
      }

    let server_configure_channel_binding ss l =
      { (svalidity ss) with scb = l  }

    let server_context ss =
      match ss.scontext with
        | None -> assert false
        | Some c -> c


    let server_finish ss =
      let user =
        match ss.suser with
          | None -> raise Not_found
          | Some u -> u in
      let authz =
        match ss.sauthz with
          | None -> raise Not_found
          | Some a -> a in
      let user_cred_opt =
        ss.slookup user authz in
      if user_cred_opt = None then
        failwith "unauthorized user";
      let ss = server_del_ctx ss in   (* no longer needed *)
      { ss with
        ssubstate = `Established;
        sstate = `OK
      }


    let server_create_cb_data ss authz cb =
      (* RFC 5801, section 5.1 *)
      { ss with
        scb_data =
          String.concat
            ""
            [ ( match cb with
                  | `None -> "n,"
                  | `SASL_none_but_advertise -> "y,"
                  | `SASL_require(ty,_) -> "p=" ^ ty ^ ","
                  | `GSSAPI _ -> assert false
              );
              ( if authz = "" then
                  ""
                else
                  "a=" ^ Netgssapi_support.gs2_encode_saslname authz
              );
              ",";
              ( match cb with
                  | `SASL_require(_,data) -> data
                  | _ -> ""
              )
            ]
      }

    let server_process_response_accept_context ss msg =
      let (out_context, out_token, ret_flags, props_opt) =
        A.accept_sec_context
          ~context:ss.scontext
          ~acceptor_cred:ss.scred
          ~input_token:msg
          ~chan_bindings:(Some(`Unspecified "", `Unspecified "", ss.scb_data))
          ss.sconf in
      let ss =
        svalidity
          { ss with
            scontext = Some out_context;
            stoken = out_token;
          } in
      if props_opt = None then
        { ss with sstate = `Emit }
      else (
        let ss =
          { ss with sprops = props_opt } in
        let src_name, targ_name =
          G.interface # inquire_context
            ~context:(server_context ss)
            ~out:(fun ~src_name ~targ_name ~lifetime_req ~mech_type ~ctx_flags
                      ~locally_initiated ~is_open ~minor_status ~major_status
                      ()  ->
                    server_check_gssapi_status
                      ss "inquire_context" major_status minor_status;
                    if mech_type <> P.mechanism_oid then
                      failwith "the mechanism is not the selected one";
                    src_name, targ_name
                 )
            () in
        try
          let (targ_disp_name, targ_disp_name_type) =
            A.get_display_name targ_name in
          let ok =
            P.server_check_target_name
              ~params:ss.sparams (targ_disp_name,targ_disp_name_type) in
          if not ok then
            failwith "target name check not passed";
          let (src_disp_name, src_disp_name_type) =
            A.get_display_name src_name in
          let user =
            try
              P.server_map_user_name
                ~params:ss.sparams (src_disp_name,src_disp_name_type)
            with
              | Not_found -> failwith "user name not acceptable" in
          let ss = { ss with suser = Some user } in

          if ss.stoken = "" then
            server_finish ss
          else (
            { ss with
              ssubstate = `Skip_empty;
              sstate = `Emit
            }
          )
        with
          | error ->
              ignore(server_del_ctx ss);
              raise error
      )


    let itoken_re =
      Netstring_str.regexp "\\(F,\\)?\
                            \\(p=[-a-zA-Z0-9.]*\\|n\\|y\\),\
                            \\(a=[^,]*\\)?,"

    let server_rewrite_initial_token ss token =
      match Netstring_str.string_match itoken_re token 0 with
        | Some m ->
            let is_non_std =
              try Netstring_str.matched_group m 1 token <> "" 
              with Not_found -> false in
            let cb_str = Netstring_str.matched_group m 2 token in
            let cb =
              if cb_str = "n" then (
                if P.announce_channel_binding then
                  failwith "no channel binding from client";
                `None
              ) else
                if cb_str = "y" then (
                  if P.announce_channel_binding then
                    failwith "no channel binding from client";
                  `SASL_none_but_advertise
                )
                else (
                  assert (cb_str.[0] = 'p');
                  if not P.announce_channel_binding then
                    failwith "client requires channel binding";
                  let ty = String.sub cb_str 2 (String.length cb_str - 2) in
                  let data =
                    try List.assoc ty ss.scb
                    with Not_found ->
                      failwith "unsupported type of channel binding" in
                  `SASL_require(ty, data)
                ) in
            let a_str =
              try 
                let s = Netstring_str.matched_group m 3 token in
                String.sub s 2 (String.length s - 2)
              with Not_found -> "" in
            let authz = Netgssapi_support.gs2_decode_saslname a_str in
            let p = Netstring_str.match_end m in
            let token1 = String.sub token p (String.length token - p) in
            let token2 = 
              if is_non_std then
                token1
              else
                Netgssapi_support.wire_encode_token P.mechanism_oid token1 in
            (token2, authz, cb)
        | None ->
            failwith "bad initial token"



    let server_process_response ss msg =
      let ss = svalidity ss in
      try
        if ss.sstate <> `Wait then raise Not_found;
        match ss.ssubstate with
          | `Acc_context ->
              if ss.scontext = None then (
                let (msg1, authz, cb) = server_rewrite_initial_token ss msg in
                let ss = { ss with sauthz = Some authz } in
                let ss = server_create_cb_data ss authz cb in
                server_process_response_accept_context ss msg1
              )
              else
                server_process_response_accept_context ss msg
          | `Skip_empty ->
              server_finish ss
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
      failwith "Netmech_gs2_sasl.server_process_response_restart: \
                not available"

    let server_emit_challenge ss =
      if ss.sstate <> `Emit then
        failwith "Netmech_gs2_sasl.server_emit_challenge: bad state";
      let ss = { (svalidity ss) with sstate =  `Wait } in
      (ss, ss.stoken)

    let server_channel_binding ss =
      `None

    let server_stash_session ss =
      (* GSSAPI does not support that unfinished contexts are exported.
         We do not need the context anyway after session establishment,
         so we don't save it at all.
       *)
      if ss.sstate <> `OK then
        failwith "Netmech_gs2_sasl.server_stash_session: the session \
                  must be established (implementation restriction)";
      "server,t=GS2;" ^ 
        Marshal.to_string (ss.suser, ss.sauthz, ss.sparams, ss.scb,
                           map_opt Netsys_gssapi.marshal_server_props ss.sprops)
                          []

    let ss_re = 
      Netstring_str.regexp "server,t=GS2;"
           

    let server_resume_session ~lookup s =
      match Netstring_str.string_match ss_re s 0 with
        | None ->
            failwith "Netmech_gs2_sasl.server_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (suser, sauthz, sparams, scb, mprops) =
              Marshal.from_string data 0 in
            { scontext = None;
              sstate = `OK;
              ssubstate = `Established;
              stoken = "";
              suser;
              sauthz;
              slookup = lookup;
              sparams;
              sconf = Netsys_gssapi.create_server_config();
              scred = G.interface#no_credential;
              scb_data = "";
              scb;
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

ktadmin
>  addprinc -randkey test/office1.lan.sumadev.de
>  ktadd -k test.keytab test/office1.lan.sumadev.de

KRB5_KTNAME=test.keytab OCAMLPATH=src ledit ocaml
#use "topfind";;
#require "netstring,netgss-system";;
open Printf;;
module S = Netmech_krb5_sasl.Krb5_gs2(Netgss.System);;
let no_creds = S.init_credentials [];;
let cs = S.create_client_session ~user:"" ~authz:"foo" ~creds:no_creds ~params:[ "gssapi-acceptor", "test@office1.lan.sumadev.de", false ] ();;
let lookup user authz = eprintf "user=%S authz=%S\n%!" user authz; Some no_creds;;
let ss = S.create_server_session ~lookup ~params:["gssapi-acceptor-service", "test", false ] ();;

let cs, msg1 = S.client_emit_response cs;;
let ss = S.server_process_response ss msg1;;
let ss, msg2 = S.server_emit_challenge ss;;
let cs = S.client_process_challenge cs msg2;;
let cs, msg3 = S.client_emit_response cs;;
assert(S.client_state cs = `OK);;
let ss = S.server_process_response ss msg3;;
assert(S.server_state ss = `OK);;
 *)
