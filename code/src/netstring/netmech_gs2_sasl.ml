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
  end



module GS2(P:PROFILE)(G:Netsys_gssapi.GSSAPI) : 
         Netsys_sasl_types.SASL_MECHANISM =
  struct
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

    (* ------------------------ *)
    (*          Client          *)
    (* ------------------------ *)


    type client_sub_state =
        [ `Pre_init_context | `Init_context | `Established ]

    type client_session =
        { cuser : string;
          cauthz : string;
          mutable ccontext : G.context option;
          mutable cstate : Netsys_sasl_types.client_state;
          mutable csubstate : client_sub_state;
          mutable ctoken : string;
          cparams : (string * string) list;
          ctarget_name : G.name;
          cinit_name : G.name;
          ccred : G.credential;
          mutable ccb_data : string;
          mutable ccb : Netsys_gssapi.channel_bindings option;
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
      let flags1 = P.client_flags ~params:cs.cparams in
      let flags2 = List.map fst flags1 in
      G.interface # init_sec_context
         ~initiator_cred:cs.ccred
         ~context:cs.ccontext
         ~target_name:cs.ctarget_name
         ~mech_type:P.mechanism_oid
         ~req_flags:(`Mutual_flag  :: `Sequence_flag :: flags2)
         ~time_req:None
         ~chan_bindings:(Some(`Unspecified "", `Unspecified "", cs.ccb_data))
         ~input_token
         ~out:(fun ~actual_mech_type ~output_context ~output_token 
                   ~ret_flags ~time_rec ~minor_status ~major_status () -> 
                 let (_,_,suppl) = major_status in
                 let cont = List.mem `Continue_needed suppl in
                 check_gssapi_status
                   "init_sec_context" major_status minor_status;
                 assert(output_context <> None);
                 cs.ccontext <- output_context;
                 cs.ctoken <- output_token;
                 if not cont then (
                   if not(List.mem `Mutual_flag ret_flags) then
                     failwith "mutual authentication requested but not available";
                   List.iter
                     (fun (flag,req) ->
                        let flag = (flag :> Netsys_gssapi.ret_flag ) in
                        if req && not(List.mem flag ret_flags) then
                          failwith "required flag missing"
                     )
                     flags1;
                   cs.cstate <- `Emit;
                   cs.csubstate <- if output_token = "" then `Established 
                                   else`Init_context;
                 )
                 else (
(*
                   if suppl <> [ `Continue_needed ] then
                     failwith "bad supplemental state";
 *)
                   cs.cstate <- `Emit;
                   cs.csubstate <- `Init_context
                 )
              )
         ()

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
          "n,";   (* channel binding FIXME *)
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
      cs.ccb_data <-
        String.concat
          ""
          [ "n,";   (* FIXME *)
            ( if cs.cauthz = "" then
                ""
              else
                "a=" ^ Netgssapi_support.gs2_encode_saslname cs.cauthz
            );
            ",";
          (* plus: channel binding data *)
          ]
          
    let create_client_session ~user ~authz ~creds ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_client_session:"
          ([ "mutual"; "secure" ] @ P.client_additional_params)
          params in
      let (targ_name, target_name_type) = P.client_get_target_name ~params in
      let ctarget_name =
        if target_name_type = [| |] then
          G.interface # no_name
        else
          G.interface # import_name
            ~input_name:targ_name
            ~input_name_type:target_name_type
            ~out:(fun ~output_name ~minor_status ~major_status () ->
                    check_gssapi_status "import_name" major_status minor_status;
                    output_name
                 )
            () in
      let (init_name, init_name_type) = P.client_map_user_name ~params user in
      let cinit_name =
        if init_name_type = [| |] then
          G.interface # no_name
        else
          G.interface # import_name
            ~input_name:init_name
            ~input_name_type:init_name_type
            ~out:(fun ~output_name ~minor_status ~major_status () ->
                    check_gssapi_status "import_name" major_status minor_status;
                    output_name
                 )
            () in
      let ccred =
        G.interface # acquire_cred
          ~desired_name:cinit_name
          ~time_req:`Indefinite
          ~desired_mechs:[ P.mechanism_oid ]
          ~cred_usage:`Initiate
          ~out:(fun ~cred ~actual_mechs ~time_rec ~minor_status ~major_status
                    () ->
                  check_gssapi_status "acquire_cred" major_status minor_status;
                  cred
               )
          () in
      let cs =
        { cuser = user;
          cauthz = authz;
          ccontext = None;
          cstate = `Emit;
          csubstate = `Pre_init_context;
          ctoken = "";
          ctarget_name;
          cinit_name;
          ccred;
          cparams = params;
          ccb_data = "";
          ccb = None;
        } in
      client_create_cb_data cs;
      cs

    let client_configure_channel_binding cs cb =
      (* TODO *)
      if cb <> `None then
        failwith "Netmech_krb5_sasl.client_configure_channel_binding: \
                  not supported"
                 
    let client_state cs = cs.cstate
    let client_channel_binding cs = `None

    let client_restart cs =
      if cs.cstate <> `OK then
        failwith "Netmech_gs2_sasl.client_restart: unfinished auth";
      cs.ccontext <- None;
      cs.cstate <- `Emit;
      cs.csubstate <- `Pre_init_context;
      cs.ctoken <- ""

    let client_context cs =
      match cs.ccontext with
        | None -> failwith "client_context"
        | Some c -> c


    let client_process_challenge cs msg =
      if cs.cstate <> `Wait then
        cs.cstate <- `Auth_error "protocol error"
      else
        match cs.csubstate with
          | `Pre_init_context ->
              assert false
          | `Init_context ->
               ( try
                   call_init_sec_context cs (Some msg)
                 with
                   | Failure msg ->
                        cs.cstate <- `Auth_error msg
               )
          | `Established ->
               cs.cstate <- `Auth_error "unexpected challenge"

    let client_emit_response cs =
      if cs.cstate <> `Emit then
        failwith "Netmech_gs2_sasl.client_emit_response: bad state";
      ( match cs.csubstate with
          | `Pre_init_context ->
              ( try
                  call_init_sec_context cs None;
                  cs.cstate <- `Wait;
                  cs.ctoken <- client_rewrite_initial_token cs cs.ctoken;
                with
                  | Failure msg ->
                      cs.cstate <- `Auth_error msg
              )
          | `Init_context ->
              cs.cstate <- `Wait
          | `Established ->
              cs.cstate <- `OK
      );
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
        failwith "Netmech_gs5_sasl.client_stash_session: the session \
                  must be established (implementation restriction)";
      "client,t=GS2;" ^ 
        Marshal.to_string (cs.cuser, cs.cauthz, cs.cparams) []

    let cs_re = 
      Netstring_str.regexp "client,t=GS2;"
           
    let client_resume_session s =
      match Netstring_str.string_match cs_re s 0 with
        | None ->
            failwith "Netmech_gs2_sasl.client_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (cuser, cauthz, cparams) = Marshal.from_string data 0 in
            { cuser;
              cauthz;
              ccontext = None;
              cstate = `OK;
              csubstate = `Established;
              ctoken = "";
              cparams;
              ctarget_name = G.interface # no_name;
              cinit_name = G.interface # no_name;
              ccred = G.interface # no_credential;
              ccb_data = "";
              ccb = None;  (* FIXME *)
            }


    (* ------------------------ *)
    (*          Server          *)
    (* ------------------------ *)


    type server_sub_state =
        [ `Acc_context | `Skip_empty | `Established ]

    type server_session =
        { mutable scontext : G.context option;
          mutable sstate : Netsys_sasl_types.server_state;
          mutable ssubstate : server_sub_state;
          mutable stoken : string;
          mutable suser : string option;
          mutable sauthz : string option;
          mutable scb_data : string;
          scred : G.credential;
          slookup : (string -> string -> credentials option);
          sparams : (string * string) list;
        }


    let server_state ss = ss.sstate

    let create_server_session ~lookup ~params () =
      let params = 
        Netsys_sasl_util.preprocess_params
          "Netmech_krb5_sasl.create_server_session:"
          ( [ "mutual"; "secure" ] @ P.server_additional_params )
          params in
      let scred_name =
        match P.server_bind_target_name ~params with
          | None ->
              G.interface#no_name
          | Some(name,ty) ->
              G.interface # import_name
                ~input_name:name
                ~input_name_type:ty
                ~out:(fun ~output_name ~minor_status ~major_status () ->
                        check_gssapi_status 
                          "import_name" major_status minor_status;
                        output_name
                     )
                () in
      let scred =
        G.interface # acquire_cred
          ~desired_name:scred_name
          ~time_req:`Indefinite
          ~desired_mechs:[ P.mechanism_oid ]
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
        sparams = params;
        scred;
        scb_data = "";
      }

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
      ss.ssubstate <- `Established;
      ss.sstate <- `OK


    let server_create_cb_data ss authz =
      (* RFC 5801, section 5.1 *)
      ss.scb_data <-
        String.concat
          ""
          [ "n,";   (* FIXME *)
            ( if authz = "" then
                ""
              else
                "a=" ^ Netgssapi_support.gs2_encode_saslname authz
            );
            ",";
          (* plus: channel binding data *)
          ]


    let server_process_response_accept_context ss msg =
      let flags = P.server_flags ~params:ss.sparams in
      let cont =
        G.interface # accept_sec_context
          ~context:ss.scontext
          ~acceptor_cred:ss.scred
          ~input_token:msg
          ~chan_bindings:(Some(`Unspecified "", `Unspecified "", ss.scb_data))
          ~out:(fun ~src_name ~mech_type ~output_context ~output_token
                    ~ret_flags ~time_rec ~delegated_cred 
                    ~minor_status ~major_status () ->
                   check_gssapi_status
                     "accept_sec_context" major_status minor_status;
                   assert(output_context <> None);
                   let (_,_,suppl) = major_status in
                   ss.scontext <- output_context;
                   ss.stoken <- output_token;
                   if suppl = [] then (
                     if not(List.mem `Mutual_flag ret_flags) then
                       failwith "mutual auth requested but not available";
                     List.iter
                       (fun flag ->
                          let flag = (flag :> Netsys_gssapi.ret_flag ) in
                          if not(List.mem flag ret_flags) then
                            failwith "missing flag";
                       )
                       flags;
                   ) else (
                     if suppl <> [ `Continue_needed ] then
                       failwith "unexpected supplemental flags";
                   );
                   suppl <> []
               )
          () in
      if cont then
        ss.sstate <- `Emit
      else (
        let src_name, targ_name =
          G.interface # inquire_context
            ~context:(server_context ss)
            ~out:(fun ~src_name ~targ_name ~lifetime_req ~mech_type ~ctx_flags
                      ~locally_initiated ~is_open ~minor_status ~major_status
                      ()  ->
                    check_gssapi_status
                      "inquire_context" major_status minor_status;
                    if mech_type <> P.mechanism_oid then
                      failwith "the mechanism is not the selected one";
                    src_name, targ_name
                 )
            () in
        G.interface # display_name
          ~input_name:targ_name
          ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status
                    () ->
                  check_gssapi_status
                    "display_name" major_status minor_status;
                  let ok =
                    P.server_check_target_name
                      ~params:ss.sparams (output_name,output_name_type) in
                  if not ok then
                    failwith "target name check not passed";
               )
          ();
        G.interface # display_name
          ~input_name:src_name
          ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status
                    () ->
                  check_gssapi_status
                    "display_name" major_status minor_status;
                  let user =
                    try
                      P.server_map_user_name
                        ~params:ss.sparams (output_name,output_name_type)
                    with
                      | Not_found -> failwith "user name not acceptable" in
                  ss.suser <- Some user;
               )
          ();
        if ss.stoken = "" then
          server_finish ss
        else (
          ss.ssubstate <- `Skip_empty;
          ss.sstate <- `Emit
        )
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
            if cb_str <> "n" then (
              if P.announce_channel_binding then (
                if cb_str = "y" then failwith "misconfigured channel binding";
                (* TODO: do something with it *)
              )
              else (
                if cb_str <> "y" then 
                  failwith "client requests channel binding but this is \
                            unavailable"
              )
            );
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
            (token2, authz)
        | None ->
            failwith "bad initial token"



    let server_process_response ss msg =
      try
        if ss.sstate <> `Wait then raise Not_found;
        match ss.ssubstate with
          | `Acc_context ->
              if ss.scontext = None then (
                let (msg1, authz) = server_rewrite_initial_token ss msg in
                ss.sauthz <- Some authz;
                server_create_cb_data ss authz;
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
            ss.sstate <- `Auth_error "unspecified"
        | Failure msg ->
            ss.sstate <- `Auth_error msg


    let server_process_response_restart ss msg set_stale =
      failwith "Netmech_gs2_sasl.server_process_response_restart: \
                not available"

    let server_emit_challenge ss =
      if ss.sstate <> `Emit then
        failwith "Netmech_gs2_sasl.server_emit_challenge: bad state";
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
        failwith "Netmech_gs2_sasl.server_stash_session: the session \
                  must be established (implementation restriction)";
      "server,t=GS2;" ^ 
        Marshal.to_string (ss.suser, ss.sauthz, ss.sparams) []

    let ss_re = 
      Netstring_str.regexp "server,t=GS2;"
           

    let server_resume_session ~lookup s =
      match Netstring_str.string_match ss_re s 0 with
        | None ->
            failwith "Netmech_gs2_sasl.server_resume_session"
        | Some m ->
            let p = Netstring_str.match_end m in
            let data = String.sub s p (String.length s - p) in
            let (suser, sauthz, sparams) =
              Marshal.from_string data 0 in
            { scontext = None;
              sstate = `OK;
              ssubstate = `Established;
              stoken = "";
              suser;
              sauthz;
              slookup = lookup;
              sparams;
              scred = G.interface#no_credential;
              scb_data = ""
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
module S = Netmech_krb5_sasl.Krb5_gs2(Netgss.System);;
let no_creds = S.init_credentials [];;
let cs = S.create_client_session ~user:"" ~authz:"foo" ~creds:no_creds ~params:[ "gssapi-acceptor", "test@office1.lan.sumadev.de", false ] ();;
let lookup user authz = eprintf "user=%S authz=%S\n%!" user authz; Some no_creds;;
let ss = S.create_server_session ~lookup ~params:["gssapi-acceptor-service", "test", false ] ();;

let msg1 = S.client_emit_response cs;;
S.server_process_response ss msg1;;
let msg2 = S.server_emit_challenge ss;;
S.client_process_challenge cs msg2;;
let msg3 = S.client_emit_response cs;;
assert(S.client_state cs = `OK);;
S.server_process_response ss msg3;;
assert(S.server_state ss = `OK);;
 *)
