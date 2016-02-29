(* $Id$ *)

module type CONFIG = sig
    val raise_error : string -> 'a
end

module Manage(G:Netsys_gssapi.GSSAPI) = struct
  let delete_context ctx_opt () =
    match ctx_opt with
      | None -> ()
      | Some ctx ->
          G.interface # delete_sec_context
            ~context:ctx
            ~out:(fun ~minor_status ~major_status () -> ())
            ()

  let format_status ?fn ?minor_status 
                    ((calling_error,routine_error,_) as major_status) =
    if calling_error <> `None || routine_error <> `None then (
        let error = Netsys_gssapi.string_of_major_status major_status in
        let minor_s =
          match minor_status with
            | None -> ""
            | Some n ->
                G.interface # display_minor_status
                  ~mech_type:[||]
                  ~status_value:n
                  ~out:(fun ~status_strings ~minor_status ~major_status () ->
                          " (details: " ^ 
                            String.concat "; " status_strings ^ ")"
                       )
                  () in
        let s1 =
          match fn with
            | None -> ""
            | Some n -> " for " ^ n in
        "GSSAPI error" ^ s1 ^ ": " ^ error ^ minor_s
    )
    else
      let s1 =
        match fn with
          | None -> ""
          | Some n -> " " ^ n in
      "GSSAPI call" ^ s1 ^ " is successful"

end


module Auth (G:Netsys_gssapi.GSSAPI)(C:CONFIG) = struct
  module M = Manage(G)

  let check_status ?fn ?minor_status
                   ((calling_error,routine_error,_) as major_status) =
    if calling_error <> `None || routine_error <> `None then
      C.raise_error(M.format_status ?fn ?minor_status major_status)


  let get_initiator_name (config:Netsys_gssapi.client_config) =
    match config#initiator_name with
      | None -> G.interface # no_name  (* means: default credential *)
      | Some(cred_string, cred_name_type) ->
          G.interface # import_name
             ~input_name:cred_string
             ~input_name_type:cred_name_type
             ~out:(fun ~output_name ~minor_status ~major_status () ->
                     check_status ~fn:"import_name" ~minor_status major_status;
                     output_name
                  )
             () 

  let get_acceptor_name (config:Netsys_gssapi.server_config) =
    match config#acceptor_name with
      | None -> G.interface # no_name  (* means: default credential *)
      | Some(cred_string, cred_name_type) ->
          G.interface # import_name
             ~input_name:cred_string
             ~input_name_type:cred_name_type
             ~out:(fun ~output_name ~minor_status ~major_status () ->
                     check_status ~fn:"import_name" ~minor_status major_status;
                     output_name
                  )
             () 

  let acquire_initiator_cred ~initiator_name 
                             (config:Netsys_gssapi.client_config) =
    let mech_type = config#mech_type in
    G.interface # acquire_cred
      ~desired_name:initiator_name
      ~time_req:`Indefinite
      ~desired_mechs:(if mech_type = [| |] then [] else [mech_type])
      ~cred_usage:`Initiate
      ~out:(fun ~cred ~actual_mechs ~time_rec ~minor_status
                ~major_status () ->
              check_status ~fn:"acquire_cred" ~minor_status major_status;
              cred
           )
      () 

  let get_initiator_cred ~initiator_name (config:Netsys_gssapi.client_config) =
    (* let mech_type = config#mech_type in *)
    match config#initiator_cred with
      | Some(G.Credential cred) ->
          (* Check that this is the cred for init_name *)
          if not(G.interface # is_no_name initiator_name) then (
            G.interface # inquire_cred
              ~cred
              ~out:(fun ~name ~lifetime ~cred_usage ~mechanisms
                        ~minor_status ~major_status () ->
                      check_status ~fn:"inquire_cred" 
                                   ~minor_status major_status;
                      G.interface # compare_name
                        ~name1:name ~name2:initiator_name
                        ~out:(fun ~name_equal ~minor_status ~major_status
                                   () ->
                                check_status ~fn:"compare_name"
                                             ~minor_status
                                             major_status;
                                if not name_equal then
                                  C.raise_error "The user name does not \
                                                 match the credential"
                             )
                        ()
                   )
              ()
              );
          cred
      | _ ->
          acquire_initiator_cred ~initiator_name config

  let get_acceptor_cred ~acceptor_name (config:Netsys_gssapi.server_config) =
    G.interface # acquire_cred
       ~desired_name:acceptor_name
       ~time_req:`Indefinite
       ~desired_mechs:config#mech_types
       ~cred_usage:`Accept
       ~out:(fun ~cred ~actual_mechs ~time_rec ~minor_status
                 ~major_status () ->
               check_status ~fn:"acquire_cred" ~minor_status major_status;
               cred
            )
       () 

  let get_target_name ?default (config:Netsys_gssapi.client_config) =
    if config#target_name=None && default=None then
      G.interface#no_name
    else
      let (name_string, name_type) =
        match config#target_name with
          | Some(n,t) -> (n,t)
          | None ->
              ( match default with
                  | None -> assert false
                  | Some(n,t) -> (n,t)
              ) in
      G.interface # import_name
        ~input_name:name_string
        ~input_name_type:name_type
        ~out:(fun ~output_name ~minor_status ~major_status () ->
                check_status ~fn:"import_name" ~minor_status major_status;
                output_name
             )
        () 

  let get_client_flags config =
    let flags1 =
      [ `Conf_flag, config#privacy;
        `Integ_flag, config#integrity
      ] @ config#flags in
    List.map fst
      (List.filter (fun (n,lev) -> lev <> `None) flags1)

  let get_server_flags = get_client_flags

  type t1 =
      < flags : (Netsys_gssapi.ret_flag * Netsys_gssapi.support_level) list;
        integrity : Netsys_gssapi.support_level;
        privacy : Netsys_gssapi.support_level;
      >

  let check_flags (config : t1) act_flags =
    let flags1 =
      [ `Conf_flag, config#privacy;
        `Integ_flag, config#integrity
      ] @ config#flags in
    let needed =
      List.map fst
        (List.filter (fun (n,lev) -> lev = `Required) flags1) in
    let missing =
      List.filter
        (fun flag ->
           not (List.mem flag act_flags)
        )
        needed in
    if missing <> [] then
      C.raise_error ("GSSAPI error: the security mechanism could not \
                      grant the following required context flags: " ^ 
                       String.concat ", " 
                         (List.map Netsys_gssapi.string_of_flag missing))

  let check_client_flags config act_flags =
    check_flags (config :> t1) act_flags

  let check_server_flags config act_flags =
    check_flags (config :> t1) act_flags

  let get_display_name name =
    G.interface # display_name
       ~input_name:name
       ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status () ->
               check_status ~fn:"display_name" ~minor_status major_status;
               output_name, output_name_type
            )
       ()

  let get_exported_name name =
    G.interface # export_name
       ~name:name
       ~out:(fun ~exported_name ~minor_status ~major_status () ->
               check_status ~fn:"export_name" ~minor_status major_status;
               exported_name
            )
       ()

  let init_sec_context ~initiator_cred ~context ~target_name ~req_flags
                       ~chan_bindings ~input_token config =
    let mech_type = config#mech_type in
    G.interface # init_sec_context
      ~initiator_cred
      ~context
      ~target_name
      ~mech_type
      ~req_flags
      ~time_req:None
      ~chan_bindings
      ~input_token
      ~out:(fun ~actual_mech_type ~output_context ~output_token 
                ~ret_flags ~time_rec ~minor_status ~major_status () -> 
              try
                check_status ~fn:"init_sec_context" ~minor_status major_status;
                let ctx =
                  match output_context with
                    | None -> assert false
                    | Some ctx -> ctx in
                let (_,_,suppl) = major_status in
                let cont_flag = List.mem `Continue_needed suppl in
                if cont_flag then (
                  assert(output_token <> "");
                  (ctx, output_token, ret_flags, None)
                )
                else (
                  check_client_flags config ret_flags;
                  let props =
                    ( object
                        method mech_type = actual_mech_type
                        method flags = ret_flags
                        method time = time_rec
                      end
                    ) in
                  (ctx, output_token, ret_flags, Some props)
                )
              with
                | error ->
                    M.delete_context output_context ();
                    raise error
           )
      ()

  let accept_sec_context ~acceptor_cred ~context ~chan_bindings ~input_token
                         config =
    G.interface # accept_sec_context
      ~context
      ~acceptor_cred
      ~input_token
      ~chan_bindings
      ~out:(fun ~src_name ~mech_type ~output_context ~output_token
                ~ret_flags ~time_rec ~delegated_cred 
                ~minor_status ~major_status () ->
              try
                check_status ~fn:"accept_sec_context" ~minor_status major_status;
                let ctx =
                  match output_context with
                    | None -> assert false
                    | Some ctx -> ctx in
                let (_,_,suppl) = major_status in
                let cont_flag = List.mem `Continue_needed suppl in
                if cont_flag then (
                  assert(output_token <> "");
                  (ctx, output_token, ret_flags, None)
                )
                else (
                  check_server_flags config ret_flags;
                  let (props : Netsys_gssapi.server_props) =
                    ( object
                        method mech_type = mech_type
                        method flags = ret_flags
                        method time = time_rec
                        method initiator_name =
                          get_display_name src_name
                        method initiator_name_exported =
                          get_exported_name src_name
                        method deleg_credential =
                          if List.mem `Deleg_flag ret_flags then
                            let t =
                              G.interface # inquire_cred
                                ~cred:delegated_cred
                                ~out:(fun ~name ~lifetime ~cred_usage
                                          ~mechanisms
                                          ~minor_status ~major_status () ->
                                        check_status ~fn:"inquire_cred"
                                                     ~minor_status major_status;
                                        lifetime
                                     )
                                () in
                            Some(G.Credential delegated_cred, t)
                          else
                            None
                      end
                    ) in
                  (ctx, output_token, ret_flags, Some props)
                )
              with
                | error ->
                    M.delete_context output_context ();
                    raise error
           )
      ()

end

  
