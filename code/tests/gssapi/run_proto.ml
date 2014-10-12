(* This test is client and server in once: We instantiate a client
   context and a server context, and try to run the protocol.

   REQUIREMENTS:

   We expect that the system is set up so that the client can use
   the default credentials. The server can use the host principal.
   You can e.g. achieve this by configuring Kerberos so that at least
   one host protocol is offered by the system (e.g. login via sshd
   and GSSAPI authentication). Also, the user must be logged in
   (kinit).

   Usually you need to run this as root (because we need to access the
   keytab), e.g.

   sudo kinit $USER      # make your user creds available for root
   sudo ./run_proto
 *)

let host_name = "e130.lan.sumadev.de"   (* CHANGE THIS *)

open Netgss.System
open Printf

let string_of_flag =
  function
    | `Deleg_flag -> "deleg"
    | `Mutual_flag -> "mutual"
    | `Replay_flag -> "replay"
    | `Sequence_flag -> "sequence"
    | `Conf_flag -> "conf"
    | `Integ_flag -> "integ"
    | `Anon_flag -> "anon"
    | `Prot_ready_flag -> "prot_ready"
    | `Trans_flag -> "trans"

let string_of_time =
  function
  | `Indefinite -> "indefinite"
  | `This n -> string_of_float n


let check_status ((calling_error,routine_error,_) as major_status) =
  if calling_error <> `None || routine_error <> `None then (
    printf "FAIL: %s\n%!" (Netsys_gssapi.string_of_major_status major_status);
    failwith "GSSAPI call failed!"
  )


let string_of_name prefix name =
  printf "%s: display_name\n%!" prefix;
  interface # display_name
    ~input_name:name
    ~out:(fun ~output_name ~output_name_type ~minor_status ~major_status () ->
            check_status major_status;
            output_name ^ " (" ^ Netoid.to_string output_name_type ^ ")"
         )
    ()


let proto() =
  printf "C: import_name\n%!";
  let c_target_name =
    interface # import_name
       ~input_name:"host"
       ~input_name_type:Netsys_gssapi.nt_hostbased_service
       ~out:(fun ~output_name ~minor_status ~major_status () ->
               check_status major_status;
               output_name
            )
       () in

  printf "S: import_name\n%!";
  let s_acceptor_name = 
    interface # import_name
       ~input_name:("host@" ^ host_name)
       ~input_name_type:Netsys_gssapi.nt_hostbased_service
       ~out:(fun ~output_name ~minor_status ~major_status () ->
               check_status major_status;
               output_name
            )
       () in

  printf "S: acquire_cred\n%!";
  let s_acceptor_cred =
    interface # acquire_cred
      ~desired_name:s_acceptor_name
      ~time_req:`Indefinite
      ~desired_mechs:[]
      ~cred_usage:`Accept
      ~out:(fun ~cred ~actual_mechs ~time_rec ~minor_status ~major_status () ->
              check_status major_status;
              cred
           )
      () in

  let proto_continues = ref true in
  let c_context = ref None in
  let s_context = ref None in
  let s_token = ref None in

  while !proto_continues do
    printf "C: init_sec_context\n%!";
    let c_ctx, c_token, c_cont =
      interface # init_sec_context
         ~initiator_cred:interface#no_credential
         ~context:!c_context
         ~target_name:c_target_name
         ~mech_type:[| |]           (* = default mech *)
         ~req_flags:[]
         ~time_req:None
         ~chan_bindings:None 
         ~input_token:!s_token
         ~out:(fun ~actual_mech_type ~output_context ~output_token 
                   ~ret_flags ~time_rec ~minor_status ~major_status () -> 
                 check_status major_status;
                 let (_,_,suppl) = major_status in
                 let cont = List.mem `Continue_needed suppl in
                 assert(output_context <> None);
                 printf "   actual_mech_type = %s\n%!"
                   (Netoid.to_string actual_mech_type);
                 printf "   flags = %s\n%!"
                        (String.concat "," (List.map string_of_flag ret_flags));
                 printf "   time_rec = %s\n%!"
                        (string_of_time time_rec);
                 printf "   token = %S\n%!" output_token;                 
                 (output_context, output_token, cont)
              )
         () in
    c_context := c_ctx;

    if c_token <> "" then (
      printf "S: accept_sec_context\n%!";
      let s_ctx, s_tok, s_cont =
        interface # accept_sec_context
          ~context:!s_context
          ~acceptor_cred:s_acceptor_cred
          ~input_token:c_token
          ~chan_bindings:None
          ~out:(fun ~src_name ~mech_type ~output_context ~output_token
                    ~ret_flags ~time_rec ~delegated_cred 
                    ~minor_status ~major_status () ->
                 check_status major_status;
                 let (_,_,suppl) = major_status in
                 let cont = List.mem `Continue_needed suppl in
                 assert(output_context <> None);
                 let src_name_str = string_of_name "S" src_name in
                 printf "   mech_type = %s\n%!"
                   (Netoid.to_string mech_type);
                 printf "   src_name = %s\n%!" src_name_str;
                 printf "   flags = %s\n%!"
                        (String.concat "," (List.map string_of_flag ret_flags));
                 printf "   time_rec = %s\n%!"
                        (string_of_time time_rec);
                 printf "   token = %S\n%!" output_token;
                 (output_context, output_token, cont)
               )
          () in
      s_context := s_ctx;

      if s_tok <> "" then
        s_token := Some s_tok
      else
        proto_continues := false
    )
    else
      proto_continues := false
  done;

  printf "Proto finished\n%!"


let () = proto()
