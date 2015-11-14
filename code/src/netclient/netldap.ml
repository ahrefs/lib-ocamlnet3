(* $Id$ *)

open Uq_engines
open Uq_engines.Operators
open Printf

type asn1_message = Netasn1.Value.value

type signal =
    { signal_eng : asn1_message engine;
      signal : asn1_message final_state -> unit
    }

type connection =
    { fd : Unix.file_descr;
      esys : Unixqueue.event_system;
      mplex0 : Uq_multiplex.multiplex_controller;
        (* the mplex for fd *)
      mplex1 : Uq_multiplex.multiplex_controller;
        (* if TLS is active, the TLS mplex, otherwise the same as mplex0 *)
      dev_in : Uq_io.in_device;
        (* mplex1 as buffered in_device *)
      dev_in_buf : Uq_io.in_buffer;
        (* the buffer of dev_in *)
      dev_out : Uq_io.out_device;
        (* mplex1 as out_device *)
      mutable next_id : int;
        (* the next message ID *)
      signals : (int, signal) Hashtbl.t;
        (* signals are invoked for server messages *)
      mutable recv_eng : unit engine;
        (* the receive engine *)
    }

type result_code =
  [ `Success
  | `OperationsError
  | `ProtocolError
  | `TimeLimitExceeded
  | `SizeLimitExceeded
  | `CompareFalse
  | `CompareTrue
  | `AuthMethodNotSupported
  | `StrongAuthRequired
  | `Referral
  | `AdminLimitExceeded
  | `UnavailableCriticalExtension
  | `ConfidentialityRequired
  | `SaslBindInProgress
  | `NoSuchAttribute
  | `UndefinedAttributeType
  | `InappropriateMatching
  | `ConstraintViolation
  | `AttributeOrValueExists
  | `InvalidAttributeSyntax
  | `NoSuchObject
  | `AliasProblem
  | `InvalidDNSyntax
  | `AliasDereferencingProblem
  | `InappropriateAuthentication
  | `InvalidCredentials
  | `InsufficientAccessRights
  | `Busy
  | `Unavailable
  | `UnwillingToPerform
  | `LoopDetect
  | `NamingViolation
  | `ObjectClassViolation
  | `NotAllowedOnNonLeaf
  | `NotAllowedOnRDN
  | `EntryAlreadyExists
  | `ObjectClassModsProhibited
  | `AffectsMultipleDSAs
  | `Other
  | `Unknown_code of int
  ]


exception LDAP_error of result_code * string
exception Auth_error of string

type ldap_result =
    { result_code : result_code;
      result_matched_dn : string;
      result_error_msg : string;
      result_referrals : string list;
    }


let result_code code =
  match code with
    | 0 -> `Success
    | 1 -> `OperationsError
    | 2 -> `ProtocolError
    | 3 -> `TimeLimitExceeded
    | 4 -> `SizeLimitExceeded
    | 5 -> `CompareFalse
    | 6 -> `CompareTrue
    | 7 -> `AuthMethodNotSupported
    | 8 -> `StrongAuthRequired
    | 10 -> `Referral
    | 11 -> `AdminLimitExceeded
    | 12 -> `UnavailableCriticalExtension
    | 13 -> `ConfidentialityRequired
    | 14 -> `SaslBindInProgress
    | 16 -> `NoSuchAttribute
    | 17 -> `UndefinedAttributeType
    | 18 -> `InappropriateMatching
    | 19 -> `ConstraintViolation
    | 20 -> `AttributeOrValueExists
    | 21 -> `InvalidAttributeSyntax
    | 32 -> `NoSuchObject
    | 33 -> `AliasProblem
    | 34 -> `InvalidDNSyntax
    | 36 -> `AliasDereferencingProblem
    | 48 -> `InappropriateAuthentication
    | 49 -> `InvalidCredentials
    | 50 -> `InsufficientAccessRights
    | 51 -> `Busy
    | 52 -> `Unavailable
    | 53 -> `UnwillingToPerform
    | 54 -> `LoopDetect
    | 64 -> `NamingViolation
    | 65 -> `ObjectClassViolation
    | 66 -> `NotAllowedOnNonLeaf
    | 67 -> `NotAllowedOnRDN
    | 68 -> `EntryAlreadyExists
    | 69 -> `ObjectClassModsProhibited
    | 71 -> `AffectsMultipleDSAs
    | 80 -> `Other
    | _ -> `Unknown_code code


let new_msg_id conn =
  let id = conn.next_id in
  conn.next_id <- id+1;
  id


let rec receive_messages_e conn buf_eof =
  if Uq_io.in_buffer_length conn.dev_in_buf = 0 && not buf_eof then (
    (* Nothing received yet *)
    Uq_io.in_buffer_fill_e conn.dev_in_buf
    ++ (fun eof ->
          receive_messages_e conn eof
       )
  )
  else (
    (* Check whether there is a full header in the buffer *)
    let s = String.create 32 in
    let n = min 32 (Uq_io.in_buffer_length conn.dev_in_buf) in
    Uq_io.in_buffer_blit conn.dev_in_buf 0 (`String s) 0 n;
    try
      let (hdr_len, _, _, _, data_len_opt) =
        Netasn1.decode_ber_header ~len:n ~skip_length_check:true s in
      let data_len =
        match data_len_opt with
          | None ->
              failwith "LDAP protocol: message with implicit length found"
          | Some l -> l in
      let total_len = hdr_len + data_len in
      let msg_buf = String.make total_len '\x00' in
      Uq_io.really_input_e conn.dev_in (`String msg_buf) 0 total_len
      ++ (fun () ->
            let _, msg =
              Netasn1.decode_ber msg_buf in
            match msg with
              | Netasn1.Value.Seq (Netasn1.Value.Integer msg_id_asn1 :: _) ->
                  let msg_id =
                    try
                      Netasn1.Value.get_int msg_id_asn1
                    with
                      | Netasn1.Out_of_range ->
                          failwith "LDAP protocol: unexpected MessageID" in
                  let signal =
                    try
                      Hashtbl.find conn.signals msg_id
                    with
                      | Not_found ->
                          failwith "LDAP protocol: unexpected MessageID" in
                  Hashtbl.remove conn.signals msg_id;
                  signal.signal (`Done msg);
                  receive_messages_e conn false
              | _ ->
                  failwith "LDAP protocol: unexpected ASN.1 structure"
         )
    with Netasn1.Header_too_short ->
      (* from decode_ber_header *)
      if not buf_eof then
        Uq_io.in_buffer_fill_e conn.dev_in_buf
        ++ (fun eof ->
              receive_messages_e conn eof
           )
      else
        raise End_of_file
  )
    

let connect_e ?proxy ?peer_name ?tls_config addr esys =
  Uq_client.connect_e ?proxy addr esys
  ++ (function
       | `Socket(fd,fd_spec) ->
           let mplex0 =
             Uq_multiplex.create_multiplex_controller_for_connected_socket
               ~close_inactive_descr:true
               ~supports_half_open_connection:true
               (* timeout *)
               fd esys in
           let mplex1 =
             match tls_config with
               | None -> mplex0
               | Some tls ->
                   Uq_multiplex.tls_multiplex_controller
                     ~role:`Client
                     ~peer_name:(match peer_name with
                                   | Some n -> Some n
                                   | None ->
                                       ( match addr with
                                           | `Socket(`Sock_inet_byname(_,p,_),
                                                     _) ->
                                               Some p
                                           | _ ->
                                               None
                                       )
                                )
                     tls
                     mplex0 in
           let dev_in_raw = `Multiplex mplex1 in
           let dev_in_buf = Uq_io.create_in_buffer dev_in_raw in
           let dev_in = `Buffer_in dev_in_buf in
           let dev_out = `Multiplex mplex1 in
           let next_id = 0 in
           let signals = Hashtbl.create 17 in
           let dummy_e = eps_e (`Done()) esys in
           let conn =
             { fd; esys; mplex0; mplex1; dev_in; dev_in_buf; dev_out; next_id;
               signals; recv_eng = dummy_e } in
           let e1 = receive_messages_e conn false in
           conn.recv_eng <- e1;
           eps_e (`Done conn) esys
       | _ -> assert false
     )


let send_message_e conn msg =
  let buf = Buffer.create 80 in
  ignore(Netasn1_encode.encode_ber buf msg);
  let data = Buffer.contents buf in
  Uq_io.really_output_e conn.dev_out (`String data) 0 (String.length data)


let close_e conn =
  let id = new_msg_id conn in
  let req_msg =
    let open Netasn1.Value in
    Seq [ Integer (int id);
          ITag(Application, 2, Null)
        ] in
  let e =
    match conn.recv_eng # state with
      | `Error _ ->
          conn.recv_eng
      | `Working _ ->
          send_message_e conn req_msg
          ++ (fun () ->
                Uq_io.write_eof_e conn.dev_out
                ++ (fun _ ->
                      (* now End_of_file is acceptable *)
                      conn.recv_eng
                      >> (function
                           | `Error End_of_file -> `Done ()
                           | other -> other
                         )
                   )
             )
      | _ -> assert false in
  let cleanup _ =
    Unix.close conn.fd;
    Hashtbl.iter
      (fun _ s -> s.signal_eng # abort())
      conn.signals in
  when_state
    ~is_done:cleanup
    ~is_error:cleanup
    ~is_aborted:cleanup
    e;
  e


let with_conn_e f conn =
  meta_engine
    (f conn)
  ++ (fun st ->
        (* FIXME: close only for only non-fatal errors! *)
        close_e conn
        ++ (fun () -> eps_e (st :> _ engine_state) conn.esys)
     )
    


let await_response_e conn msg_id f_e =
  (* Invoke f_e with the response message when a response for msg_id arrives *)
  let signal_eng, signal = Uq_engines.signal_engine conn.esys in
  let s = { signal_eng; signal } in
  let e = signal_eng ++ f_e in
  Hashtbl.replace conn.signals msg_id s;
  when_state
    ~is_error:(fun _ -> printf "e->ERROR\n%!")
    e;
  e


let trivial_sync_e conn l =
  let e =
    msync_engine l (fun () () -> ()) () conn.esys in
  when_state
    ~is_error:(fun _ -> printf "sync->ERROR\n%!")
    e;
  e


let decode_ldap_result msg =
  let open Netasn1.Value in
  let fail() =
    failwith "LDAP protocol: cannot decode LDAPResult" in
  match msg with
    | (Enum rcode) ::
        (Octetstring result_matched_dn) :: 
          (Octetstring result_error_msg) ::
            comps1 ->
        let result_referrals, comps =
          match comps1 with
            | Tagptr(Context, 3, ref_pc, ref_s, ref_pos, ref_len) :: comps2 ->
                let _, ref_msg =
                  Netasn1.decode_ber_contents
                    ~pos:ref_pos ~len:ref_len ref_s ref_pc
                    Netasn1.Type_name.Seq in
                let refs =
                  match ref_msg with
                    | Seq list ->
                        List.map
                          (function
                            | Octetstring url -> url
                            | _ -> fail()
                          )
                          list
                    | _ -> fail() in
                refs, comps2
            | _ ->
                [], comps1 in
        let r =
          { result_code = result_code (get_int rcode);
            result_matched_dn;
            result_error_msg;
            result_referrals
          } in
        (r, comps)
    | _ ->
        fail()


let encode_simple_bind_req id bind_dn password =
  let open Netasn1.Value in
  let ldap_version = 3 in
  Seq [ Integer (int id);
        ITag(Application, 0,
             Seq [ Integer (int ldap_version);
                   Octetstring bind_dn;
                   ITag(Context, 0,
                        Octetstring password)
                 ]
            )
      ]


let encode_sasl_bind_req id bind_dn mech creds_opt =
  let open Netasn1.Value in
  let ldap_version = 3 in
  Seq [ Integer (int id);
        ITag(Application, 0,
             Seq [ Integer (int ldap_version);
                   Octetstring bind_dn;
                   ITag(Context, 3,
                        Seq ( Octetstring mech ::
                                ( match creds_opt with
                                    | None -> []
                                    | Some creds -> [ Octetstring creds ]
                                )
                            )
                       )
                 ]
            )
      ]


let decode_bind_resp ?(ok=[`Success]) resp_msg =
  let open Netasn1.Value in
  match resp_msg with
    | Seq [ Integer _;
            Tagptr(Application, 1, pc, s, pos, len)
          ] ->
        let _, bind_resp =
          Netasn1.decode_ber_contents
            ~pos ~len s pc Netasn1.Type_name.Seq in
        ( match bind_resp with
            | Seq bind_seq ->
                let bind_result, comps =
                  decode_ldap_result bind_seq in
                if not (List.mem bind_result.result_code ok) then (
                  printf "ERROR %s\n%!" bind_result.result_error_msg;
                  raise(LDAP_error(bind_result.result_code,
                                   bind_result.result_error_msg));
                );
                (bind_result.result_code, comps)
            | _ ->
                raise Not_found
        )
    | _ ->
        raise Not_found


let decode_simple_bind_resp resp_msg =
  let _, comps = decode_bind_resp resp_msg in
  if comps <> [] then raise Not_found;
  ()


let decode_sasl_bind_resp resp_msg =
  let open Netasn1.Value in
  let code, comps = 
    decode_bind_resp ~ok:[`Success;`SaslBindInProgress] resp_msg in
  let cont =
    code = `SaslBindInProgress in
  match comps with
    | [ Tagptr(Context, 7, pc, s, pos, len) ] ->
        let _, creds_msg =
           Netasn1.decode_ber_contents
             ~pos ~len s pc Netasn1.Type_name.Octetstring in
        ( match creds_msg with
            | Octetstring data ->
                (cont, Some data)
            | _ ->
                raise Not_found
        )
    | [] ->
        (cont, None)
    | _ ->
        raise Not_found


let conn_simple_bind_e conn bind_dn password =
  let fail() =
    failwith "LDAP bind: unexpected response" in
  let id = new_msg_id conn in
  let req_msg = encode_simple_bind_req id bind_dn password in
  trivial_sync_e
    conn
    [ await_response_e
        conn
        id
        (fun resp_msg ->
         try
           decode_simple_bind_resp resp_msg;
           eps_e (`Done()) conn.esys
         with
           | Not_found -> fail()
        );
      send_message_e conn req_msg
    ]


let conn_sasl_bind_e conn
                     (mech : (module Netsys_sasl_types.SASL_MECHANISM))
                     bind_dn user authz sasl_creds params =
  let module M = (val mech) in
  let fail() =
    failwith "LDAP bind: unexpected response" in
  let creds = M.init_credentials sasl_creds in
  let cs =
    M.create_client_session 
      ~user
      ~authz
      ~creds
      ~params () in
  let id = new_msg_id conn in

  let rec loop_e cont_needed =
    printf "LOOP\n%!";
    match M.client_state cs with
      | `OK ->
          if cont_needed then fail();
          eps_e (`Done()) conn.esys
      | `Auth_error msg ->
          raise (Auth_error msg)
      | `Stale ->
          failwith "Netldap.conn_sasl_bind_e: unexpected SASL state"
      | `Wait ->
          if not cont_needed then fail();
          let req_msg = encode_sasl_bind_req id bind_dn M.mechanism_name None in
          trivial_sync_e
            conn
            [ await_response_e conn id on_challenge_e;
              send_message_e conn req_msg
            ]
      | `Emit ->
          if not cont_needed then fail();
          let data = M.client_emit_response cs in
          let req_msg =
            encode_sasl_bind_req id bind_dn M.mechanism_name (Some data) in
          trivial_sync_e
            conn
            [ await_response_e conn id on_challenge_e;
              send_message_e conn req_msg
            ]

    and on_challenge_e resp_msg =
      printf "CHALLENGE\n%!";
      let cont_needed, data_opt =
        try
          decode_sasl_bind_resp resp_msg
        with
          | Not_found -> fail() in
      match M.client_state cs with
      | `OK ->
          if cont_needed then fail();
          eps_e (`Done()) conn.esys
      | `Auth_error msg ->
          raise (Auth_error msg)
      | `Wait ->
          ( match data_opt with
              | Some data ->
                  M.client_process_challenge cs data;
                  loop_e cont_needed
              | None ->
                  fail()
          )
      | `Stale
      | `Emit ->
          failwith "Netldap.conn_sasl_bind_e: unexpected SASL state"
  in
  loop_e true

  
(*
#use "topfind";;
#require "netclient,nettls-gnutls";;
open Netldap;;
open Uq_engines.Operators;;

let bind_dn = "uid=gerdsasl,ou=users,o=gs-adressbuch";;
let password = "XXX";;

let esys = Unixqueue.create_unix_event_system();;
let addr = `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "office1", 389),
                   Uq_client.default_connect_options);;
let e =
  connect_e addr esys
  ++ (fun conn ->
         conn_simple_bind_e conn bind_dn password
         ++ (fun () -> close_e conn)
     );;

let mech = (module Netmech_scram_sasl.SCRAM_SHA1 : Netsys_sasl_types.SASL_MECHANISM);;
let e =
  connect_e addr esys
  ++ with_conn_e
    (fun conn ->
         conn_sasl_bind_e
            conn mech bind_dn "gerdsasl" "" [ "password", password, [] ] []
     );;


Unixqueue.run esys;;
 *)
