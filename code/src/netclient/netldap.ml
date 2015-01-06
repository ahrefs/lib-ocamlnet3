(* $Id$ *)

open Uq_engines
open Uq_engines.Operators

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


let await_response conn msg_id f_e =
  (* Invoke f_e with the response message when a response for msg_id arrives *)
  let signal_eng, signal = Uq_engines.signal_engine conn.esys in
  let s = { signal_eng; signal } in
  let _e = signal_eng ++ f_e in
  Hashtbl.replace conn.signals msg_id s;
  ()


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


let simple_bind_e conn bind_dn password =
  let fail() =
    failwith "LDAP bind: unexpected response" in
  let id = new_msg_id conn in
  let ldap_version = 3 in
  let req_msg =
    let open Netasn1.Value in
    Seq [ Integer (int id);
          ITag(Application, 0,
               Seq [ Integer (int ldap_version);
                     Octetstring bind_dn;
                     ITag(Context, 0,
                          Octetstring password)
                   ]
              )
        ] in
  await_response
    conn
    id
    (fun resp_msg ->
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
                     if bind_result.result_code <> `Success then
                       raise(LDAP_error(bind_result.result_code,
                                        bind_result.result_error_msg));
                     if comps <> [] then fail();
                     eps_e (`Done ()) conn.esys
                 | _ ->
                     fail()
             )
         | _ -> 
             fail()
    );
  send_message_e conn req_msg

  
(*
#use "topfind";;
#require "netclient";;
open Netldap;;
open Uq_engines.Operators;;

let password = "XXX";;

let esys = Unixqueue.create_unix_event_system();;
let addr = `Socket(`Sock_inet_byname(Unix.SOCK_STREAM, "office1", 389),
                   Uq_client.default_connect_options);;
let e =
  connect_e addr esys
  ++ (fun conn ->
         simple_bind_e conn "uid=gerd,ou=users,o=gs-adressbuch" password
         ++ (fun () -> close_e conn)
     );;
Unixqueue.run esys;;
 *)
