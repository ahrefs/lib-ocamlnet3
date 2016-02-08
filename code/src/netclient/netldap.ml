(* $Id$ *)

open Uq_engines
open Uq_engines.Operators
open Printf

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netldap" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netldap" Debug.enable

let () =
  Netlog.Debug.register_module "Netldap" Debug.enable

type asn1_message = Netasn1.Value.value

type signal =
    { signal_eng : asn1_message engine;
      signal : asn1_message final_state -> unit
    }

class type ldap_server =
object
  method ldap_endpoint : Netsockaddr.socksymbol
  method ldap_timeout : float
  method ldap_peer_name : string option
  method ldap_tls_config : (module Netsys_crypto_types.TLS_CONFIG) option
end

type sasl_bind_creds =
  { sasl_dn : string;
    sasl_user : string;
    sasl_authz : string;
    sasl_creds : (string * string * (string * string)list)list;
    sasl_params : (string * string * bool) list;
    sasl_mech : (module Netsys_sasl_types.SASL_MECHANISM);
  }

type bind_creds =
  | Simple of string * string
  | SASL of sasl_bind_creds

type ldap_connection =
    { srv : ldap_server;
      mutable fd : Unix.file_descr option;
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


exception Timeout
exception LDAP_error of result_code * string
exception Auth_error of string

type ldap_result =
    { result_code : result_code;
      result_matched_dn : string;
      result_error_msg : string;
      result_referrals : string list;
    }


let ldap_server ?(timeout=15.0)
                ?peer_name 
                ?tls_config
                ?(tls_enable = false)
                addr : ldap_server =
  let tls_config =
    if tls_enable then
      match tls_config with
        | None ->
            let p = Netsys_crypto.current_tls() in
            let c =
              Netsys_tls.create_x509_config
                ~system_trust:true
                ~peer_auth:`Required
                p in
            Some c
        | Some tls ->
            Some tls
    else
      None in
  ( object
      method ldap_endpoint = addr
      method ldap_timeout = timeout
      method ldap_peer_name = peer_name
      method ldap_tls_config = tls_config
    end
  )

let simple_bind_creds ~dn ~pw =
  Simple(dn,pw)

let sasl_bind_creds ~dn ~user ~authz ~creds ~params mech =
  SASL
    { sasl_dn = dn;
      sasl_user = user;
      sasl_authz = authz;
      sasl_creds = creds;
      sasl_params = params;
      sasl_mech = mech
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


let ops = Netstring_tstring.bytes_ops

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
    let s = Bytes.create 32 in
    let n = min 32 (Uq_io.in_buffer_length conn.dev_in_buf) in
    Uq_io.in_buffer_blit conn.dev_in_buf 0 (`Bytes s) 0 n;
    try
      let (hdr_len, _, _, _, data_len_opt) =
        Netasn1.decode_ber_header_poly ~len:n ~skip_length_check:true ops s in
      let data_len =
        match data_len_opt with
          | None ->
              failwith "LDAP protocol: message with implicit length found"
          | Some l -> l in
      let total_len = hdr_len + data_len in
      let msg_buf = Bytes.make total_len '\x00' in
      Uq_io.really_input_e conn.dev_in (`Bytes msg_buf) 0 total_len
      ++ (fun () ->
            let _, msg =
              Netasn1.decode_ber_poly ops msg_buf in
            match msg with
              | Netasn1.Value.Seq (Netasn1.Value.Integer msg_id_asn1 :: _) ->
                  let msg_id =
                    try
                      Netasn1.Value.get_int msg_id_asn1
                    with
                      | Netasn1.Out_of_range ->
                          failwith "LDAP protocol: unexpected MessageID" in
                  dlog (sprintf "LDAP: got response for request %d" msg_id);
                  let signal =
                    try
                      Hashtbl.find conn.signals msg_id
                    with
                      | Not_found ->
                          dlog (sprintf "LDAP: request %d is unknown" msg_id);
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
      else (
        dlog "LDAP: end of file";
        raise End_of_file
      )
  )
    

exception Sync_exit

let sync e =
  let result = ref None in
  Uq_engines.when_state
    ~is_done:(fun x -> result := Some x; raise Sync_exit)
    ~is_error:(fun e -> raise e)
    ~is_aborted:(fun () -> failwith "Engine has been aborted")
    e;
  try
    Unixqueue.run e#event_system;
    raise Sync_exit
  with
    | Sync_exit ->
        match !result with
          | None -> assert false
          | Some x -> x


let real_connect_e ?proxy (server:ldap_server) esys =
  let addr =
    `Socket(Uq_client.sockspec_of_socksymbol
              Unix.SOCK_STREAM
              server#ldap_endpoint,
            Uq_client.default_connect_options) in
  Uq_client.connect_e ?proxy addr esys
  ++ (function
       | `Socket(fd,fd_spec) ->
           dlog(sprintf "LDAP: connected to %s"
                  (Netsockaddr.string_of_socksymbol server#ldap_endpoint));
           let mplex0 =
             Uq_multiplex.create_multiplex_controller_for_connected_socket
               ~close_inactive_descr:true
               ~supports_half_open_connection:true
               (* timeout *)
               fd esys in
           let mplex1 =
             match server#ldap_tls_config with
               | None -> mplex0
               | Some tls ->
                   Uq_multiplex.tls_multiplex_controller
                     ~role:`Client
                     ~peer_name:(match server#ldap_peer_name with
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
             { srv = server;
               fd = Some fd;
               esys; mplex0; mplex1; dev_in; dev_in_buf; dev_out; next_id;
               signals; recv_eng = dummy_e } in
           dlog "LDAP: starting message receiver";
           let e1 = receive_messages_e conn false in
           conn.recv_eng <- e1;
           eps_e (`Done conn) esys
       | _ -> assert false
     )

let connect_e ?proxy server esys =
  Uq_engines.timeout_engine
    server#ldap_timeout
    Timeout
    (real_connect_e ?proxy server esys)

let connect ?proxy server =
  let esys = Unixqueue.create_unix_event_system() in
  sync (connect_e ?proxy server esys)


let send_message_e conn msg =
  let buf = Netbuffer.create 80 in
  ignore(Netasn1_encode.encode_ber buf msg);
  let data = Netbuffer.to_bytes buf in
  Uq_io.really_output_e conn.dev_out (`Bytes data) 0 (Bytes.length data)


let abort conn  =
  dlog "LDAP: aborting connection";
  ( match conn.fd with
      | None -> ()
      | Some fd ->
          conn.mplex0 # inactivate();
          conn.fd <- None
  );
  Hashtbl.iter
    (fun _ s -> s.signal_eng # abort())
    conn.signals;
  conn.recv_eng # abort()


let real_close_e conn =
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
          dlog (sprintf "LDAP: close request %d" id);
          send_message_e conn req_msg
          ++ (fun () ->
              dlog "LDAP: sending EOF";
                Uq_io.write_eof_e conn.dev_out
                ++ (fun _ ->
                      (* now End_of_file is acceptable *)
                      dlog "LDAP: awaiting EOF";
                      conn.recv_eng
                      >> (function
                           | `Error End_of_file -> `Done ()
                           | other -> other
                         )
                   )
             )
      | _ -> assert false in
  let cleanup _ = abort conn in
  when_state
    ~is_done:cleanup
    ~is_error:cleanup
    ~is_aborted:cleanup
    e;
  e


let close_e conn =
  Uq_engines.timeout_engine
    conn.srv#ldap_timeout
    Timeout
    (real_close_e conn)


let close conn =
  sync (close_e conn)


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
    ~is_error:(fun err -> 
                 dlog(sprintf "LDAP: processing response for %d results in \
                               exception: %s"
                              msg_id (Netexn.to_string err))
              )
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
            | Tagptr(Context, 3, ref_pc, ref_box, ref_pos, ref_len) :: comps2 ->
                let Netstring_tstring.Tstring_polybox(ref_ops, ref_s) =
                  ref_box in
                let _, ref_msg =
                  Netasn1.decode_ber_contents_poly
                    ~pos:ref_pos ~len:ref_len ref_ops ref_s ref_pc
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
            Tagptr(Application, 1, pc, box, pos, len)
          ] ->
        let Netstring_tstring.Tstring_polybox(ops, s) = box in
        let _, bind_resp =
          Netasn1.decode_ber_contents_poly
            ~pos ~len ops s pc Netasn1.Type_name.Seq in
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
    | [ Tagptr(Context, 7, pc, box, pos, len) ] ->
        let Netstring_tstring.Tstring_polybox(ops, s) = box in
        let _, creds_msg =
           Netasn1.decode_ber_contents_poly
             ~pos ~len ops s pc Netasn1.Type_name.Octetstring in
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
  dlog(sprintf "LDAP: simple bind request %d" id);
  send_message_e conn req_msg
  ++ (fun () ->
        await_response_e
          conn
          id
          (fun resp_msg ->
             dlog(sprintf "LDAP: simple bind response %d" id);
             try
               decode_simple_bind_resp resp_msg;
               eps_e (`Done()) conn.esys
             with
               | Not_found -> fail()
          )
     )


let conn_sasl_bind_e conn
                     (mech : (module Netsys_sasl_types.SASL_MECHANISM))
                     bind_dn user authz sasl_creds params =
  let module M = (val mech) in
  let fail() =
    failwith "LDAP bind: unexpected response" in
  let creds = M.init_credentials sasl_creds in
  let id = new_msg_id conn in

  let rec loop_e cs cont_needed =
    dlog (sprintf "LDAP: SASL request %d: entering loop, cont=%B"
                  id cont_needed);
    match M.client_state cs with
      | `OK ->
          if cont_needed then fail();
          dlog (sprintf "LDAP: SASL request %d: bind successful" id);
          eps_e (`Done()) conn.esys
      | `Auth_error msg ->
          dlog (sprintf "LDAP: SASL request %d: auth error %S" id msg);
          raise (Auth_error msg)
      | `Stale ->
          dlog (sprintf "LDAP: SASL request %d: stale" id);
          failwith "Netldap.conn_sasl_bind_e: unexpected SASL state"
      | `Wait ->
          dlog (sprintf "LDAP: SASL request %d: wait" id);
          if not cont_needed then fail();
          dlog (sprintf "LDAP: SASL request %d: emitting request w/o challenge"
                        id);
          let req_msg = encode_sasl_bind_req id bind_dn M.mechanism_name None in
          send_message_e conn req_msg
          ++ (fun () -> await_response_e conn id (on_challenge_e cs))
      | `Emit ->
          dlog (sprintf "LDAP: SASL request %d: emit" id);
          if not cont_needed then fail();
          dlog (sprintf "LDAP: SASL request %d: emitting request with challenge"
                        id);
          let cs, data = M.client_emit_response cs in
          let req_msg =
            encode_sasl_bind_req id bind_dn M.mechanism_name (Some data) in
          send_message_e conn req_msg
          ++ (fun () -> await_response_e conn id (on_challenge_e cs))

    and on_challenge_e cs resp_msg =
      dlog (sprintf "LDAP: SASL response %d" id);
      let cont_needed, data_opt =
        try
          decode_sasl_bind_resp resp_msg
        with
          | Not_found -> fail() in
      match M.client_state cs with
      | `OK ->
          dlog (sprintf "LDAP: SASL response %d: ok" id);
          if cont_needed then fail();
          eps_e (`Done()) conn.esys
      | `Auth_error msg ->
          dlog (sprintf "LDAP: SASL response %d: auth error %S" id msg);
          raise (Auth_error msg)
      | `Wait ->
          dlog (sprintf "LDAP: SASL response %d: wait" id);
          ( match data_opt with
              | Some data ->
                  let cs = M.client_process_challenge cs data in
                  loop_e cs cont_needed
              | None ->
                  fail()
          )
      | `Stale
      | `Emit ->
          failwith "Netldap.conn_sasl_bind_e: unexpected SASL state"
  in
  let cs =
    M.create_client_session 
      ~user
      ~authz
      ~creds
      ~params () in
  loop_e cs true


let real_conn_bind_e conn creds =
  match creds with
    | Simple(dn,pw) ->
        conn_simple_bind_e conn dn pw
    | SASL sasl ->
        conn_sasl_bind_e conn sasl.sasl_mech sasl.sasl_dn sasl.sasl_user
                         sasl.sasl_authz sasl.sasl_creds sasl.sasl_params

let conn_bind_e conn creds =
  Uq_engines.timeout_engine
    conn.srv#ldap_timeout
    Timeout
    (real_conn_bind_e conn creds)

let conn_bind conn creds =
  sync (conn_bind_e conn creds)

let test_bind_e ?proxy server creds esys =
  connect_e ?proxy server esys
  ++ (fun conn ->
        let e =
          ( conn_bind_e conn creds
            >> (function
                 | `Done() -> `Done true
                 | `Error(Auth_error _ | LDAP_error _) -> `Done false
                 | `Error err -> `Error err
                 | `Aborted -> `Aborted
               )
          ) ++ (fun ok ->
                 close_e conn
                 ++ (fun () ->
                     eps_e (`Done ok) esys
                    )
                ) in
        Uq_engines.when_state
          ~is_done:(fun _ -> abort conn)
          ~is_error:(fun _ -> abort conn)
          ~is_aborted:(fun _ -> abort conn)
          e;
        e
     )

let test_bind ?proxy server creds =
  let esys = Unixqueue.create_unix_event_system() in
  sync (test_bind_e ?proxy server creds esys)
  

  
(*
#use "topfind";;
#require "netclient,nettls-gnutls";;
open Netldap;;

Debug.enable := true;;
let password = "XXX";;
let bind_dn = "uid=gerdsasl,ou=users,o=gs-adressbuch";;

let server =
  ldap_server
    (`Inet_byname("office1", 389)) ;;

let creds1 = simple_bind_creds ~dn:bind_dn ~pw:password;;
let creds2 =
  sasl_bind_creds 
    ~dn:bind_dn ~user:"gerdsasl" ~authz:"" 
    ~creds:[ "password", password, [] ]
    ~params:[]
    (module Netmech_scram_sasl.SCRAM_SHA1 : Netsys_sasl_types.SASL_MECHANISM);;

let conn = connect server;;

conn_bind conn creds1;;
conn_bind conn creds2;;

close conn;;
 *)
