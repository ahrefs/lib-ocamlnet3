(* $Id$ *)

open Printf

module type GNUTLS_PROVIDER =
  sig
    include Netsys_crypto_types.TLS_PROVIDER
            with type error_code = Nettls_gnutls_bindings.error_code

    val gnutls_session : endpoint -> Nettls_gnutls_bindings.gnutls_session_t
    val gnutls_credentials : credentials -> 
                               Nettls_gnutls_bindings.gnutls_credentials
  end


module type GNUTLS_ENDPOINT =
  sig
    module TLS : GNUTLS_PROVIDER
    val endpoint : TLS.endpoint
  end


exception I of (module GNUTLS_PROVIDER)

let self = ref Not_found


module TLS : GNUTLS_PROVIDER =
  struct
    let implementation_name = "Nettls_gnutls.TLS"
    let implementation () = !self

    module G = Nettls_gnutls_bindings

    type credentials =
        { gcred : G.gnutls_credentials;
        }

    type error_code =
        G.error_code

    type direction = [ `R | `W ]

    type dh_params =
      [ `PKCS3_PEM_file of string
      | `PKCS3_DER of string
      | `Generate of int
      ]

    type config =
        { priority : G.gnutls_priority_t;
          dh_params : G.gnutls_dh_params_t option;
          peer_auth : [ `None | `Optional | `Required ];
          credentials : credentials;
        }
          
    type crt_list =
        [`PEM_file of string | `DER of string list]

    type crl_list =
        [`PEM_file of string | `DER of string list]

    type private_key =
        [ `PEM_file of string 
        | `RSA of string 
        | `DSA of string
        | `EC of string
        | `PKCS8 of string
        | `PKCS8_encrypted of string
        ]

    type server_name = [ `Domain of string ]

    type endpoint =
        { role : [ `Server | `Client ];
          recv : (Netsys_types.memory -> int);
          send : (Netsys_types.memory -> int -> int);
          config : config;
          session : G.gnutls_session_t;
        }

    exception EAGAIN of direction
    exception EINTR
    exception Switch_request
    exception Error of error_code
    exception Warning of error_code

    let error_message code = G.gnutls_strerror code

    let error_name code = G.gnutls_strerror_name code

    let trans_exn f arg =
      try
        f arg
      with
        | G.Error code ->
            raise(Error code)


    let parse_pem ?(empty_ok=false) header_tags file f =
      let spec = List.map (fun tag -> (tag, `Base64)) header_tags in
      let blocks =
        Netchannels.with_in_obj_channel
          (new Netchannels.input_channel(open_in file))
          (fun ch -> Netascii_armor.parse spec ch) in
      if not empty_ok && blocks = [] then
        failwith ("Cannot find PEM-encoded objects in file: " ^ file);
      List.map
        (function
          | (tag, `Base64 body) -> f (tag,body#value)
          | _ -> assert false
        )
        blocks

    let create_pem header_tag data =
      let b64 = Netencoding.Base64.encode ~linelength:80 data in
      "-----BEGIN " ^ header_tag ^ "-----\n" ^ 
        b64 ^
      "-----END " ^ header_tag ^ "-----\n"


    let create_config ?(algorithms="NORMAL") ?dh_params ~peer_auth 
                      ~credentials () =
      let f() =
        let priority = G.gnutls_priority_init algorithms in
        let dhp_opt =
          match dh_params with
            | None -> None
            | Some(`PKCS3_PEM_file file) ->
                let data =
                  List.hd (parse_pem ["DH PARAMETERS"] file snd) in
                let dhp = G.gnutls_dh_params_init() in
                G.gnutls_dh_params_import_pkcs3 dhp data `Der;
                Some dhp
            | Some(`PKCS3_DER data) ->
                let dhp = G.gnutls_dh_params_init() in
                G.gnutls_dh_params_import_pkcs3 dhp data `Der;
                Some dhp
            | Some(`Generate bits) ->
                let dhp = G.gnutls_dh_params_init() in
                G.gnutls_dh_params_generate2 dhp bits;
                Some dhp in
        { priority;
          dh_params = dhp_opt;
          peer_auth;
          credentials
        } in
      trans_exn f ()


    let create_x509_credentials_1 ~trust ~revoke ~keys () =
      let gcred = G.gnutls_certificate_allocate_credentials() in
      List.iter
        (fun crt_spec ->
           let der_crts =
             match crt_spec with
               | `PEM_file file ->
                   parse_pem [ "X509 CERTIFICATE"; "CERTIFICATE" ] file snd
               | `DER l ->
                   l in
           List.iter
             (fun data ->
                G.gnutls_certificate_set_x509_trust_mem gcred data `Der
             )
             der_crts
        )
        trust;
      List.iter
        (fun crl_spec ->
           let der_crls =
             match crl_spec with
               | `PEM_file file ->
                   parse_pem [ "X509 CRL" ] file snd
               | `DER l ->
                   l in
           List.iter
             (fun data ->
                G.gnutls_certificate_set_x509_crl_mem gcred data `Der
             )
             der_crls
        )
        revoke;
      List.iter
        (fun (crts, pkey, pw_opt) ->
           let der_crts =
             match crts with
               | `PEM_file file ->
                   parse_pem [ "X509 CERTIFICATE"; "CERTIFICATE" ] file snd
               | `DER l ->
                   l in
           let gcrts =
             List.map
               (fun data ->
                  let gcrt = G.gnutls_x509_crt_init() in
                  G.gnutls_x509_crt_import gcrt data `Der;
                  gcrt
               )
               der_crts in
           let gpkey = G.gnutls_x509_privkey_init() in
           let pkey1 =
             match pkey with
               | `PEM_file file ->
                   let p =
                     parse_pem
                       [ "RSA PRIVATE KEY";
                         "DSA PRIVATE KEY";
                         "EC PRIVATE KEY";
                         "PRIVATE KEY";
                         "ENCRYPTED PRIVATE KEY"
                       ]
                       file
                       (fun (tag,data) ->
                          match tag with
                            | "RSA PRIVATE KEY" -> `RSA data
                            | "DSA PRIVATE KEY" -> `DSA data
                            | "EC PRIVATE KEY" -> `EC data
                            | "PRIVATE KEY" -> `PKCS8 data
                            | "ENCRYPTED PRIVATE KEY" -> `PKCS8_encrypted data
                            | _ -> assert false
                       ) in
                   (List.hd p :> private_key)
               | other ->
                   other in

           ( match pkey1 with
               | `PEM_file file ->
                   assert false
               | `RSA data ->
                   (* There is no entry point for parsing ONLY this format *)
                   let pem = create_pem "RSA PRIVATE KEY" data in
                   G.gnutls_x509_privkey_import gpkey pem `Pem
               | `DSA data ->
                   (* There is no entry point for parsing ONLY this format *)
                   let pem = create_pem "DSA PRIVATE KEY" data in
                   G.gnutls_x509_privkey_import gpkey pem `Pem
               | `EC data ->
                   (* There is no entry point for parsing ONLY this format *)
                   let pem = create_pem "EC PRIVATE KEY" data in
                   G.gnutls_x509_privkey_import gpkey pem `Pem
               | `PKCS8 data ->
                   G.gnutls_x509_privkey_import_pkcs8 
                     gpkey data `Der "" [`Plain]
               | `PKCS8_encrypted data ->
                   ( match pw_opt with
                       | None ->
                           failwith "No password for encrypted PKCS8 data"
                       | Some pw ->
                           G.gnutls_x509_privkey_import_pkcs8
                             gpkey data `Der pw []
                   )

           );
           G.gnutls_certificate_set_x509_key gcred (Array.of_list gcrts) gpkey
        )
        keys;
      { gcred = `Certificate gcred }

    let create_x509_credentials ?(trust=[]) ?(revoke=[]) ?(keys=[]) () =
      trans_exn
        (create_x509_credentials_1 ~trust ~revoke ~keys)
        ()

    let create_endpoint ~role ~recv ~send config =
      let f() =
        let flags = [ (role :> G.gnutls_init_flags_flag) ] in
        let session = G.gnutls_init flags in
        G.gnutls_credentials_set session config.credentials.gcred;
        G.b_set_pull_callback session recv;
        G.b_set_push_callback session send;
        { role;
          recv;
          send;
          config;
          session
        } in
      trans_exn f ()
          
    let endpoint_exn ?(warnings=false) ep f arg =
      try
        f arg
      with
        | G.Error `Again -> 
            let dir =
              if G.gnutls_record_get_direction ep.session then `W else `R in
            raise (EAGAIN dir)
        | G.Error `Interrupted ->
            raise EINTR
        | G.Error `Rehandshake ->
            raise Switch_request
        | G.Error code ->
            if warnings && not(G.gnutls_error_is_fatal code) then
              raise(Warning code)
            else
              raise(Error code)

    let hello ep =
      endpoint_exn
        ~warnings:true
        ep
        G.gnutls_handshake
        ep.session

    let bye ep how =
      let ghow =
        match how with
          | `W -> `Wr
          | `RW  -> `Rdwr in
      endpoint_exn
        ~warnings:true
        ep
        (G.gnutls_bye ep.session)
        ghow

    let verify ep peer_name =
      let f() =
        let status_l = G.gnutls_certificate_verify_peers2 ep.session in
        if status_l <> [] then
          failwith(sprintf "Certificate verification failed with codes: " ^ 
                     (String.concat ", " 
                        (List.map 
                           G.string_of_verification_status_flag
                           status_l)));
        let der_peer_certs = G.gnutls_certificate_get_peers ep.session in
        assert(der_peer_certs <> [| |]);
        let peer_cert = G.gnutls_x509_crt_init() in
        G.gnutls_x509_crt_import peer_cert der_peer_certs.(0) `Der;
        let ok = G.gnutls_x509_crt_check_hostname peer_cert peer_name in
        if not ok then
          failwith "Certificate verification failed with codes: BAD_HOSTNAME";
        () in
      trans_exn f ()

    let get_endpoint_crt ep =
      trans_exn G.gnutls_certificate_get_ours ep.session

    let get_peer_crt_list ep =
      Array.to_list(trans_exn G.gnutls_certificate_get_peers ep.session)

    let switch _ = assert false
    let accept_switch _ = assert false
    let refuse_switch _ = assert false

    let send ep buf n =
      endpoint_exn
        ~warnings:true
        ep
        (G.gnutls_record_send ep.session buf)
        n

    let recv ep buf =
      endpoint_exn
        ~warnings:true
        ep
        (G.gnutls_record_recv ep.session)
        buf

    let recv_will_not_block ep =
      let f() =
        G.gnutls_record_check_pending ep.session > 0 in
      trans_exn f ()

    let get_cipher_algo ep =
      let f() =
        G.gnutls_cipher_get_name (G.gnutls_cipher_get ep.session) in
      trans_exn f ()

    let get_kx_algo ep =
      let f() =
        G.gnutls_kx_get_name (G.gnutls_kx_get ep.session) in
      trans_exn f ()

    let get_mac_algo ep =
      let f() =
        G.gnutls_mac_get_name (G.gnutls_mac_get ep.session) in
      trans_exn f ()

    let get_compression_algo ep =
      let f() =
        G.gnutls_compression_get_name (G.gnutls_compression_get ep.session) in
      trans_exn f ()

    let get_cert_type ep =
      let f() =
        G.gnutls_certificate_type_get_name
          (G.gnutls_certificate_type_get ep.session) in
      trans_exn f ()
      
    let get_protocol ep =
      let f() =
        G.gnutls_protocol_get_name (G.gnutls_protocol_get_version ep.session) in
      trans_exn f ()

    let get_addressed_servers ep =
      let rec get k =
        try
          let n1, t = G.gnutls_server_name_get ep.session k in
          let n2 =
            match t with
              | `Dns -> `Domain n1 in
          n2 :: get(k+1)
        with
          | G.Error `Requested_data_not_available ->
              [] in
      trans_exn get 0

    let set_addressed_servers ep l =
      List.iter
        (function
          | `Domain n ->
              G.gnutls_server_name_set ep.session `Dns n
        )
        l

    let gnutls_credentials c = c.gcred
    let gnutls_session ep = ep.session
  end


let tls = (module TLS : GNUTLS_PROVIDER)

let () =
  self := I tls


let endpoint ep =
  let module EP =
    struct
      module TLS = TLS
      let endpoint = ep
    end in
  (module EP : GNUTLS_ENDPOINT)

let downcast p =
  let module P = (val p : Netsys_crypto_types.TLS_PROVIDER) in
  match P.implementation() with
    | I tls -> tls
    | _ -> raise Not_found

let init() =
  Nettls_gnutls_bindings.gnutls_global_init()


let () =
  init()
