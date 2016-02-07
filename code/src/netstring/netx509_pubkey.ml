type oid = Netoid.t
type alg_id = Alg_id of oid * Netasn1.Value.value option
type pubkey =
  { pubkey_type : alg_id;
    pubkey_data : Netasn1.Value.bitstring_value;
  }
type hash_function = [ `SHA_1 | `SHA_224 | `SHA_256 | `SHA_384 | `SHA_512 ]
type maskgen_function = [ `MGF1 of hash_function ]

#ifdef HAVE_EXTENSIVE_VARIANTS
type alg_param = ..
type alg_param +=
#else
type alg_param =
#endif
| P_PSS of hash_function * maskgen_function * int
| P_OAEP of hash_function * maskgen_function * string

type encrypt_alg = Encrypt of oid * alg_param option
type sign_alg = Sign of oid * alg_param option
type kex_alg = Kex of oid * alg_param option
type privkey = Privkey of string * string


let decode_pubkey_from_der s =
  let module V = Netasn1.Value in
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then
    failwith "Netx509_pubkey.decode_pubkey_from_der";
  match v with
    | V.Seq [ V.Seq s_keytype; V.Bitstring pubkey_data ] ->
        let pubkey_type =
          match s_keytype with
            | [ V.OID oid ] ->
                Alg_id(oid, None)
            | [ V.OID oid; params ] ->
                Alg_id(oid, Some params)
            | _ ->
                failwith "Netx509_pubkey.decode_pubkey_from_der" in
        { pubkey_type;
          pubkey_data
        }
    | _ ->
        failwith "Netx509_pubkey.decode_pubkey_from_der"


let encode_pubkey_to_der pk =
  let module V = Netasn1.Value in
  let Alg_id(oid, params) = pk.pubkey_type in
  let v_params =
    match params with
      | None -> []
      | Some p -> [p] in
  let v =
    V.Seq [ V.Seq (V.OID oid :: v_params); V.Bitstring pk.pubkey_data ] in
  let b = Netbuffer.create 80 in
  ignore(Netasn1_encode.encode_ber b v);
  Netbuffer.contents b


let read_pubkey_from_pem ch =
  let l = Netascii_armor.parse [ "PUBLIC KEY", `Base64 ] ch in
  match l with
    | [] ->
        failwith "Netx509_pubkey.read_pubkey_from_pem: no key found"
    | [_, `Base64 msg] ->
        decode_pubkey_from_der msg#value
    | _ ->
        failwith "Netx509_pubkey.read_pubkey_from_pem: several keys found"


let key_types = [ "RSA"; "DSA"; "DH"; "EC"; "KEA"; "EDDSA" ]

let read_privkey_from_pem ch =
  let suffix = " PRIVATE KEY" in
  let spec =
    List.map
      (fun ty -> (ty ^ suffix, `Base64))
      key_types in
  let l = Netascii_armor.parse spec ch in
  match l with
    | [] ->
        failwith "Netx509_pubkey.read_privkey_from_pem: no key found"
    | [ty, `Base64 msg] ->
        let n1 = String.length ty in
        let n2 = String.length suffix in
        let fmt = String.sub ty 0 (n1 - n2) in
        Privkey(fmt, msg#value)
    | _ ->
        failwith "Netx509_pubkey.read_privkey_from_pem: several keys found"


let hash_functions =
  let module V = Netasn1.Value in
  [ `SHA_1,   V.Seq [ V.OID [| 1; 3; 14; 3; 2; 26 |]; V.Null ];
    `SHA_224, V.Seq [ V.OID [| 2; 16; 840; 1; 101; 3; 4; 2; 4 |]; V.Null ];
    `SHA_256, V.Seq [ V.OID [| 2; 16; 840; 1; 101; 3; 4; 2; 1 |]; V.Null ];
    `SHA_384, V.Seq [ V.OID [| 2; 16; 840; 1; 101; 3; 4; 2; 2 |]; V.Null ];
    `SHA_512, V.Seq [ V.OID [| 2; 16; 840; 1; 101; 3; 4; 2; 3 |]; V.Null ];
  ]

let hash_size =
  [ `SHA_1, 20;
    `SHA_224, 28;
    `SHA_256, 32;
    `SHA_384, 48;
    `SHA_512, 64
  ]

let maskgen_functions =
  let module V = Netasn1.Value in
  let mfg1_oid = [| 1; 2; 840; 113549; 1; 8 |] in
  List.map
    (fun (h, h_asn1) ->
     (`MGF1 h, V.Seq [ V.OID mfg1_oid; h_asn1 ])
    )
    hash_functions


module Key = struct
  let rsa_key = [| 1; 2; 840; 113549; 1; 1; 1 |]
  let rsassa_pss_key = [| 1; 2; 840; 113549; 1; 1; 10 |]
  let rsaes_oaep_key = [| 1; 2; 840; 113549; 1; 1; 7 |]
  let dsa_key = [| 1; 2; 840; 10040; 4; 1 |]
  let dh_key = [| 1; 2; 840; 10046; 2; 1 |]
  let kea_key = [| 2; 16; 840; 1; 101; 2; 1; 1; 22 |]
  let ec_key = [| 1; 2; 840; 10045; 2; 1 |]
  let ecdh_key = [| 1; 3; 132; 1; 12 |]
  let ecmqv_key = [| 1; 3; 132; 1; 13 |]
  let eddsa_key = [| 1; 3; 101; 100 |]

  let catalog =
    [ ( "RSA",
        [ "RSA"; "PKCS-1"; "RSAES-PKCS1-v1_5" ],
        "RSA",
        rsa_key
      );
      ( "RSASSA-PSS",
        [ "RSASSA-PSS"; "RSASSA-PSS-PKCS1-v2_1" ],
        "RSA",
        rsassa_pss_key
      );
      ( "RSAES-OAEP",
        [ "RSAES-OAEP"; "RSAES-OAEP-PKCS1-v2_1" ],
        "RSA",
        rsaes_oaep_key
      );
      ( "DSA",      [ "DSA" ],    "DSA",   dsa_key);
      ( "DH",       [ "DH" ],     "DH",    dh_key);
      ( "KEA",      [ "KEA" ],    "KEA",   kea_key);
      ( "EC",       [ "EC" ],     "EC",    ec_key);
      ( "ECDH",     [ "ECDH" ],   "EC",    ecdh_key);
      ( "ECMQV",    [ "ECMQV" ],  "EC",    ecmqv_key);
      ( "EDDSA",    [ "EDDSA" ],  "EDDSA", eddsa_key)
    ]

  let private_key_format_of_key oid =
    (* get the private key format for a pubkey OID *)
    let _, _, format, _ =
      List.find
        (fun (_, _, _, o) -> o = oid)
        catalog in
    format


  let pspecified_oid = [| 1; 2; 840; 113549; 1; 1; 9 |]

  let create_rsassa_pss_alg_id ~hash_function ~maskgen_function ~salt_length ()=
    let module V = Netasn1.Value in
    let size = List.assoc hash_function hash_size in
    let hash_asn1 =
      if hash_function = `SHA_1 then
        []
      else
        [ V.ITag(V.Context, 0, List.assoc hash_function hash_functions) ] in
    let mg_asn1 =
      if maskgen_function = `MGF1 `SHA_1 then
        []
      else
        [ V.ITag(V.Context, 1, List.assoc maskgen_function maskgen_functions)
        ] in
    let slen_asn1 =
      if salt_length = size then
        []
      else
        [ V.ITag(V.Context, 2, V.Integer(V.int salt_length)) ] in
    let params =
      V.Seq
        (hash_asn1 @ mg_asn1 @ slen_asn1) in
    Alg_id(rsassa_pss_key, Some params)


  let create_rsassa_pss_key ~hash_function ~maskgen_function ~salt_length key =
    let Alg_id(oid, _) = key.pubkey_type in
    if oid <> rsa_key && oid <> rsassa_pss_key then
      failwith "Netx509_pubkey.Key.create_rsassa_pss_key";
    { key with
      pubkey_type = create_rsassa_pss_alg_id
                      ~hash_function ~maskgen_function ~salt_length ()
    }

  let parse_rsassa_pss_params v =
    let module V = Netasn1.Value in
    try
      match v with
        | V.Seq seq ->
            let seq' =
              Netasn1.streamline_seq
                [ (V.Context, 0, Netasn1.Type_name.Seq);
                  (V.Context, 1, Netasn1.Type_name.Seq);
                  (V.Context, 2, Netasn1.Type_name.Integer)
                ]
                seq in
            ( match seq' with
                | [ v_hf_opt; v_mgf_opt; int_opt ] ->
                    let h =
                      match v_hf_opt with
                        | Some v_hf ->
                            let h, _ =
                              List.find (fun (_, v) -> v_hf = v) hash_functions
                            in h
                        | None -> `SHA_1 in
                    let size = List.assoc h hash_size in
                    let mgf =
                      match v_mgf_opt with
                        | Some v_mgf ->
                            let mgf, _ =
                              List.find
                                (fun (_, v) -> v_mgf = v) maskgen_functions in
                            mgf
                        | None -> `MGF1 `SHA_1 in
                    let salt =
                      match int_opt with
                        | None -> size
                        | Some(V.Integer i) -> V.get_int i
                        | Some _ -> raise Not_found in
                    (h, mgf, salt)
              | _ ->
                  raise Not_found
          )
      | _ ->
          raise Not_found
    with 
      | Not_found
      | Netasn1.Out_of_range ->
          failwith "Netx509_pubkey.Key.parse_rsassa_pss_params"


  let create_rsaes_oaep_alg_id ~hash_function ~maskgen_function
                               ~psource_function () =
    let module V = Netasn1.Value in
    let hash_asn1 =
      if hash_function = `SHA_1 then
        []
      else
        [ V.ITag(V.Context, 0, List.assoc hash_function hash_functions) ] in
    let mg_asn1 =
      if maskgen_function = `MGF1 `SHA_1 then
        []
      else
        [ V.ITag(V.Context, 1, List.assoc maskgen_function maskgen_functions)
        ] in
    let psource_asn1 =
      if psource_function = "" then
        []
      else
        [ V.ITag(V.Context, 2, V.Seq [ V.OID pspecified_oid;
                                       V.Octetstring psource_function
                                     ]
                )
        ] in
    let params =
      V.Seq
        (hash_asn1 @ mg_asn1 @ psource_asn1) in
    Alg_id(rsaes_oaep_key, Some params)

  let create_rsaes_oaep_key ~hash_function ~maskgen_function ~psource_function
                            key =
    let Alg_id(oid, _) = key.pubkey_type in
    if oid <> rsa_key && oid <> rsaes_oaep_key then
      failwith "Netx509_pubkey.Key.create_rsaes_oaep_key";
    { key with
      pubkey_type =
        create_rsaes_oaep_alg_id ~hash_function ~maskgen_function
                                 ~psource_function ()
    }

  let parse_rsaes_oaep_params v =
    let module V = Netasn1.Value in
    try
      match v with
        | V.Seq seq ->
            let seq' =
              Netasn1.streamline_seq
                [ (V.Context, 0, Netasn1.Type_name.Seq);
                  (V.Context, 1, Netasn1.Type_name.Seq);
                  (V.Context, 2, Netasn1.Type_name.Seq)
                ]
                seq in
            ( match seq' with
                | [ v_hf_opt; v_mgf_opt; v_psrc_opt ] ->
                    let h =
                      match v_hf_opt with
                        | Some v_hf ->
                            let h, _ =
                              List.find (fun (_, v) -> v_hf = v) hash_functions
                            in h
                        | None -> `SHA_1 in
                    let mgf =
                      match v_mgf_opt with
                        | Some v_mgf ->
                            let mgf, _ =
                              List.find
                                (fun (_, v) -> v_mgf = v) maskgen_functions in
                            mgf
                        | None -> `MGF1 `SHA_1 in
                    let psrc =
                      match v_psrc_opt with
                        | Some (V.Seq [ V.OID oid; V.Octetstring s ])
                             when oid = pspecified_oid ->
                            s
                        | None ->
                            ""
                        | _ -> raise Not_found in
                    (h, mgf, psrc)
              | _ ->
                  raise Not_found
          )
      | _ ->
          raise Not_found
    with 
      | Not_found
      | Netasn1.Out_of_range ->
          failwith "Netx509_pubkey.Key.parse_rsaes_oaep_params"

  let alg_param_to_asn1 =
    function
    | P_PSS(h, mgf, salt) ->
        let Alg_id(_, p) =
          create_rsassa_pss_alg_id
            ~hash_function:h
            ~maskgen_function:mgf
            ~salt_length:salt
            () in
        p
    | P_OAEP(h, mgf, psrc) ->
        let Alg_id(_, p) =
          create_rsaes_oaep_alg_id
            ~hash_function:h
            ~maskgen_function:mgf
            ~psource_function:psrc
            () in
        p

end

module Encryption = struct
  let rsa = Encrypt(Key.rsa_key, None)
  let rsaes_oaep ~hash_function ~maskgen_function ~psource_function =
    let p = P_OAEP(hash_function, maskgen_function, psource_function) in
    Encrypt(Key.rsaes_oaep_key,Some p)

  let catalog =
    [ ( "RSA",
        [ "RSA"; "PKCS-1"; "RSAES-PKCS1-v1_5" ],
        rsa,
        Key.rsa_key
      )
    ]
    @
      List.map
        (fun (h,name) ->
           let full_name = "RSAES-OAEP-MGF1-" ^ name in
           ( full_name, [ full_name ],
             rsaes_oaep
               ~hash_function:h
               ~maskgen_function:(`MGF1 h)
               ~psource_function:"",
             Key.rsaes_oaep_key
           )
        )
        [ `SHA_1, "SHA1"; `SHA_224, "SHA224"; `SHA_256, "SHA256";
          `SHA_384, "SHA384"; `SHA_512, "SHA512"
        ]


  let encrypt_alg_of_pubkey pk =
    let Alg_id(oid,params) = pk.pubkey_type in
    if oid = Key.rsa_key then
      Encrypt(oid, None)
    else if oid = Key.rsaes_oaep_key then
      let params' =
        match params with
          | Some p ->
              let (h, mgf, psrc) = Key.parse_rsaes_oaep_params p in
              Some (P_OAEP(h, mgf, psrc))
          | None ->
              None in
      Encrypt(oid, params')
    else
      failwith "Netx509_pubkey.Encryption.encrypt_alg_of_pubkey: not an \
                encryption algorithm"


  let alg_id_of_encrypt_alg (Encrypt(oid,p_opt)) =
    let p_opt' =
      match p_opt with
        | None -> None
        | Some p -> Key.alg_param_to_asn1 p in
    Alg_id(oid, p_opt')


  let key_oid_of_encrypt_alg alg0 =
    let _, _, _, pubkey_oid =
      List.find
        (fun (_, _, alg, _) -> alg = alg0)
        catalog in
    pubkey_oid

end


module Keyagreement = struct
  let dh = Kex([| 1; 2; 840; 10046; 2; 1 |], None)
  let kea = Kex([| 2; 16; 840; 1; 101; 2; 1; 1; 22 |], None)
  let ec = Kex([| 1; 2; 840; 10045; 2; 1 |], None)
  let ecdh = Kex([| 1; 3; 132; 1; 12 |], None)
  let ecmqv = Kex([| 1; 3; 132; 1; 13 |], None)

  let catalog =
    [ ( "DH",       [ "DH" ],     dh,     Key.dh_key);
      ( "KEA",      [ "KEA" ],    kea,    Key.kea_key);
      ( "EC",       [ "EC" ],     ec,     Key.ec_key);
      ( "ECDH",     [ "ECDH" ],   ecdh,   Key.ecdh_key);
      ( "ECMQV",    [ "ECMQV" ],  ecmqv,  Key.ecmqv_key);
    ]

  let alg_id_of_kex_alg (Kex(oid,p_opt)) =
    let p_opt' =
      match p_opt with
        | None -> None
        | Some p -> Key.alg_param_to_asn1 p in
    Alg_id(oid, p_opt')


  let key_oid_of_kex_alg alg0 =
    let _, _, _, pubkey_oid =
      List.find
        (fun (_, _, alg, _) -> alg = alg0)
        catalog in
    pubkey_oid
end


module Signing = struct
  let rsa_with_sha1 = Sign([| 1; 2; 840; 113549; 1; 1; 5 |], None)
  let rsa_with_sha224 = Sign([| 1; 2; 840; 113549; 1; 1; 14 |], None)
  let rsa_with_sha256 = Sign([| 1; 2; 840; 113549; 1; 1; 11 |], None)
  let rsa_with_sha384 = Sign([| 1; 2; 840; 113549; 1; 1; 12 |], None)
  let rsa_with_sha512 = Sign([| 1; 2; 840; 113549; 1; 1; 13 |], None)
  let dsa_with_sha1 = Sign([| 1; 2; 840; 10040; 4; 3 |], None)
  let dsa_with_sha224 = Sign([| 2; 16; 840; 1; 101; 3; 4; 3; 1 |], None)
  let dsa_with_sha256 = Sign([| 2; 16; 840; 1; 101; 3; 4; 3; 2 |], None)
  let ecdsa_with_sha1 = Sign([| 1; 2; 840; 10045; 4; 1 |], None)
  let ecdsa_with_sha224 = Sign([| 1; 2; 840; 10045; 3; 1 |], None)
  let ecdsa_with_sha256 = Sign([| 1; 2; 840; 10045; 3; 2 |], None)
  let ecdsa_with_sha384 = Sign([| 1; 2; 840; 10045; 3; 3 |], None)
  let ecdsa_with_sha512 = Sign([| 1; 2; 840; 10045; 3; 4 |], None)
  let eddsa = Sign([| 1; 3; 101; 101 |], None)

  let rsassa_pss ~hash_function ~maskgen_function ~salt_length =
    Sign([| 1; 2; 840; 113549; 1; 1; 10 |], 
         Some(P_PSS(hash_function, maskgen_function, salt_length)))

  let catalog =
    [ ( "RSA-SHA1",
        [ "RSA-SHA1" ],
        rsa_with_sha1,
        Key.rsa_key
      );
      ( "RSA-SHA224",
        [ "RSA-SHA224" ],
        rsa_with_sha224,
        Key.rsa_key
      );
      ( "RSA-SHA256",
        [ "RSA-SHA256" ],
        rsa_with_sha256,
        Key.rsa_key
      );
      ( "RSA-SHA384",
        [ "RSA-SHA384" ],
        rsa_with_sha384,
        Key.rsa_key
      );
      ( "RSA-SHA512",
        [ "RSA-SHA512" ],
        rsa_with_sha512,
        Key.rsa_key
      );
      ( "DSA-SHA1",
        [ "DSA"; "DSA-SHA1" ],
        dsa_with_sha1,
        Key.dsa_key
      );
      ( "DSA-SHA224",
        [ "DSA-SHA224" ],
        dsa_with_sha224,
        Key.dsa_key
      );
      ( "DSA-SHA256",
        [ "DSA-SHA256" ],
        dsa_with_sha256,
        Key.dsa_key
      );
      ( "ECDSA-SHA1",
        [ "ECDSA-SHA1" ],
        ecdsa_with_sha1,
        Key.ec_key
      );
      ( "ECDSA-SHA224",
        [ "ECDSA-SHA224" ],
        ecdsa_with_sha224,
        Key.ec_key
      );
      ( "ECDSA-SHA256",
        [ "ECDSA-SHA256" ],
        ecdsa_with_sha256,
        Key.ec_key
      );
      ( "ECDSA-SHA384",
        [ "ECDSA-SHA384" ],
        ecdsa_with_sha384,
        Key.ec_key
      );
      ( "ECDSA-SHA512",
        [ "ECDSA-SHA512" ],
        ecdsa_with_sha512,
        Key.ec_key
      );
      ( "EDDSA",
        [ "EDDSA" ],
        eddsa,
        Key.eddsa_key
      )
    ]
    @
      List.map
        (fun (h,name) ->
           let full_name = "RSASSA-PSS-MGF1-" ^ name in
           ( full_name, [ full_name ],
             rsassa_pss
               ~hash_function:h
               ~maskgen_function:(`MGF1 h)
               ~salt_length:(List.assoc h hash_size),
             Key.rsassa_pss_key
           )
        )
        [ `SHA_1, "SHA1"; `SHA_224, "SHA224"; `SHA_256, "SHA256";
          `SHA_384, "SHA384"; `SHA_512, "SHA512"
        ]


  let alg_id_of_sign_alg (Sign(oid,p_opt)) =
    let p_opt' =
      match p_opt with
        | None -> None
        | Some p -> Key.alg_param_to_asn1 p in
    Alg_id(oid, p_opt')


  let key_oid_of_sign_alg alg0 =
    let _, _, _, pubkey_oid =
      List.find
        (fun (_, _, alg, _) -> alg = alg0)
        catalog in
    pubkey_oid

end

