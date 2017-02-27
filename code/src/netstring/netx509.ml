(* $Id$ *)

open Netasn1.Value
open Printf

type oid = Netoid.t
  (** OIDs are just integer sequences *)

exception Extension_not_found of oid

class type directory_name =
object
  method name : (oid * Netasn1.Value.value) list list
  method eq_name : (oid * Netasn1.Value.value) list list
  method string : string
  method eq_string : string
end



class type x509_certificate =
object
  method subject : directory_name
  method subject_unique_id : Netasn1.Value.bitstring_value option
  method issuer : directory_name
  method issuer_unique_id : Netasn1.Value.bitstring_value option
  method version : int
  method serial_number : string
  method valid_not_before : float
  method valid_not_after : float
  method signature : Netasn1.Value.bitstring_value
  method signature_algorithm : oid * Netasn1.Value.value option
  method public_key : Netasn1.Value.bitstring_value
  method public_key_algorithm : oid  * Netasn1.Value.value option
  method extensions : (oid * string * bool) list
end


module DN_attributes = struct
  let at k = [| 2; 5; 4; k |]

  let at_name = at 41
  let at_surname = at 4 
  let at_givenName = at 42
  let at_initials = at 43
  let at_generationQualifier = at 44
  let at_commonName = at 3
  let at_localityName = at 7
  let at_stateOrProvinceName = at 8
  let at_organizationName = at 10
  let at_organizationalUnitName = at 11
  let at_title = at 12
  let at_dnQualifier = at 46
  let at_countryName = at 6
  let at_serialNumber = at 5
  let at_pseudonym = at 65
  let at_domainComponent = [| 0; 9; 2342; 19200300; 100; 1; 25 |]
  let at_uid = [| 0; 9; 2342; 19200300; 100; 1; 1 |]
  let at_emailAddress = [| 1; 2; 840; 113549; 1; 9; 1 |]

  let attribute_types =
    [ at_name, "name", [ "name" ];
      at_surname, "surname", [ "sn"; "surname" ];
      at_givenName, "givenName", [ "gn"; "givenName" ];
      at_initials, "initials", [ "initials" ];
      at_generationQualifier, "generationQualifier", [ "generationQualifier" ];
      at_commonName, "commonName", [ "cn"; "commonName" ];
      at_localityName, "localityName", [ "l"; "localityName" ];
      at_stateOrProvinceName, "stateOrProvinceName", [ "st";
                                                       "stateOrProvinceName" ];
      at_organizationName, "organizationName", [ "o"; "organizationName" ];
      at_organizationalUnitName, "organizationalUnitName",
                                 [ "ou";
                                   "organizationalUnitName" ];
      at_title, "title", [ "title" ];
      at_dnQualifier, "dnQualifier", [ "dnQualifier" ];
      at_countryName, "countryName", [ "c"; "countryName" ];
      at_serialNumber, "serialNumber", [ "serialNumber" ];
      at_pseudonym, "pseudonym", [ "pseudonym" ];
      at_domainComponent, "domainComponent", [ "dc"; "domainComponent" ];
      at_emailAddress, "emailAddress", [ "email"; "emailAddress";
                                         "pkcs9email" ];
      at_uid, "userid", [ "uid"; "userid" ];
    ]

  let attribute_types_lc =
    List.map
      (fun (oid, name, l) -> (oid, name, List.map STRING_LOWERCASE l))
      attribute_types

  let lookup_attribute_type_by_oid oid =
    let (_, n, l) =
      List.find (fun (o,_,_) -> o = oid) attribute_types in
    (n,l)

  let lookup_attribute_type_by_name n =
    let lc = STRING_LOWERCASE n in
    List.find
      (fun (_,_,l) -> List.mem lc l)
      attribute_types_lc
end


module X509_DN_string = Netdn.DN_string_generic(DN_attributes)


let list_list_map f l1 =
  List.map (fun l2 -> List.map f l2) l1


let dn_uppercase =
  (* both PrintableString and IA5String are ASCII subsets *)
  function
  | PrintableString s ->
       PrintableString (STRING_UPPERCASE s)
  | IA5String s ->
       IA5String (STRING_UPPERCASE s)
  | other ->
       other


let eq_normalize name =
  let name1 =
    list_list_map
      (fun (oid, att) ->
         let to_upper =
           (match att with
              | PrintableString _ -> true
              | IA5String _ -> oid = DN_attributes.at_emailAddress
              | _ -> false
           ) in
         if to_upper then
           (oid, dn_uppercase att)
         else
           (oid, att)
      )
      name in
  List.map
    (fun rdn ->
       List.sort (fun (oid1,_) (oid2,_) -> Netoid.compare oid1 oid2) rdn
    )
    name1


class x509_dn_from_ASN1 v =
  let name =
    match v with
      | Seq dn_l ->
           List.map
             (fun rdn ->
                match rdn with
                  | Set rdn_l ->
                       List.map
                         (fun ava ->
                            match ava with
                              | Seq [ OID oid; any ] ->
                                   (oid, any)
                              | _ ->
                                   failwith "Netx509.x509_dn_from_ASN1"
                         )
                         rdn_l
                  | _ ->
                       failwith "Netx509.x509_dn_from_ASN1"
             )
             dn_l
      | _ ->
           failwith "Netx509.x509_dn_from_ASN1" in
  let eq_name_lz =
    lazy (eq_normalize name) in
  let string_lz =
    lazy (X509_DN_string.print name) in
  let eq_string_lz =
    lazy (X509_DN_string.print (Lazy.force eq_name_lz)) in

object(self)
  method name = name
  method eq_name = Lazy.force eq_name_lz
  method string = Lazy.force string_lz
  method eq_string = Lazy.force eq_string_lz
end


class x509_dn_from_string s =
  let name = X509_DN_string.parse s in
  let eq_name_lz =
    lazy (eq_normalize name) in
  let string_lz =
    lazy (X509_DN_string.print name) in
  let eq_string_lz =
    lazy (X509_DN_string.print (Lazy.force eq_name_lz)) in

object(self)
  method name = name
  method eq_name = Lazy.force eq_name_lz
  method string = Lazy.force string_lz
  method eq_string = Lazy.force eq_string_lz
end


let lookup_dn_ava (dn:directory_name) oid =
  let rel_dn =
    List.find
      (fun rel_dn ->
         match rel_dn with
           | [ oid1, v ] -> oid1 = oid
           | _ -> false
      )
      dn#name in
  match rel_dn with
    | [ _, v ] -> v
    | _ -> assert false


let lookup_dn_ava_utf8 dn oid =
  let v = lookup_dn_ava dn oid in
  Netdn.directory_string_from_ASN1 v


let map_opt f =
  function
  | None -> None
  | Some x -> Some(f x)


class x509_certificate_from_ASN1 asn1 =
  let fail() =
    failwith "Netx509.x509_certificate_from_ASN1" in
  let parse_time asn1 =
    Netdate.since_epoch
      (match asn1 with
         | UTCTime tval -> get_time tval
         | GeneralizedTime tval -> get_time tval
         | _ -> fail()
      ) in
  let parse_algo_id asn1 =
    match asn1 with
      | Seq [ OID oid ] -> (oid, None) 
      | Seq [ OID oid; param ] -> (oid, Some param)
      | _ -> fail() in

  let tbs_cert_l0, sig_algo_asn1, sig_value_bits =
    match asn1 with
      | Seq [ Seq tbs_cert_l0; sig_algo_asn1; Bitstring sig_value_bits ] ->
           (tbs_cert_l0, sig_algo_asn1, sig_value_bits)
      | _ ->
           fail() in
  let version_asn1, tbs_cert_l1 =
    (* explicitly tagged *)
    match tbs_cert_l0 with
      | Tag(Context, 0, Constructed, version_asn1) :: tbs_cert_l1 ->
           (Some version_asn1, tbs_cert_l1)
      | Tagptr(Context, 0, Constructed, box, pos, len) :: tbs_cert_l1 ->
           let Netstring_tstring.Tstring_polybox(ops,s) = box in
           let (k, version_asn1) =
             Netasn1.decode_ber_poly ~pos ~len ops s in
           if k <> len then fail();
           (Some version_asn1, tbs_cert_l1)
      | _ ->
           (None, tbs_cert_l0) in
  let version =
    match version_asn1 with
      | Some (Integer i) ->
           let version = get_int i in
           if version < 0 || version > 2 then fail();
           version+1
      | Some _ -> 
           fail()
      | None ->
           1 in
  let sig_algo = parse_algo_id sig_algo_asn1 in
  let cert_serial_int, sigtoo_algo_asn1, issuer_asn1, validity_asn1,
      subject_asn1, subjectpki_asn1, tbs_cert_l2  =
    match tbs_cert_l1 with
      | (Integer cert_serial_int) ::
        algoIdent_asn1 ::
        issuer_asn1 ::
        validity_asn1 ::
        subject_asn1 ::
        subjectpki_asn1 :: 
          tbs_cert_l2 -> (cert_serial_int,
                          algoIdent_asn1,
                          issuer_asn1,
                          validity_asn1,
                          subject_asn1,
                          subjectpki_asn1,
                          tbs_cert_l2)
      | _ ->
           fail() in
  let cert_serial_str = get_int_repr cert_serial_int in
  let sigtoo_algo = parse_algo_id sigtoo_algo_asn1 in
  let sig_algo_ok =
    fst sig_algo = fst sigtoo_algo &&
      match snd sig_algo, snd sigtoo_algo with
        | Some p1, Some p2 -> 
             Netasn1.Value.equal p1 p2
        | None, None ->
             true
        | _ ->
             false in
  let () =
    if not sig_algo_ok then fail() in
  let issuer = new x509_dn_from_ASN1 issuer_asn1 in
  let subject = new x509_dn_from_ASN1 subject_asn1 in
  let not_before, not_after =
    match validity_asn1 with
      | Seq [ not_before_asn1; not_after_asn1 ] ->
           (parse_time not_before_asn1, parse_time not_after_asn1) 
      | _ ->
           fail() in
  let pubkey_algo, pubkey_data =
    match subjectpki_asn1 with
      | Seq [ algo_asn1; Bitstring bits ] ->
           (parse_algo_id algo_asn1, bits)
      | _ ->
           fail() in
  let issuer_uqid_asn1, tbs_cert_l3 =
    (* implicitly tagged *)
    match tbs_cert_l2 with
      | Tagptr(Context, 1, Primitive, box, pos, len) :: tbs_cert_l3 ->
           let Netstring_tstring.Tstring_polybox(ops, s) = box in
           let n, issuer_uqid_asn1 =
             Netasn1.decode_ber_contents_poly
               ~pos ~len ops s Primitive Netasn1.Type_name.Bitstring in
           if n <> len then fail();
           (Some issuer_uqid_asn1, tbs_cert_l3)
      | Tag(Context, 1, Primitive, issuer_uqid_asn1) :: tbs_cert_l3 ->
           (Some issuer_uqid_asn1, tbs_cert_l3)
      | _ ->
           (None, tbs_cert_l2) in
  let issuer_uqid_bits =
    map_opt
      (function
        | Bitstring bits -> bits
        | _ -> fail()
      )
      issuer_uqid_asn1 in
  let () =
    if issuer_uqid_bits <> None && version < 2 then fail() in
  let subject_uqid_asn1, tbs_cert_l4 =
    (* implicitly tagged *)
    match tbs_cert_l3 with
      | Tagptr(Context, 2, Primitive, box, pos, len) :: tbs_cert_l4 ->
           let Netstring_tstring.Tstring_polybox(ops, s) = box in
           let n, subject_uqid_asn1 =
             Netasn1.decode_ber_contents_poly
               ~pos ~len ops s Primitive Netasn1.Type_name.Bitstring in
           if n <> len then fail();
           (Some subject_uqid_asn1, tbs_cert_l4)
      | Tag(Context, 2, Primitive, subject_uqid_asn1) :: tbs_cert_l4 ->
           (Some subject_uqid_asn1, tbs_cert_l4)
      | _ ->
           (None, tbs_cert_l3) in
  let subject_uqid_bits =
    map_opt
      (function
        | Bitstring bits -> bits
        | _ -> fail()
      )
      subject_uqid_asn1 in
  let () =
    if subject_uqid_bits <> None && version < 2 then fail() in
  let exts_asn1 =
    (* explicitly tagged *)
    match tbs_cert_l4 with
      | [ Tag(Context, 3, Constructed, exts_asn1) ] ->
           Some exts_asn1
      | [ Tagptr(Context, 3, Constructed, box, pos, len) ] ->
           let Netstring_tstring.Tstring_polybox(ops, s) = box in
           let (k, exts_asn1) =
             Netasn1.decode_ber_poly ~pos ~len ops s in
           if k <> len then fail();
           Some exts_asn1
      | [] ->
           None
      | _ ->
           fail() in
  let extensions =
    match exts_asn1 with
      | Some(Seq l) ->
           if l = [] then fail();
           List.map
             (fun seq ->
                match seq with
                  | Seq [ OID oid; Octetstring extval ] ->
                       (oid, extval, false)
                  | Seq [ OID oid; Bool crit; Octetstring extval ] ->
                       (oid, extval, crit)
                  | _ ->
                       fail()
             )
             l
      | Some _ -> fail()
      | None -> [] in
  let () =
    if extensions <> [] && version < 3 then fail() in

  ( object(self)
      method version = version
      method serial_number = cert_serial_str
      method issuer = issuer
      method issuer_unique_id = issuer_uqid_bits
      method subject = subject
      method subject_unique_id = subject_uqid_bits  
      method signature = sig_value_bits
      method signature_algorithm = sig_algo
      method valid_not_before = not_before
      method valid_not_after = not_after
      method public_key = pubkey_data
      method public_key_algorithm = pubkey_algo
      method extensions = extensions
  end
  )


class x509_certificate_from_DER s =
  let fail() =
    failwith "Netx509.x509_certificate_from_DER" in
  let n, asn1 = 
    try Netasn1.decode_ber s
    with _ -> fail() in
  let () =
    if n <> String.length s then fail() in
  x509_certificate_from_ASN1 asn1


module CE = struct
  let ce k = [| 2; 5; 29; k |]
  let pe k = [| 1; 3; 6; 1; 5; 5; 7; 1; k |]

  let ce_authority_key_identifier = ce 35
  let ce_subject_key_identifier = ce 14
  let ce_key_usage = ce 15
  let ce_certificate_policies = ce 32
  let ce_any_policy = Array.append (ce 32) [| 0 |]
  let ce_policy_mappings = ce 33
  let ce_subject_alt_name = ce 17
  let ce_issuer_alt_name = ce 18
  let ce_subject_directory_attributes = ce 9
  let ce_basic_constraints = ce 19
  let ce_name_constraints = ce 30
  let ce_policy_constraints = ce 36
  let ce_ext_key_usage = ce 37
  let ce_crl_distribution_points = ce 31
  let ce_inhibit_any_policy = ce 54
  let ce_freshest_crl = ce 46
  let ce_authority_info_access = pe 1
  let ce_subject_info_access = pe 11

  let certificate_extensions =
    [ ce_authority_key_identifier, "authorityKeyIdentifier";
      ce_subject_key_identifier, "subjectKeyIdentifier";
      ce_key_usage, "keyUsage";
      ce_certificate_policies, "certificatePolicies";
      ce_any_policy, "anyPolicy";
      ce_policy_mappings, "policyMappinggs";
      ce_subject_alt_name, "subjectAltName";
      ce_issuer_alt_name, "issuerAltName";
      ce_subject_directory_attributes, "subjectDirectoryAttributes";
      ce_basic_constraints, "basicConstraints";
      ce_name_constraints, "nameConstraints";
      ce_policy_constraints, "policyConstraints";
      ce_ext_key_usage, "extKeyUsage";
      ce_crl_distribution_points, "cRLDistributionPoints";
      ce_inhibit_any_policy, "inhibitAnyPolicy";
      ce_freshest_crl, "freshestCRL";
      ce_authority_info_access, "authorityInfoAccess";
      ce_subject_info_access, "subjectInfoAccess"
    ]
end


type ext_key_usage_flag =
    [ `Server_auth
    | `Client_auth
    | `Code_signing
    | `Email_protection
    | `Time_stamping
    | `OCSP_signing
    | `Unknown
    ]


module KP = struct
  let kp k = [| 1; 3; 6; 1; 5; 5; 7; 3; k |]

  let kp_server_auth = kp 1
  let kp_client_auth = kp 2
  let kp_code_signing = kp 3 
  let kp_email_protection = kp 4
  let kp_time_stamping = kp 8
  let kp_ocsp_signing = kp 9

  let ext_key_purposes =
    [ kp_server_auth, `Server_auth, "serverAuth";
      kp_client_auth, `Client_auth, "clientAuth";
      kp_code_signing, `Code_signing, "codeSigning";
      kp_email_protection, `Email_protection, "emailProtection";
      kp_time_stamping, `Time_stamping, "timeStamping";
      kp_ocsp_signing, `OCSP_signing, "OCSPSigning";
    ]
end

type authority_access_description_flag =
  [ `CA_issuers
  | `OCSP
  | `Unknown
  ]

type subject_access_description_flag =
  [ `CA_repository
  | `Time_stamping
  | `Unknown
  ]

type access_description_flag =
  [ authority_access_description_flag | subject_access_description_flag ]


module AD = struct
  let ad k = [| 1; 3; 6; 1; 5; 5; 7; 48; k |]

  let ad_ca_issuers = ad 2
  let ad_ocsp = ad 1
  let ad_ca_repository = ad 5
  let ad_time_stamping = ad 3

  let access_descriptions =
    [ ad_ca_issuers, `CA_issuers, "caIssuers";
      ad_ocsp, `OCSP, "ocsp";
      ad_ca_repository, `CA_repository, "caRepository";
      ad_time_stamping, `Time_stamping, "timeStamping";
    ]
end

type general_name =
  [ `Other_name of oid * Netasn1.Value.value
  | `Rfc822_name of string
  | `DNS_name of string
  | `X400_address of Netasn1.Value.value
  | `Directory_name of directory_name
  | `Edi_party_name of string option * string
  | `Uniform_resource_identifier of string 
  | `IP_address of Unix.socket_domain * Unix.inet_addr * Unix.inet_addr
  | `Registered_ID of oid
  ]

let find_extension oid exts =
  try
    let (_, data, critical) =
      List.find
        (fun (xoid, _, _) -> xoid = oid)
        exts in
    (data, critical)
  with Not_found ->
       raise (Extension_not_found oid)

let check_critical_exts oids exts =
  let ht = Hashtbl.create 20 in
  List.iter (fun oid -> Hashtbl.add ht oid ()) oids;
  List.for_all
    (fun (oid, _, critical) -> critical && not(Hashtbl.mem ht oid))
    exts

let directory_string_from_ASN1 v =
  Netdn.directory_string_from_ASN1 v

let resolve_explicit_tag fail =
  function
  | Tag(_,_,_,v) -> v
  | Tagptr(_,_,_,box,pos,len) -> 
       let Netstring_tstring.Tstring_polybox(ops, s) = box in
       let (k, inner) = Netasn1.decode_ber_poly ~pos ~len ops s in
       if k <> len then fail();
       inner
  | _ -> assert false

let resolve_implicit_tag fail t =
  function
  | Tag(_,_,_,v) -> v
  | Tagptr(_,_,pc,box,pos,len) -> 
       let Netstring_tstring.Tstring_polybox(ops, s) = box in
       let (k,inner) = Netasn1.decode_ber_contents_poly ~pos ~len ops s pc t in
       if k <> len then fail();
       inner
  | _ -> assert false

let general_name_from_ASN1 v : general_name =
  let fail() = failwith "Netx509.general_name_from_ASN1: parse_error" in

  let parse_other_name v =
    match v with
      | Seq [ OID oid;
              (* explicitly tagged *)
              ( Tag(Context, 0, Constructed, _) |
                Tagptr(Context, 0, Constructed, _, _, _)
              ) as tagged_other_val
            ] -> 
           let other_val = resolve_explicit_tag fail tagged_other_val in
           `Other_name(oid, other_val)
      | _ ->
           fail() in

  let parse_rfc822_name v =
    match v with
      | IA5String u -> `Rfc822_name u
      | _ -> fail() in

  let parse_dns_name v =
    match v with
      | IA5String u -> `DNS_name u
      | _ -> fail() in

  let parse_url v =
    match v with
      | IA5String u -> `Uniform_resource_identifier u
      | _ -> fail() in

  let parse_edi_party_name v =
    match v with
      | Seq [ ( Tag(Context, 0, Constructed, _) |
                Tagptr(Context, 0, Constructed, _, _, _)) as tagged_assigner;
              ( Tag(Context, 1, Constructed, _) |
                Tagptr(Context, 1, Constructed, _, _, _)) as tagged_party
            ] ->
           let v_assigner = resolve_explicit_tag fail tagged_assigner in
           let v_party = resolve_explicit_tag fail tagged_party in
           let assigner = directory_string_from_ASN1 v_assigner in
           let party = directory_string_from_ASN1 v_party in
           `Edi_party_name(Some assigner, party)
      | Seq [ ( Tag(Context, 1, Constructed, _) |
                Tagptr(Context, 1, Constructed, _, _, _) ) as tagged_party
            ] ->
           let v_party = resolve_explicit_tag fail tagged_party in
           let party = directory_string_from_ASN1 v_party in
           `Edi_party_name(None, party)
      | _ -> fail() in

  let parse_ip_address v =
    match v with
      | Octetstring u ->
           if String.length u = 8 then
             let addr = String.sub u 0 4 in
             let mask = String.sub u 4 4 in
             `IP_address(Unix.PF_INET,
                         Netsys.inet_addr_of_protostring addr,
                         Netsys.inet_addr_of_protostring mask)
           else if String.length u = 32 then
             let addr = String.sub u 0 16 in
             let mask = String.sub u 16 16 in
             `IP_address(Unix.PF_INET6,
                         Netsys.inet_addr_of_protostring addr,
                         Netsys.inet_addr_of_protostring mask)
           else
             fail()
      | _ ->
           fail() in

  let parse_registered_id v =
    match v with
      | OID oid -> `Registered_ID oid
      | _ -> fail() in

  (* implicitly tagged except for directory strings *)
  match v with
    | Tagptr(Context, 0, Primitive, box, pos, len) ->
         (* other_name *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.Seq in
         if k <> len then fail();
         parse_other_name w
 
   | Tag(Context, 0, Primitive, w) ->
         parse_other_name w
         
    | Tagptr(Context, 1, Primitive, box, pos, len) ->
         (* rfc822_name *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.IA5String in
         if k <> len then fail();
         parse_rfc822_name w

    | Tag(Context, 1, Primitive, w) ->
         parse_rfc822_name w

    | Tagptr(Context, 2, Primitive, box, pos, len) ->
         (* dns_name *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.IA5String in
         if k <> len then fail();
         parse_dns_name w

    | Tag(Context, 2, Primitive, w) ->
         parse_dns_name w

    | Tagptr(Context, 3, Primitive, box, pos, len) ->
         (* x400_address *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.IA5String in
         if k <> len then fail();
         `X400_address w

    | Tag(Context, 3, Primitive, w) ->
         `X400_address w

    | ( Tag(Context, 4, Constructed, _)
      | Tagptr(Context, 4, Constructed, _, _, _)) as tagged ->
         (* directory_name *)
         (* This is EXPLICIT because a name is an untagged choice type
            (see section 31.2.7 in X.690 (2008))
          *)
         let w = resolve_explicit_tag fail tagged in
         `Directory_name(new x509_dn_from_ASN1 w)

    | Tagptr(Context, 5, Primitive, box, pos, len) ->
         (* edi_party_name *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.Seq in
         if k <> len then fail();
         parse_edi_party_name w

    | Tag(Context, 5, Primitive, w) ->
         parse_edi_party_name w

    | Tagptr(Context, 6, Primitive, box, pos, len) ->
         (* uniform_resource_identifier *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.IA5String in
         if k <> len then fail();
         parse_url w

    | Tag(Context, 6, Primitive, w) ->
         parse_url w

    | Tagptr(Context, 7, Primitive, box, pos, len) ->
         (* ip_address *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.Octetstring in
         if k <> len then fail();
         parse_ip_address w

    | Tag(Context, 7, Primitive, w) ->
         parse_ip_address w

    | Tagptr(Context, 8, Primitive, box, pos, len) ->
         (* registered_id *)
         let Netstring_tstring.Tstring_polybox(ops, s) = box in
         let k, w = 
           Netasn1.decode_ber_contents_poly ~pos ~len ops s Primitive 
                                            Netasn1.Type_name.OID in
         if k <> len then fail();
         parse_registered_id w

    | Tag(Context, 8, Primitive, w) ->
         parse_registered_id w

    | _ ->
         fail()

let general_names_from_ASN1 v =
  match v with
    | Seq l ->
         List.map general_name_from_ASN1 l
    | _ ->
         failwith "Netx509.general_names_from_ASN1: parse error"

let parse_subject_alt_name s =
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then failwith "Netx509.parse_subject_alt_name";
  general_names_from_ASN1 v


let parse_issuer_alt_name s =
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then failwith "Netx509.parse_issuer_alt_name";
  general_names_from_ASN1 v



type authority_key_identifier =
    { aki_key_identifier : string option;
      aki_authority_cert_issuer : general_name list;
      aki_authority_cert_serial_number : string option;
    }


let parse_authority_key_identifier s =
  let fail () =
    failwith "Netx509.parse_authority_key_identifier" in

  let parse_keyid =
    function
    | Octetstring s -> s
    | _ -> fail() in

  let parse_serno =
    function
    | Integer i -> get_int_repr i
    | _ -> fail() in

  let k, v = Netasn1.decode_ber s in
  if k <> String.length s then fail();
  match v with
    | Seq l1 ->
         let keyid_opt, l2 =
           match l1 with
             (* implicitly tagged *)
             | ( ( Tagptr(Context, 0, Primitive, _, _, _)
                 | Tag(Context, 0, Primitive, _)
                 ) as tagged_keyid
               ) :: l2 ->
                 let v_keyid = 
                   resolve_implicit_tag
                     fail Netasn1.Type_name.Octetstring tagged_keyid in
                 let keyid = parse_keyid v_keyid in
                 Some keyid, l2
             | _ ->
                  None, l1 in
         let names, l3 =
           match l2 with
             (* implicitly tagged *)
             | ( ( Tagptr(Context, 1, Constructed, _, _, _)
                 | Tag(Context, 1, Constructed, _)
                 ) as tagged_names
               ) :: l3 ->
                 let v_names = 
                   resolve_implicit_tag
                     fail Netasn1.Type_name.Seq tagged_names in
                 let names = general_names_from_ASN1 v_names in
                 names, l3
             | _ ->
                  [], l2 in
         let serno_opt =
           match l3 with
             (* implicitly tagged *)
             | [ ( Tagptr(Context, 2, Primitive, _, _, _)
                 | Tag(Context, 2, Primitive, _)
                 ) as tagged_serno
               ] ->
                  let v_serno =
                   resolve_implicit_tag
                     fail Netasn1.Type_name.Integer tagged_serno in
                  let serno = parse_serno v_serno in
                  Some serno
             | [] ->
                  None
             | _ ->
                  fail() in
         { aki_key_identifier = keyid_opt;
           aki_authority_cert_issuer = names;
           aki_authority_cert_serial_number = serno_opt
         }
    | _ ->
         fail()

                  
let parse_subject_key_identifier s =
  let fail() = failwith "Netx509.parse_subject_key_identifier" in
  let k, v = Netasn1.decode_ber s in
  if k <> String.length s then fail();
  match v with
    | Octetstring s -> s
    | _ -> fail()


type key_usage_flag =
  [ `Digital_signature
  | `Non_repudiation
  | `Key_encipherment
  | `Data_encipherment
  | `Key_agreement
  | `Key_cert_sign
  | `Crl_sign
  | `Encipher_only
  | `Decipher_only
  ]

let parse_key_usage s =
  let fail() = failwith "Netx509.parse_key_usage" in
  let k, v = Netasn1.decode_ber s in
  if k <> String.length s then fail();
  match v with
    | Bitstring b ->
         if get_bitstring_size b <> 9 then fail();
         let bits = get_bitstring_bits b in
         ( match bits with
             | [| digital_signature;
                  non_repudiation;
                  key_encipherment;
                  data_encipherment;
                  key_agreement;
                  key_cert_sign;
                  crl_sign;
                  encipher_only;
                  decipher_only;
               |] ->
                  let l =
                    [ `Digital_signature, digital_signature;
                      `Non_repudiation, non_repudiation;
                      `Key_encipherment, key_encipherment;
                      `Data_encipherment, data_encipherment;
                      `Key_agreement, key_agreement;
                      `Key_cert_sign, key_cert_sign;
                      `Crl_sign, crl_sign;
                      `Encipher_only, encipher_only;
                      `Decipher_only, decipher_only
                    ] in
                  List.map fst (List.filter (fun (_, flag) -> flag) l)
             | _ ->
                  fail()
         )
    | _ ->
         fail()

let attribute_from_ASN1 v =
  let fail() = failwith "Netx509.attribute_from_ASN1" in
  match v with
    | Seq [ OID oid;
            Seq l 
          ] ->
       (oid, l)
    | _ ->
         fail()

let attributes_from_ASN1 v =
  let fail() = failwith "Netx509.attributes_from_ASN1" in
  match v with
    | Seq l ->
         List.map attribute_from_ASN1 l
    | _ ->
         fail()

let parse_subject_directory_attributes s =
  let fail() = failwith "Netx509.parse_subject_directory_attributes" in
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then fail();
  attributes_from_ASN1 v


let parse_basic_constraints s =
  let fail() = failwith "Netx509.parse_basic_constraints" in
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then fail();
  match v with
    | Seq [] ->
         (false, None)
    | Seq [ Bool ca ] ->
         (ca, None)
    | Seq [ Integer path_len ] ->
         (false, Some(get_int path_len))
    | Seq [ Bool ca; Integer path_len ] ->
         (ca, Some(get_int path_len))
    | _ ->
         fail()


let parse_ext_key_usage s =
  let fail() = failwith "Netx509.parse_ext_key_usage" in
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then fail();
  match v with
    | Seq l ->
         let oids =
           List.map
             (function OID oid -> oid | _ -> fail())
             l in
         List.map
           (fun oid ->
             try
               let (_, flag, _) = 
                 List.find
                   (fun (o, _, _) -> o = oid)
                   KP.ext_key_purposes in
               (oid, flag)
             with Not_found -> (oid, `Unknown)
           )
           oids
    | _ ->
         fail()


let parse_info_access s =
  let fail() = failwith "Netx509.parse_info_access" in
  let n, v = Netasn1.decode_ber s in
  if n <> String.length s then fail();
  match v with
    | Seq l ->
         List.map
           (fun u ->
              match u with
                | Seq [ OID oid; v_gen_name ] ->
                     let gen_name = general_name_from_ASN1 v_gen_name in
                     let flag =
                       try
                         let _, flag, _ =
                           List.find
                             (fun (o,_,_) -> o = oid)
                             AD.access_descriptions in
                         flag
                       with Not_found -> `Unknown in
                     (oid, flag, gen_name)
                | _ ->
                     fail()
           )
           l
    | _ ->
         fail()


let parse_authority_info_access s = 
  let l = parse_info_access s in
  List.map
    (fun (oid, flag, name) ->
       match flag with
         | #authority_access_description_flag as flag' -> (oid, flag', name)
         | _ -> (oid, `Unknown, name)
    )
    l


let parse_subject_info_access s =
  let l = parse_info_access s in
  List.map
    (fun (oid, flag, name) ->
       match flag with
         | #subject_access_description_flag as flag' -> (oid, flag', name)
         | _ -> (oid, `Unknown, name)
    )
    l

