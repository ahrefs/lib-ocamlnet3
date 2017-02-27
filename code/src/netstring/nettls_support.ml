(* $Id$ *)

open Printf

type credentials =
  [ `X509 of Netx509.x509_certificate
  | `Anonymous
  ]

type raw_credentials =
  [ `X509 of string
  | `Anonymous
  ]

type cred_type =
  [ `X509
  | `Anonymous
  ]

class type tls_session_props =
object
  method id : string
  method addressed_server : string option
  method cipher_suite_type : string
  method endpoint_credentials : credentials
  method endpoint_credentials_type : cred_type
  method endpoint_credentials_raw : raw_credentials
  method peer_credentials : credentials
  method peer_credentials_type : cred_type
  method peer_credentials_raw : raw_credentials
  method cipher_algo : string
  method kx_algo : string
  method mac_algo : string
  method compression_algo : string
  method protocol : string
end


let cred_type =
  function
  | `X509 _ -> `X509
  | `Anonymous -> `Anonymous

let parse_creds =
  function
  | `X509 der -> `X509 (new Netx509.x509_certificate_from_DER der)
  | `Anonymous -> `Anonymous
       


let get_tls_session_props (ep:Netsys_crypto_types.tls_endpoint) 
    : tls_session_props =
  let module Endpoint =
    (val ep : Netsys_crypto_types.TLS_ENDPOINT) in
  let module TLS =
    Endpoint.TLS in
  let e1 = Endpoint.endpoint in
  let id = TLS.get_session_id e1 in
  let sni_l =
    try TLS.get_addressed_servers e1
    with 
      | TLS.Exc.TLS_error ""
      | TLS.Exc.TLS_error "GNUTLS_E_INVALID_REQUEST"  -> [] in
  let sni =
    match sni_l with
      | `Domain n :: _ -> Some n
      | [] -> None in
  let cs_type = TLS.get_cipher_suite_type e1 in
  let ep_creds = TLS.get_endpoint_creds e1 in
  let ep_creds_lz = lazy(parse_creds ep_creds) in
  let p_creds = TLS.get_peer_creds e1 in
  let p_creds_lz = lazy(parse_creds p_creds) in
  let cipher_algo = TLS.get_cipher_algo e1 in
  let kx_algo = TLS.get_kx_algo e1 in
  let mac_algo = TLS.get_mac_algo e1 in
  let compression_algo = TLS.get_compression_algo e1 in
  let protocol = TLS.get_protocol e1 in
  ( object(self)
      method id = id
      method addressed_server = sni
      method cipher_suite_type = cs_type
      method endpoint_credentials_raw = ep_creds
      method endpoint_credentials_type = cred_type ep_creds
      method endpoint_credentials = Lazy.force ep_creds_lz
      method peer_credentials_raw = p_creds
      method peer_credentials_type = cred_type p_creds
      method peer_credentials = Lazy.force p_creds_lz
      method cipher_algo = cipher_algo
      method kx_algo = kx_algo
      method mac_algo = mac_algo
      method compression_algo = compression_algo
      method protocol = protocol
    end
  )


let squash_file_tls_endpoint file_ep =
  let module FEP =
    (val file_ep : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module EP =
    struct
      module TLS = FEP.TLS
      let endpoint = FEP.endpoint
    end in
  (module EP : Netsys_crypto_types.TLS_ENDPOINT)


let get_tls_user_name props =
  let rec search_dn_loop dn at_list =
    match at_list with
      | [] ->
           raise Not_found
      | at :: at_list' ->
           try
             Netx509.lookup_dn_ava_utf8 dn at
           with
             | Not_found -> search_dn_loop dn at_list' in
  let search_dn dn =
    search_dn_loop
      dn
      [ Netx509.DN_attributes.at_uid;
        Netx509.DN_attributes.at_emailAddress;
        Netx509.DN_attributes.at_commonName;
      ] in

  match props # peer_credentials with
    | `X509 cert ->
         ( try
             let (san_der, _) =
               Netx509.find_extension
                 Netx509.CE.ce_subject_alt_name
                 cert#extensions in
             let san = Netx509.parse_subject_alt_name san_der in
             try
               let san_email =
                 List.find
                   (function
                     | `Rfc822_name n -> true
                     | _ -> false
                   )
                   san in
               match san_email with
                 | `Rfc822_name n -> n
                 | _ -> assert false
             with
               | Not_found ->
                    let san_dn =
                      List.find
                        (function
                          | `Directory_name n -> true
                          | _ -> false
                        )
                        san in
                    match san_dn with
                      | `Directory_name dn ->
                           search_dn dn
                      | _ -> assert false
           with
             | Not_found
             | Netx509.Extension_not_found _ ->
                  search_dn cert#subject
         )
    | _ ->
         raise Not_found


let dot_re = Netstring_str.regexp "[.]"


let match_hostname n1 n2 =
  (* n1 may contain "*" as domain component patterns *)
  let l1 = Netstring_str.split dot_re n1 in
  let l2 = Netstring_str.split dot_re n2 in
  List.length l1 = List.length l2 &&
    List.for_all2
      (fun dc1 dc2 ->
         dc1 = "*" || STRING_UPPERCASE dc1 = STRING_UPPERCASE dc2
      )
      l1
      l2
  

let is_dns_name =
  function `DNS_name _ -> true | _ -> false

let is_this_dns_name n1 =
  function `DNS_name n2 -> match_hostname n2 n1 | _ -> false

let is_endpoint_host name (props : tls_session_props) =
  match props # endpoint_credentials with
    | `X509 cert ->
         ( try
             let data, _ =
               Netx509.find_extension 
                 Netx509.CE.ce_subject_alt_name cert#extensions in
             let san = Netx509.parse_subject_alt_name data in
             (* if there is any DNS alternate name, one of these
                         names must match
              *)
             if not(List.exists is_dns_name san) then
               raise Not_found;
             List.exists (is_this_dns_name name) san
           with
             | Netx509.Extension_not_found _ 
             | Not_found ->
                  let subj = cert#subject in
                  let cn = 
                    Netx509.lookup_dn_ava_utf8
                      subj Netx509.DN_attributes.at_commonName in
                  match_hostname cn name
         )
    | `Anonymous ->
         true   (* anonymous can be anybody *)
