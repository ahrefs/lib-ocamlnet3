(* $Id$ *)

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
    with TLS.Error code when TLS.error_name code = "" ->
      [] in
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
