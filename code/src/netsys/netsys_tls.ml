(* $Id$ *)

open Printf


module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Netsys_tls" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Netsys_tls" Debug.enable

let () =
  Netlog.Debug.register_module "Netsys_tls" Debug.enable



exception Error of string * string

type dh_params =
  [ `PKCS3_PEM_file of string
  | `PKCS3_DER of string
  | `Generate of int
  ]

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


let trans_exn tls exn =
  let module P = (val tls : Netsys_crypto_types.TLS_PROVIDER) in
  match exn with
    | P.Switch_request ->
         Error("Switch_request", "A handshake has been requested")
    | P.Error code ->
         Error(P.error_name code, P.error_message code)
    | P.Warning code ->
         Error(P.error_name code, P.error_message code)
    | _ ->
         exn


let translate_exn endpoint exn =
  let module Endpoint = 
    (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module P = Endpoint.TLS in
  trans_exn (module P) exn


let debug_backtrace fn exn bt =
  dlog (sprintf "Exception in function Netsys_tls.%s: %s - backtrace: %s"
                fn (Netexn.to_string exn) bt
       )



let create_x509_config
      ?algorithms ?dh_params ?(verify = fun _ -> true) 
      ?peer_name ?trust ?revoke ?keys 
      ~peer_auth tls =
  let module P = (val tls : Netsys_crypto_types.TLS_PROVIDER) in
  let verify ep =
    let module EP = struct
      module TLS = P
      let endpoint = ep
    end in
    verify (module EP : Netsys_crypto_types.TLS_ENDPOINT) in
  try
    let credentials = P.create_x509_credentials ?trust ?revoke ?keys () in
    let config =
      P.create_config
        ?algorithms ?dh_params ~verify ?peer_name ~peer_auth ~credentials () in
    let module Config = struct
      module TLS = P
      let config = config
    end in
    (module Config : Netsys_crypto_types.TLS_CONFIG)
  with
    | exn -> 
         if !Debug.enable then 
           debug_backtrace "create_x509_config" exn (Printexc.get_backtrace());
         raise(trans_exn tls exn)


let create_file_endpoint ~role ~rd_file ~wr_file config =
  let module Config = (val config : Netsys_crypto_types.TLS_CONFIG) in
  let module P = Config.TLS in
  try
    let recv buf =
      Netsys_mem.mem_recv rd_file buf 0 (Bigarray.Array1.dim buf) [] in
    let send buf size =
      Netsys_mem.mem_send wr_file buf 0 size [] in
    let ep = P.create_endpoint ~role ~recv ~send Config.config in
    let module Endpoint = struct
      module TLS = P
      let endpoint = ep
      let rd_file = rd_file
      let wr_file = wr_file
    end in
    (module Endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT)
  with
    | exn -> 
         if !Debug.enable then 
           debug_backtrace "create_file_endpoint" 
                           exn (Printexc.get_backtrace());
         raise(trans_exn (module P) exn)


let start_tls endpoint =
  let module Endpoint = 
    (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module P = Endpoint.TLS in
  try
    let state = P.get_state Endpoint.endpoint in
    if state = `Start || state = `Handshake then (
      P.hello Endpoint.endpoint;
      P.verify Endpoint.endpoint
    )
  with
    | exn -> 
         if !Debug.enable then
           debug_backtrace "start_tls" exn (Printexc.get_backtrace());
         raise(trans_exn (module P) exn)


let mem_recv endpoint buf pos len =
  let module Endpoint = 
    (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module P = Endpoint.TLS in
  start_tls endpoint;
  let buf' =
    if pos=0 && len=Bigarray.Array1.dim buf then
      buf
    else
      Bigarray.Array1.sub buf pos len in
  try
    P.recv Endpoint.endpoint buf'
  with
    | exn ->
         if !Debug.enable then
           debug_backtrace "mem_recv" exn (Printexc.get_backtrace());
         raise(trans_exn (module P) exn)


let recv endpoint buf pos len =
  let mem = Netsys_mem.pool_alloc_memory Netsys_mem.default_pool in
  let mem_len = min len (Bigarray.Array1.dim mem) in
  let n = mem_recv endpoint mem 0 mem_len in
  Netsys_mem.blit_memory_to_string mem 0 buf pos n;
  n


let mem_send endpoint buf pos len =
  let module Endpoint = 
    (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module P = Endpoint.TLS in
  start_tls endpoint;
  let buf' =
    if pos=0 then
      buf
    else
      Bigarray.Array1.sub buf pos len in
  try
    P.send Endpoint.endpoint buf' len
  with
    | exn ->
         if !Debug.enable then
           debug_backtrace "mem_send" exn (Printexc.get_backtrace());
         raise(trans_exn (module P) exn)


let send endpoint buf pos len =
  let mem = Netsys_mem.pool_alloc_memory Netsys_mem.default_pool in
  let mem_len = min len (Bigarray.Array1.dim mem) in
  Netsys_mem.blit_string_to_memory buf pos mem 0 mem_len;
  mem_send endpoint mem 0 mem_len


let end_tls endpoint how =
  let module Endpoint = 
    (val endpoint : Netsys_crypto_types.FILE_TLS_ENDPOINT) in
  let module P = Endpoint.TLS in
  start_tls endpoint;
  try
    P.bye Endpoint.endpoint how
  with
    | exn ->
         if !Debug.enable then
           debug_backtrace "end_tls" exn (Printexc.get_backtrace());
         raise(trans_exn (module P) exn)
