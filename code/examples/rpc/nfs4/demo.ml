(* Demo: get the top-level directory of an NFSv4 export.
   This requires:
    - NFS is NFSv4
    - NFS is exported "insecure", i.e. client ports >= 1024 are allowed
      (this is an option in /etc/exports, note that there is no security
      risk if used with Kerberos)
    - NFS security layer is Kerberos (sec=krb5 or krb5i or krb5p)
    - You have a Kerberos ticket permitting access
 *)

#use "topfind";;
#require "rpc,netgss-system";;
#load "nfs4.cma";;

module NA = Rfc3530_aux
module NC = Rfc3530_clnt.NFS4_PROGRAM.NFS_V4

let connect host =
  let gss_conf =
    Netsys_gssapi.create_client_config
      ~target_name:("nfs", Netsys_gssapi.nt_hostbased_service)
      () in
  let gss_m =
    Rpc_auth_gssapi.client_auth_method
      (module Netgss.System)
      gss_conf in
  let client = 
    NC.create_client
      (Rpc_client.Inet(host, 2049))
      Rpc.Tcp in
  Rpc_client.set_auth_methods
    client
    [ gss_m ];
  client

      
let test1 client =
  NC.nfsproc4_null client ()


let test2 client =
  let req0 =
    `op_putrootfh in
  let req1 =
    `op_readdir(0L, String.make 8 '\000', 100000l, 120000l, [| |]) in
  let reqarr =
    [| req0; req1 |] in
  let (_, _, resarr) =
    NC.nfsproc4_compound client ("tag1", 0l, reqarr) in
  if Array.length resarr < Array.length reqarr then
    failwith "not all requests executed";
  ( match resarr.(0) with
      | `op_putrootfh status -> 
          if Netnumber.int_of_int4 status <> 0 then
            failwith "PUTROOTFH failed"
      | `op_illegal _ -> failwith "OP_ILLEGAL"
      | _ -> failwith "unexpected response"
  );
  ( match resarr.(1) with
      | `op_readdir(`nfs4_ok(_, l)) -> l
      | `op_readdir code ->
          failwith "READDIR failed"
      | `op_illegal _ -> failwith "OP_ILLEGAL"
      | _ -> failwith "unexpected response"
  )



