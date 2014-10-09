(* $Id$ *)

(* Utilities for the generated object encapsulation *)

open Netsys_gssapi
open Netgss_bindings

let identity x = x

let calling_errors =
  [| `None;
     `Inaccessible_read;
     `Inaccessible_write;
     `Bad_structure
    |]


let routine_errors =
  [| `None;
     `Bad_mech;
     `Bad_name;
     `Bad_nametype;
     `Bad_bindings;
     `Bad_status;
     `Bad_mic;
     `No_cred;
     `No_context;
     `Defective_token;
     `Defective_credential;
     `Credentials_expired;
     `Context_expired;
     `Failure;
     `Bad_QOP;
     `Unauthorized;
     `Unavailable;
     `Duplicate_element;
     `Name_not_mn;
    |]

let suppl_status_flags =
  [| `Continue_needed;
     `Duplicate_token;
     `Old_token;
     `Unseq_token;
     `Gap_token;
    |]

let decode_status n : major_status =
  let bits_calling_error =
    Int32.shift_right_logical n 24 in
  let bits_routine_error =
    Int32.logand (Int32.shift_right_logical n 16) 0xffl in
  let bits_suppl_info =
    Int32.logand n 0xffffl in
  try
    if bits_calling_error >= Array.length calling_errors then raise Not_found;
    if bits_routine_error >= Array.length routine_errors then raise Not_found;
    let suppl_info, _ =
      Array.fold_right
        (fun flag (l, k) ->
           let is_set =
             Int32.logand
               (Int32.shift_left 1l k)
               bits_suppl_info
             <> 0l in
           if is_set then
             (flag :: l, k+1)
           else
             (l, k+1)
        )
        suppl_status_flags
        ([], 0) in
    (calling_errors.(bits_calling_error),
     routine_errors.(bits_routine_error),
     suppl_info
    )
  with
    | Not_found ->
         failwith "Netgss.decode_status"

let _gss_ctx_id_t_of_context_option =
  function
  | None -> no_context()
  | Some ctx -> ctx

let _context_option_of_gss_ctx_id_t ctx =
  (* FIXME *)
  (* hmmm, how to check for no_context? *)
  Some ctx

let _gss_buffer_t_of_token s =
  buffer_of_string s

let _token_of_gss_buffer_t buf =
  string_of_buffer buf

let _gss_buffer_t_of_message m =
  XXX

let _message_of_gss_buffer_t buf =
  let mem = memory_of_buffer buf in
  Xdr_mstring.memory_to_mstring mem
   (* CHECK: no copy here. These buffers are "use once" buffers *)

let _gss_channel_bindings_t_of_cb_option _ =
  (* FIXME *)
  no_channel_bindings()

let _oid_of_gss_OID oid =
  XXX

let _gss_OID_of_oid oid =
  XXX

let _oid_set_of_gss_OID_set set =
  XXX

let _gss_OID_set_of_oid_set XXX =
  XXX

let _time_ret_of_OM_uint32 n =
  XXX

let _OM_uint32_of_time_req XXX =
  XXX
