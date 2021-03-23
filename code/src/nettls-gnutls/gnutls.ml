(* This file is included into nettls_gnutls_bindings.ml *)

exception Null_pointer
exception Error of error_code
exception Short_memory_buffer of int

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t

type gnutls_credentials =
    [ `Certificate of gnutls_certificate_credentials_t
    | `Srp_client of gnutls_srp_client_credentials_t
    | `Srp_server of gnutls_srp_server_credentials_t
    | `Psk_client of gnutls_psk_client_credentials_t
    | `Psk_server of gnutls_psk_server_credentials_t
    | `Anon_client of gnutls_anon_client_credentials_t
    | `Anon_server of gnutls_anon_server_credentials_t
    ]

external gnutls_credentials_set : gnutls_session_t -> gnutls_credentials -> unit
  = "net_gnutls_credentials_set" "net_gnutls_credentials_set"

type 'a unix_code =
  | ESUCCESS of 'a
  | EINTR
  | EAGAIN
  | EMSGSIZE
  | EPERM

external net_b_set_pull_callback : 
  gnutls_session_t -> (memory -> int unix_code) -> unit
  = "net_b_set_pull_callback" "net_b_set_pull_callback"

external net_b_set_push_callback : 
  gnutls_session_t -> (memory -> int -> int unix_code) -> unit
  = "net_b_set_push_callback" "net_b_set_push_callback"

external net_b_set_pull_timeout_callback : 
  gnutls_session_t -> (int -> bool unix_code) -> unit
  = "net_b_set_pull_timeout_callback" "net_b_set_pull_timeout_callback"

external net_b_set_verify_callback : 
  gnutls_session_t -> (unit -> bool) -> unit
  = "net_b_set_verify_callback" "net_b_set_verify_callback"


let protect f arg =
  try
    ESUCCESS(f arg)
  with
    | Unix.Unix_error(Unix.EINTR, _, _) ->
         EINTR
    | Unix.Unix_error((Unix.EAGAIN | Unix.EWOULDBLOCK), _, _) ->
         EAGAIN
    | Unix.Unix_error(Unix.EMSGSIZE, _, _) ->
         EMSGSIZE
    | Unix.Unix_error(e, _, _) ->
         EPERM
    | e ->
         Netlog.logf `Crit "Exception in Nettls_gnutls_bindings: %s"
                     (Netexn.to_string e);
         EPERM


let b_set_pull_callback s f =
  net_b_set_pull_callback s (protect f)


let b_set_push_callback s f =
  net_b_set_push_callback s (fun buf size -> protect (f buf) size)


let b_set_pull_timeout_callback s f =
  net_b_set_pull_timeout_callback s (protect f)


let b_set_verify_callback s f =
  net_b_set_verify_callback s (fun () -> f s)


external b_set_db_callbacks :
  gnutls_session_t ->
  (string -> string -> unit) ->
  (string -> unit) ->
  (string -> string) ->
  unit
  = "net_b_set_db_callbacks" "net_b_set_db_callbacks"


let set_fd s fd =
  let recv mem =
    Netsys_mem.mem_recv fd mem 0 (Bigarray.Array1.dim mem) [] in
  let send mem size =
    Netsys_mem.mem_send fd mem 0 size [] in
  let timeout ms =
    Netsys_posix.poll_single fd true false false (0.001 *. float ms) in
  b_set_pull_callback s recv;
  b_set_push_callback s send;
  b_set_pull_timeout_callback s timeout;
  ()

let string_of_verification_status_flag =
  function
    | `Invalid -> "INVALID"
    | `Revoked -> "REVOKED"
    | `Signer_not_found -> "SIGNER_NOT_FOUND"
    | `Signer_not_ca -> "SIGNER_NOT_CA"
    | `Insecure_algorithm -> "INSECURE_ALGORITHM"
    | `Not_activated -> "NOT_ACTIVATED"
    | `Expired -> "EXPIRED"
    | `Signature_failure -> "SIGNATURE_FAILURE"
    | `Revocation_data_superseded -> "REVOCATION_DATA_SUPERSEDED"
    | `Unexpected_owner -> "UNEXPECTED_OWNER"
    | `Revocation_data_issued_in_future -> "REVOCATION_DATA_ISSUED_IN_FUTURE"
    | `Signer_constraints_failure -> "SIGNER_CONSTRAINTS_FAILURE"
    | `Mismatch -> "MISMATCH"
    | `Purpose_mismatch -> "PURPOSE_MISMATCH"

external gnutls_x509_crt_list_import : string -> gnutls_x509_crt_fmt_t ->
                                  gnutls_certificate_import_flags ->
                                  gnutls_x509_crt_t array
  = "net_gnutls_x509_crt_list_import" "net_gnutls_x509_crt_list_import"

external gnutls_x509_crl_list_import : string -> gnutls_x509_crt_fmt_t ->
                                  gnutls_certificate_import_flags ->
                                  gnutls_x509_crl_t array
  = "net_gnutls_x509_crl_list_import" "net_gnutls_x509_crl_list_import"


let () =
  Callback.register_exception
    "Nettls_gnutls_bindings.Null_pointer"
    Null_pointer;
  Callback.register_exception
    "Nettls_gnutls_bindings.Error"
    (Error `Success);
  Callback.register_exception
    "Nettls_gnutls_bindings.Short_memory_buffer"
    (Short_memory_buffer 0)


let () =
  Netexn.register_printer
    (Error `Success)
    (function
      | Error code ->
           Printf.sprintf
             "Nettls_gnutls_bindings.Error(%s)" (gnutls_strerror_name code)
      | _ ->
           assert false
    )
