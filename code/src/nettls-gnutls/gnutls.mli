(* This file is included into nettls_gnutls_bindings.mli *)

exception Null_pointer
exception Error of error_code
exception Short_memory_buffer of int

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t
  (** See {!Netsys_types.memory} *)

type gnutls_credentials =
    [ `Certificate of gnutls_certificate_credentials_t
    | `Srp_client of gnutls_srp_client_credentials_t
    | `Srp_server of gnutls_srp_server_credentials_t
    | `Psk_client of gnutls_psk_client_credentials_t
    | `Psk_server of gnutls_psk_server_credentials_t
    | `Anon_client of gnutls_anon_client_credentials_t
    | `Anon_server of gnutls_anon_server_credentials_t
    ]

val gnutls_credentials_set : gnutls_session_t -> gnutls_credentials -> unit

val b_set_pull_callback : 
  gnutls_session_t -> (memory -> int) -> unit
  (** Sets the function for reading data. The function must return the number
      of read bytes (like [Unix.read]). The function can raise [Unix_error].
      Only the codes [EINTR], [EAGAIN], [EWOULDBLOCK], and [EMSGSIZE] are
      interpreted.
   *)

val b_set_push_callback : 
  gnutls_session_t -> (memory -> int -> int) -> unit
  (** Sets the function for writing data. The function must return the number
      of written bytes (like [Unix.write]). The function can raise [Unix_error].
      Only the codes [EINTR], [EAGAIN], [EWOULDBLOCK], and [EMSGSIZE] are
      interpreted.
   *)

val b_set_pull_timeout_callback : 
  gnutls_session_t -> (int -> bool) -> unit
  (** Sets the function for waiting for new data to arrive (only used for
      DTLS). The integer are the milliseconds to wait at most. The function
      shall return [true] if there is data, and [false] in case of a timeout.
      The function can raise [Unix_error].
      Only the codes [EINTR], [EAGAIN], [EWOULDBLOCK], and [EMSGSIZE] are
      interpreted.
   *)

val b_set_verify_callback :
  gnutls_session_t -> (gnutls_session_t -> bool) -> unit
  (** Sets the function for verifying the peer's certificate. The function
      can return [true] if the certificate is acceptable, and [false] otherwise.
      Note that this callback is set in this binding on the session, and
      not on [gnutls_certificate_credentials_t].
   *)


val set_fd : gnutls_session_t -> Unix.file_descr -> unit
  (** Sets that this file descriptor is used for I/O. NB. This function just
      invokes [b_set_pull_callback], [b_set_push_callback], and
      [b_set_pull_timeout_callback] with the right argument functions.
   *)

val b_set_db_callbacks :
  gnutls_session_t ->
  (string -> string -> unit) ->
  (string -> unit) ->
  (string -> string) ->
  unit
  (** [b_set_db_callbacks session store remove retrieve]: sets the three
      callbacks for server-side session caching
   *)

val string_of_verification_status_flag : 
      gnutls_certificate_status_t_flag -> string
  (** Returns a string for the status code *)

val gnutls_x509_crt_list_import : string -> gnutls_x509_crt_fmt_t ->
                                  gnutls_certificate_import_flags ->
                                  gnutls_x509_crt_t array

val gnutls_x509_crl_list_import : string -> gnutls_x509_crt_fmt_t ->
                                  gnutls_certificate_import_flags ->
                                  gnutls_x509_crl_t array
