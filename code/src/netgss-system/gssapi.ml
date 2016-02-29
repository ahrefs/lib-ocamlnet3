(* This file is included into netgss_bindings.ml *)

exception Null_pointer

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t

external buffer_of_string : string -> int -> int -> gss_buffer_t
  = "netgss_buffer_of_string"

external buffer_of_bytes : Bytes.t -> int -> int -> gss_buffer_t
  = "netgss_buffer_of_string"

external buffer_of_memory : memory -> gss_buffer_t
  = "netgss_buffer_of_memory"

external string_of_buffer : gss_buffer_t -> string
  = "netgss_string_of_buffer"

external bytes_of_buffer : gss_buffer_t -> Bytes.t
  = "netgss_string_of_buffer"

external netgss_memory_of_buffer : gss_buffer_t -> memory
  = "netgss_memory_of_buffer"

let hide_reference x _ =
  x := None

let memory_of_buffer buf =
  let buf_opt = ref (Some buf) in
  let finalizer = hide_reference buf_opt in
  let m = 
    try netgss_memory_of_buffer buf
    with Null_pointer ->
      Bigarray.Array1.create Bigarray.char Bigarray.c_layout 0 in
  Gc.finalise finalizer m;
  m

external release_buffer : gss_buffer_t -> unit
  = "netgss_release_buffer"

external oid_of_der : string -> gss_OID
  = "netgss_oid_of_string"

external der_of_oid : gss_OID -> string
  = "netgss_string_of_oid"

external array_of_oid_set : gss_OID_set -> gss_OID array
  = "netgss_array_of_oid_set"

external oid_set_of_array : gss_OID array -> gss_OID_set
  = "netgss_oid_set_of_array"

external map_cb : int -> string -> int -> string -> string -> 
                  gss_channel_bindings_t
  = "netgss_map_cb"

external no_channel_bindings : unit -> gss_channel_bindings_t
  = "netgss_no_cb"

external no_context : unit -> gss_ctx_id_t
  = "netgss_no_ctx"

external is_no_context : gss_ctx_id_t -> bool
  = "netgss_is_no_ctx"

external no_credential : unit -> gss_cred_id_t
  = "netgss_no_cred"

external is_no_credential : gss_cred_id_t -> bool
  = "netgss_is_no_cred"

external no_name : unit -> gss_name_t
  = "netgss_no_name"

external is_no_name : gss_name_t -> bool
  = "netgss_is_no_name"

external gss_indefinite : unit -> int32
  = "netgss_indefinite"

external no_oid : unit -> gss_OID
  = "netgss_no_oid"

external no_oid_set : unit -> gss_OID_set
  = "netgss_no_oid_set"

let () =
  Callback.register_exception
    "Netgss_bindings.Null_pointer"
    Null_pointer
