(* This file is included into netgss_bindings.mli *)

exception Null_pointer

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t

val buffer_of_string : string -> int -> int -> gss_buffer_t
val buffer_of_bytes : Bytes.t -> int -> int -> gss_buffer_t
val buffer_of_memory : memory -> gss_buffer_t
val string_of_buffer : gss_buffer_t -> string
val bytes_of_buffer : gss_buffer_t -> Bytes.t
val memory_of_buffer : gss_buffer_t -> memory
val release_buffer : gss_buffer_t -> unit
val oid_of_der : string -> gss_OID
val der_of_oid : gss_OID -> string
val array_of_oid_set : gss_OID_set -> gss_OID array
val oid_set_of_array : gss_OID array -> gss_OID_set
val map_cb : int -> string -> int -> string -> string -> gss_channel_bindings_t
val no_channel_bindings : unit -> gss_channel_bindings_t
val no_context : unit -> gss_ctx_id_t
val is_no_context : gss_ctx_id_t -> bool
val no_credential : unit -> gss_cred_id_t
val is_no_credential : gss_cred_id_t -> bool
val no_name : unit -> gss_name_t
val is_no_name : gss_name_t -> bool
val no_oid : unit -> gss_OID
val no_oid_set : unit -> gss_OID_set
val gss_indefinite : unit -> int32
