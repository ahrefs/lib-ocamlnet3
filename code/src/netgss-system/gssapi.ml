(* This file is included into netgss_bindings.ml *)

exception Null_pointer

type memory = 
    (char,Bigarray.int8_unsigned_elt,Bigarray.c_layout) Bigarray.Array1.t

external buffer_of_string : string -> gss_buffer_t
  = "netgss_buffer_of_string"

external buffer_of_memory : memory -> gss_buffer_t
  = "netgss_buffer_of_memory"

external string_of_buffer : gss_buffer_t -> string
  = "netgss_string_of_buffer"

external oid_of_der : string -> gss_OID
  = "netgss_oid_of_string"

external der_of_oid : gss_OID -> string
  = "netgss_string_of_oid"

external array_of_oid_set : gss_OID_set -> gss_OID array
  = "netgss_array_of_oid_set"

external oid_set_of_array : gss_OID array -> gss_OID_set
  = "netgss_oid_set_of_array"

external no_channel_bindings : unit -> gss_channel_bindings_t
  = "netgss_no_cb"

let () =
  Callback.register_exception
    "Netgss_bindings.Null_pointer"
    Null_pointer
