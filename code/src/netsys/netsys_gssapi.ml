(* $Id$ *)

open Printf

type oid = int array
type oid_set = oid list
type token = string
type interprocess_token = string
type calling_error =
    [ `None
    | `Inaccessible_read
    | `Inaccessible_write
    | `Bad_structure
    ]
type routine_error =
    [ `None
    | `Bad_mech
    | `Bad_name
    | `Bad_nametype
    | `Bad_bindings
    | `Bad_status
    | `Bad_mic
    | `No_cred
    | `No_context
    | `Defective_token
    | `Defective_credential
    | `Credentials_expired
    | `Context_expired
    | `Failure
    | `Bad_QOP
    | `Unauthorized
    | `Unavailable
    | `Duplicate_element
    | `Name_not_mn
    ]
type suppl_status =
    [ `Continue_needed
    | `Duplicate_token
    | `Old_token
    | `Unseq_token
    | `Gap_token
    ]
type major_status = calling_error * routine_error * suppl_status list
type minor_status = int32
type address =
    [ `Unspecified of string
    | `Local of string
    | `Inet of Unix.inet_addr
    | `Nulladdr
    | `Other of int32 * string
    ]
type channel_bindings = address * address * string
type cred_usage = [ `Initiate |`Accept | `Both ]
type qop = int32
type message = Netsys_types.mstring list
type ret_flag =
    [ `Deleg_flag | `Mutual_flag | `Replay_flag | `Sequence_flag 
    | `Conf_flag | `Integ_flag | `Anon_flag | `Prot_ready_flag
    | `Trans_flag
    ]
type req_flag = 
    [ `Deleg_flag | `Mutual_flag | `Replay_flag | `Sequence_flag 
    | `Conf_flag | `Integ_flag | `Anon_flag
    ]

type time =
  [ `Indefinite | `This of float]

class type ['credential, 'name, 'context] poly_gss_api =
  object
    method provider : string
    method no_credential : 'credential
    method no_name : 'name
    method is_no_credential : 'credential -> bool
    method is_no_name : 'name -> bool
    method accept_sec_context :
          't . context:'context option ->
               acceptor_cred:'credential -> 
               input_token:token ->
               chan_bindings:channel_bindings option ->
               out:( src_name:'name ->
		     mech_type:oid ->
		     output_context:'context option ->
		     output_token:token ->
		     ret_flags:ret_flag list ->
		     time_rec:time ->
		     delegated_cred:'credential ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't 
		   ) -> unit -> 't

    method acquire_cred :
          't . desired_name:'name ->
               time_req:time ->
               desired_mechs:oid_set ->
               cred_usage:cred_usage  ->
               out:( cred:'credential ->
		     actual_mechs:oid_set ->
		     time_rec:time ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method add_cred :
          't . input_cred:'credential ->
               desired_name:'name ->
               desired_mech:oid ->
               cred_usage:cred_usage ->
               initiator_time_req:time ->
               acceptor_time_req:time ->
               out:( output_cred:'credential ->
		     actual_mechs:oid_set ->
		     initiator_time_rec:time ->
		     acceptor_time_rec:time ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method canonicalize_name :
          't . input_name:'name ->
               mech_type:oid ->
               out:( output_name:'name ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method compare_name :
          't . name1:'name ->
               name2:'name ->
               out:( name_equal:bool ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method context_time :
          't . context:'context ->
               out:( time_rec:time ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method delete_sec_context :
          't . context:'context ->
               out:( minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method display_name :
          't . input_name:'name ->
               out:( output_name:string ->
		     output_name_type:oid ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method display_minor_status :
          't . status_value:minor_status ->
               mech_type: oid ->
               out:( status_strings: string list ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method duplicate_name :
           't . name:'name ->
               out:( dest_name:'name ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method export_name : 
          't . name:'name ->
               out:( exported_name:string ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method export_sec_context :
          't . context:'context ->
               out:( interprocess_token:interprocess_token ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method get_mic : 
           't . context:'context ->
               qop_req:qop ->
               message:message ->
               out:( msg_token:token ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method import_name :
          't . input_name:string ->
               input_name_type:oid ->
               out:( output_name:'name ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method import_sec_context :
          't . interprocess_token:interprocess_token ->
               out:( context:'context option ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method indicate_mechs :
          't . out:( mech_set:oid_set ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method init_sec_context :
           't . initiator_cred:'credential ->
               context:'context option ->
               target_name:'name ->
               mech_type:oid -> 
               req_flags:req_flag list ->
               time_req:float option ->
               chan_bindings:channel_bindings option ->
               input_token:token option ->
               out:( actual_mech_type:oid ->
		     output_context:'context option ->
		     output_token:token ->
		     ret_flags:ret_flag list ->
		     time_rec:time ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method inquire_context :
          't . context:'context ->
               out:( src_name:'name ->
                     targ_name:'name ->
		     lifetime_req : time ->
		     mech_type:oid ->
		     ctx_flags:ret_flag list ->
		     locally_initiated:bool ->
		     is_open:bool ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method inquire_cred :
          't . cred:'credential ->
               out:( name:'name ->
		     lifetime: time ->
		     cred_usage:cred_usage ->
		     mechanisms:oid_set ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method inquire_cred_by_mech :
          't . cred:'credential ->
               mech_type:oid -> 
               out:( name:'name ->
		     initiator_lifetime: time ->
		     acceptor_lifetime: time ->
		     cred_usage:cred_usage ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method inquire_mechs_for_name :
          't . name:'name ->
               out:( mech_types:oid_set ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method inquire_names_for_mech :
          't . mechanism:oid ->
               out:( name_types:oid_set ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't


    method process_context_token :
          't . context:'context ->
               token:token ->
               out:( minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method unwrap :
          't . context:'context ->
               input_message:message ->
               output_message_preferred_type:[ `Bytes | `Memory ] ->
               out:( output_message:message ->
		     conf_state:bool ->
		     qop_state:qop ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method verify_mic :
          't . context:'context ->
               message:message ->
               token:token ->
               out:( qop_state:qop ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method wrap :
          't . context:'context ->
               conf_req:bool ->
               qop_req:qop ->
               input_message:message ->
               output_message_preferred_type:[ `Bytes | `Memory ] ->
               out:( conf_state:bool ->
		     output_message:message ->
		     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't

    method wrap_size_limit :
          't . context:'context ->
               conf_req:bool ->
               qop_req:qop ->
               req_output_size:int ->
               out:( max_input_size:int ->
                     minor_status:minor_status ->
		     major_status:major_status ->
		     unit ->
		     't
		   ) -> unit -> 't
  end


module type GSSAPI =
  sig
    type credential
    type context
    type name

    exception Credential of credential
    exception Context of context
    exception Name of name

    class type gss_api = [credential, name, context] poly_gss_api

    val interface : gss_api

end

let string_of_calling_error =
  function
    | `None -> "-"
    | `Inaccessible_read -> "Inaccessible_read"
    | `Inaccessible_write -> "Inaccessible_write"
    | `Bad_structure -> "Bad_structure"

let string_of_routine_error =
  function
    | `None -> "-"
    | `Bad_mech -> "Bad_mech"
    | `Bad_name -> "Bad_name"
    | `Bad_nametype -> "Bad_nametype"
    | `Bad_bindings -> "Bad_bindings"
    | `Bad_status -> "Bad_status"
    | `Bad_mic -> "Bad_mic"
    | `No_cred -> "No_cred"
    | `No_context -> "No_context"
    | `Defective_token -> "Defective_token"
    | `Defective_credential -> "Defective_credential"
    | `Credentials_expired -> "Credentials_expired"
    | `Context_expired -> "Context_expired"
    | `Failure -> "Failure"
    | `Bad_QOP -> "Bad_QOP"
    | `Unauthorized -> "Unauthorized"
    | `Unavailable -> "Unavailable"
    | `Duplicate_element -> "Duplicate_element"
    | `Name_not_mn -> "Name_not_mn"

let string_of_suppl_status =
  function
    | `Continue_needed -> "Continue_needed"
    | `Duplicate_token -> "Duplicate_token"
    | `Old_token -> "Old_token"
    | `Unseq_token -> "Unseq_token"
    | `Gap_token -> "Gap_token"

let string_of_major_status (ce,re,sl) =
  let x = String.concat "," (List.map string_of_suppl_status sl) in
  "<major:" ^ string_of_calling_error ce ^ 
  ";" ^ string_of_routine_error re ^ 
  (if x <> "" then ";" ^ x else "") ^ 
  ">"

let string_of_flag =
  function
  | `Deleg_flag -> "Deleg"
  | `Mutual_flag -> "Mutual"
  | `Replay_flag -> "Replay"
  | `Sequence_flag -> "Sequence"
  | `Conf_flag -> "Conf"
  | `Integ_flag -> "Integ"
  | `Anon_flag -> "Anon"
  | `Prot_ready_flag -> "Prot_ready"
  | `Trans_flag -> "Trans"


let nt_hostbased_service =
  [| 1; 3; 6; 1; 5; 6; 2 |]

let nt_hostbased_service_alt =
  [| 1; 2; 840; 113554; 1; 2; 1; 4 |]

let nt_user_name =
  [| 1; 2; 840; 113554; 1; 2; 1; 1 |]

let nt_machine_uid_name =
  [| 1; 2; 840; 113554; 1; 2; 1; 2 |]

let nt_string_uid_name =
  [| 1; 2; 840; 113554; 1; 2; 1; 3 |]

let nt_anonymous =
  [| 1; 3; 6; 1; 5; 6; 3 |]

let nt_export_name =
  [| 1; 3; 6; 1; 5; 6; 4 |]

let nt_krb5_principal_name =
  [| 1; 2; 840; 113554; 1; 2; 2; 1 |]

let parse_hostbased_service s =
  try
    let k = String.index s '@' in
    (String.sub s 0 k, String.sub s (k+1) (String.length s - k - 1))
  with
    | Not_found ->
	failwith "Netsys_gssapi.parse_hostbased_service"

type support_level =
    [ `Required | `If_possible | `None ]

class type client_config =
object
  method mech_type : oid
  method target_name : (string * oid) option
  method initiator_name : (string * oid) option
  method initiator_cred : exn option
  method privacy : support_level
  method integrity : support_level
  method flags : (req_flag * support_level) list
end

let create_client_config ?(mech_type = [| |]) ?initiator_name ?initiator_cred
                         ?target_name
                         ?(privacy = `If_possible) ?(integrity = `If_possible)
                         ?(flags=[]) () : client_config =
  object
    method mech_type = mech_type
    method target_name = target_name
    method initiator_name = initiator_name
    method initiator_cred = initiator_cred
    method privacy = privacy
    method integrity = integrity
    method flags = flags
  end

class type server_config =
object
  method mech_types : oid list
  method acceptor_name : (string * oid) option
  method privacy : support_level
  method integrity : support_level
  method flags : (req_flag * support_level) list
end

let create_server_config ?(mech_types = []) ?acceptor_name
                         ?(privacy = `If_possible) ?(integrity = `If_possible)
                         ?(flags=[]) () =
  object
    method mech_types = mech_types
    method acceptor_name = acceptor_name
    method privacy = privacy
    method integrity = integrity
    method flags = flags
  end

class type client_props =
object
  method mech_type : oid
  method flags : ret_flag list
  method time : time
end


class type server_props =
object
  method mech_type : oid
  method flags : ret_flag list
  method time : time
  method initiator_name : (string * oid)
  method initiator_name_exported : string
  method deleg_credential : (exn * time) option
end


let marshal_client_props p =
  Marshal.to_string (p#mech_type, p#flags, p#time) []

let unmarshal_client_props s =
  let (mech_type, flags, time) = 
    Marshal.from_string s 0 in
  ( object
      method mech_type = mech_type
      method flags = flags
      method time = time
    end
  )

let marshal_server_props p =
  Marshal.to_string (p#mech_type, p#flags, p#time, p#initiator_name,
                     p#initiator_name_exported) []

let unmarshal_server_props s =
  let (mech_type, flags, time, initiator_name, initiator_name_exported) =
    Marshal.from_string s 0 in
  ( object
      method mech_type = mech_type
      method flags = flags
      method time = time
      method initiator_name = initiator_name
      method initiator_name_exported = initiator_name_exported
      method deleg_credential = None
    end
  )
