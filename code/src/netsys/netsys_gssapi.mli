(* $Id$ *)

(** GSS-API Definition *)

(* TODO:
   - OID/SASL name translation from RFC-5801
   - flag that disallows GS2 for this mechanism
 *)

(** This is mainly a translation of RFC 2743/2744 to Ocaml.

    The following other modules are also interesting in this context:
     - {!Netgssapi_support}
     - {!Netoid}

 *)

(** {2 Types} *)

type oid = int array
    (** OIDs like "1.3.6.1.5.6.2" as array of int's. The empty array
	means [GSS_C_NO_OID]. See also {!Netoid}.
     *)

type oid_set = oid list
    (** A set of OID's. These lists should not contain OID's twice.
	The empty list means [GSS_C_NO_OID_SET].
     *)

type token = string
    (** Authentication tokens. These are also opaque to the caller,
	but have a string representation so that they can be sent
	over the wire.
     *)

type interprocess_token = string
    (** Interprocess tokens. These are also opaque to the caller,
	but have a string representation so that they can be sent
	over the wire.
     *)

type calling_error =
    [ `None
    | `Inaccessible_read
    | `Inaccessible_write
    | `Bad_structure
    ]
    (** Possible errors caused by the caller *)

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
    (** Possible errors caused by the provider *)

type suppl_status =
    [ `Continue_needed
    | `Duplicate_token
    | `Old_token
    | `Unseq_token
    | `Gap_token
    ]
    (** Further flags *)

type major_status = calling_error * routine_error * suppl_status list
    (** The major status consists of these three elements. The bits of the
	supplementary status field are represented as list
     *)

type minor_status = int32
    (** The minor status is provider-specific. Note that GSS-API defines
	it as {b unsigned} 32-bit integer whereas [int32] is signed.
     *)

type address =
    [ `Unspecified of string
    | `Local of string
    | `Inet of Unix.inet_addr
    | `Nulladdr
    | `Other of int32 * string
    ]
  (** Addresses tagged by address types *)

type channel_bindings = address * address * string
    (** Channel binding as tuple
	[(initiator_address, acceptor_address, application_data)] 
     *)

type cred_usage = [ `Initiate |`Accept | `Both ]

type qop = int32
    (** Quality-of-proctection parameters are mechanism-specific.
        The value 0 can always be used for a default protection level.
     *)

type message =
    Netsys_types.mstring list
    (** Messages are represented as lists of [mstring] *)

type ret_flag =
    [ `Deleg_flag | `Mutual_flag | `Replay_flag | `Sequence_flag 
    | `Conf_flag | `Integ_flag | `Anon_flag | `Prot_ready_flag
    | `Trans_flag
    ]
    (** Flags for the [accept_sec_context] method *)

type req_flag = 
    [ `Deleg_flag | `Mutual_flag | `Replay_flag | `Sequence_flag 
    | `Conf_flag | `Integ_flag | `Anon_flag
    ]
    (** Flags for the [init_sec_context] method *)

type time =
  [ `Indefinite | `This of float]



class type ['credential, 'name, 'context] poly_gss_api =
  object
    method provider : string
        (** A string name identifying the provider *)

    method no_credential : 'credential
        (** A substitute credential for [GSS_C_NO_CREDENTIAL] *)

    method no_name : 'name
        (** A substitute name for [GSS_C_NO_NAME] *)

    method is_no_credential : 'credential -> bool
        (** A test for [GSS_C_NO_CREDENTIAL] *)

    method is_no_name : 'name -> bool
        (** A test for [GSS_C_NO_NAME] *)

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
        (** On the first call, pass [~context:None]. If successful, the
	function outputs a non-None [~output_context] which should be
	passed as new [~context] in follow-up calls.

	If the [output_token] is non-empty, it must be transmitted to
	the peer - independent of the [major_status].
         *)


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
        (** Output tokens are not supported (this is a deprecated feature of
	    GSSAPI)
         *)

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
        (** Note that [display_minor_status] decodes all status value parts in
	one step and returns the result as [string list]. Also, this
	method is restricted to decoding minor statuses
         *)

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
        (** On the first call, pass [~context:None]. If successful, the
	function outputs a non-None [~output_context] which should be
	passed as new [~context] in follow-up calls.

	If the [output_token] is non-empty, it must be transmitted to
	the peer - independent of the [major_status].
         *)

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
        (** Note that the [output_message] can be a buffer of different type
	(string vs. bigarray) than [input_message]. In 
	[output_message_preferred_type] the called may wish a certain
	representation. It is, however, not ensured that the wish is
	granted.
         *)

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
        (** [output_message_preferred_type]: see [unwrap] *)

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
    (** The General Security Services API *)

    (** See also {!Netsys_gssapi} for additional type definitions *)

    type credential
    (** A credential is opaque for the caller of the GSS-API.
	The provider of the GSS-API can emit new credential objects,
	and hand them out to the caller.
     *)

    type context
    (** A context is also opaque. *)


    type name
    (** A name is also opaque *)


    (** {2 Exceptions} *)
           
    (** There are no defined exceptions for reporting errors.

    Errors should be reported using the [major_status] and [minor_status]
    codes as much as possible.

    [Invalid_argument] may be raised for clear violations of calling
    requirements, e.g. when an opaque object is passed to this interface
    that was not returned by it before.

    The following three exceptions can be used to wrap the per-GSSAPI types
    [credential], [context], and [name]:
     *)

    exception Credential of credential
    exception Context of context
    exception Name of name


    (** {2 The API} *)

    (** The methods have generally a type of the form

    {[ 
       m : 't . arg1 -> ... -> argN -> out:( ret1 -> ... -> retM -> 't ) -> 't 
    ]}

    where [arg]s are input arguments (with the exception of [context] 
    which is in/out), and where outputs are passed back by calling the [out]
    functions with the outputs. The return value of [out] is the return
    value of the method call.

    For example, if only [output_token] of the [accept_sec_context] method
    is needed, one could call this method as in

    {[
      let output_token =
	gss_api # accept_sec_context 
	   ... 
	   ~out:(fun ~src_name ~mech_type ~output_token ~ret_flags
		     ~time_rec ~delegated_cred_handle ~minor_status
		     ~major_status ->
		  output_token
		)
    ]}

    Output values may not be defined when [major_status] indicates
    an error. (But see the RFC for details; especially [init_sec_contect]
    and [accept_sec_context] may emit tokens even when [major_status]
    indicates an error.)

    The names of the parameters are taken from RFC 2744, only
    suffixes like [_handle] have been removed. When the prefixes
    [input_] and [output_] are meaningless, they are also removed.
    All prefixes like "GSS" are removed anyway.
     *)
    class type gss_api = [credential, name, context] poly_gss_api


    val interface : gss_api

end

(** {2 Utility functions} *)

(** These functions convert values to strings. Useful for generating
    log messages.
 *)

val string_of_calling_error : calling_error -> string
val string_of_routine_error : routine_error -> string
val string_of_suppl_status : suppl_status -> string
val string_of_major_status : major_status -> string
val string_of_flag : ret_flag -> string

(** {2 Common OID's for name types} *)

(** See RFC 2078, section 4 *)

val nt_hostbased_service : oid
  (** names like "service\@hostname" *)

val nt_hostbased_service_alt : oid
  (** another OID for the same (RFC 1964 mentions it) *)

val nt_user_name : oid
  (** names like "username" *)

val nt_machine_uid_name : oid
  (** user ID in host byte order *)
  
val nt_string_uid_name : oid
  (** user ID as string of digits *)

val nt_anonymous : oid
  (** anonymous name *)

val nt_export_name : oid
  (** an export name *)

val nt_krb5_principal_name : oid
  (** a Kerberos 5 principal name (see {!Netgssapi_support} for parsers *)

val parse_hostbased_service : string -> string * string
  (** Returns ([service,host]) for "service\@host". Fails if not parseable *)


(** {2 Configuring clients} *)

type support_level =
    [ `Required | `If_possible | `None ]

(** See {!Netsys_gssapi.create_client_config} *)
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

val create_client_config : 
      ?mech_type:oid ->
      ?initiator_name:(string * oid) ->
      ?initiator_cred:exn ->
      ?target_name:(string * oid) ->
      ?privacy:support_level ->
      ?integrity:support_level ->
      ?flags:(req_flag * support_level) list ->
      unit ->
      client_config
  (** [mech_type] is the GSSAPI mechanism to use. If left unspecified,
    a default is used. [target_name] is the name of the service to
    connect to. [initiator_name] identifies and authenticates the client.
    Note that you normally can omit all of [mech_type], [target_name],
    and [initiator_name] as GSSAPI already substitutes reasonable defaults
    (at least if Kerberos is available as mechanism).

    If you have a delegated credential you can also pass it as
    [initiator_cred]. This must be a [Credential] exception from the
    GSSAPI provider. [initiator_cred] has precedence over [initiator_name].

    [privacy] and [integrity] specify the desired level of protection.
    By default, both integrity and privacy are enabled if available, but
    it is no error if the mechanism doesn't support these features.

    [flags]: additional GSSAPI flags. These should not contain [`Conf_flag]
    and [`Integ_flag] (instead use [privacy] and [integrity], resp.).
   *)

(** Return properties of the client context *)
class type client_props =
object
  method mech_type : oid         (** Actual mechanism *)
  method flags : ret_flag list   (** Actual flags *)
  method time : time             (** Actual context lifetime *)
end

val marshal_client_props : client_props -> string
val unmarshal_client_props : string -> client_props

(** {2 Configuring servers} *)

(** See {!Netsys_gssapi.create_server_config} *)
class type server_config =
object
  method mech_types : oid list
  method acceptor_name : (string * oid) option
  method privacy : support_level
  method integrity : support_level
  method flags : (req_flag * support_level) list
end

val create_server_config : 
      ?mech_types:oid list ->
      ?acceptor_name:(string * oid) ->
      ?privacy:support_level ->
      ?integrity:support_level ->
      ?flags:(req_flag * support_level) list ->
      unit ->
      server_config
  (** [mech_types] is the list of GSSAPI mechanism that are acceptable. 
    If left unspecified,
    a default is used. [acceptor_name] is the name of the service to
    offer.

    Note that you normally can omit [mech_types]
    as GSSAPI already substitutes reasonable defaults
    (at least if Kerberos is available as mechanism). [acceptor_name] should
    normally be specified.

    [privacy] and [integrity] specify the desired level of protection.
    By default, both integrity and privacy are enabled if available, but
    it is no error if the mechanism doesn't support these features.

    [flags]: additional GSSAPI flags. These should not contain [`Conf_flag]
    and [`Integ_flag] (instead use [privacy] and [integrity], resp.).
   *)

(** Return properties of the server context *)
class type server_props =
object
  method mech_type : oid            (** Actual mechanism *)
  method flags : ret_flag list      (** Actual flags *)
  method time : time                (** Actual context lifetime *)
  method initiator_name : (string * oid)
    (** The name of the initiator. string and [oid] may be empty *)
  method initiator_name_exported : string
    (** The name of the initiator in exported format *)
  method deleg_credential : (exn * time) option
    (** If a credential was delegated it is returned here as [(e,t)].
        [e] is the exception [G.Credential] from the GSSAPI provider.
     *)
end

val marshal_server_props : server_props -> string
val unmarshal_server_props : string -> server_props
  (** This doesn't restore deleg_credential which is unmarshallable! *)



(** {2 Encodings} *)

(** Some conversions have been moved to {!Netoid}:

    - [oid_to_string] is now {!Netoid.to_string_curly}
    - [string_to_oid] is now {!Netoid.of_string_curly}

    The remaining functions can now be found in {!Netgssapi_support}.

 *)

(** {2 Create tokens} *)

(** All functions have been moved to {!Netgssapi_support} *)
