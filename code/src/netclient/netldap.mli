(* $Id$ *)

type result_code =
  [ `Success
  | `OperationsError
  | `ProtocolError
  | `TimeLimitExceeded
  | `SizeLimitExceeded
  | `CompareFalse
  | `CompareTrue
  | `AuthMethodNotSupported
  | `StrongAuthRequired
  | `Referral
  | `AdminLimitExceeded
  | `UnavailableCriticalExtension
  | `ConfidentialityRequired
  | `SaslBindInProgress
  | `NoSuchAttribute
  | `UndefinedAttributeType
  | `InappropriateMatching
  | `ConstraintViolation
  | `AttributeOrValueExists
  | `InvalidAttributeSyntax
  | `NoSuchObject
  | `AliasProblem
  | `InvalidDNSyntax
  | `AliasDereferencingProblem
  | `InappropriateAuthentication
  | `InvalidCredentials
  | `InsufficientAccessRights
  | `Busy
  | `Unavailable
  | `UnwillingToPerform
  | `LoopDetect
  | `NamingViolation
  | `ObjectClassViolation
  | `NotAllowedOnNonLeaf
  | `NotAllowedOnRDN
  | `EntryAlreadyExists
  | `ObjectClassModsProhibited
  | `AffectsMultipleDSAs
  | `Other
  | `Unknown_code of int
  ]

exception Timeout
exception LDAP_error of result_code * string
exception Auth_error of string

(** {2 Specifying the LDAP server} *)

class type ldap_server =
object
  method ldap_endpoint : Netsockaddr.socksymbol
  method ldap_timeout : float
  method ldap_peer_name : string option
  method ldap_tls_config : (module Netsys_crypto_types.TLS_CONFIG) option
end

val ldap_server : ?timeout:float ->
                  ?peer_name:string ->
                  ?tls_config:(module Netsys_crypto_types.TLS_CONFIG) ->
                  ?tls_enable:bool ->
                  Netsockaddr.socksymbol -> ldap_server

(** {2 Specifying LDAP credentials} *)

type bind_creds

val simple_bind_creds : dn:string -> pw:string -> bind_creds
val sasl_bind_creds : dn:string -> user:string -> authz:string ->
                       creds:(string * string * (string * string)list)list ->
                       params:(string * string * bool) list ->
                       (module Netsys_sasl_types.SASL_MECHANISM) ->
                       bind_creds

(** {2 LDAP connections} *)

type ldap_connection

val connect_e :
      ?proxy:#Uq_engines.client_endpoint_connector ->
      ldap_server -> Unixqueue.event_system -> 
      ldap_connection Uq_engines.engine
val connect : 
      ?proxy:#Uq_engines.client_endpoint_connector ->
      ldap_server -> ldap_connection

val close_e : ldap_connection -> unit Uq_engines.engine
val close : ldap_connection -> unit
val abort : ldap_connection -> unit

val conn_bind_e : ldap_connection -> bind_creds -> unit Uq_engines.engine
val conn_bind : ldap_connection -> bind_creds -> unit

(** {2 LDAP searches} *)

(* TODO *)

(** {2 LDAP routines} *)

val test_bind_e : ?proxy:#Uq_engines.client_endpoint_connector ->
                  ldap_server -> bind_creds -> 
                  Unixqueue.event_system -> bool Uq_engines.engine
val test_bind : ?proxy:#Uq_engines.client_endpoint_connector ->
                ldap_server -> bind_creds -> bool

(*
val retr_password_e : dn:string -> ldap_server -> bind_creds ->
                      (string * string * (string * string) list) list engine
val retr_password : dn:string -> ldap_server -> bind_creds ->
                      (string * string * (string * string) list) list
*)
