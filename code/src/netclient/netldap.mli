(* $Id$ *)

(** LDAP client *)

(** This is a simple asynchronous LDAP client.

    Regarding LDAP URLs, please note that there are some special functions
    in {!Neturl_ldap}.

 *)

(** {2 Error handling} *)

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
  (** Raised when the TCP connection times out. Timeouts should be considered
      as non-recoverable by the user, and the connection should be aborted.
   *)

exception LDAP_error of result_code * string
  (** The server indicates a (logical) error. Such errors are normal messages,
      and the connection remains intact.
   *)

exception Auth_error of string
  (** Authentication error *)

(** {2 Specifying the LDAP server} *)

type tls_mode = [ `Disabled | `Immediate | `StartTLS | `StartTLS_if_possible ]
  (** Options:
       - [`Disabled]: do not negotiate TLS
       - [`Immediate]: assume that the connection directly requires TLS
       - [`StartTLS]: upgrade an initially unprotected connection to TLS
       - [`StartTLS_if_possible]: upgrade an unprotected connection to TLS
         if possible (i.e. if supported by both ends of the connection)
   *)

class type ldap_server =
object
  method ldap_endpoint : Netsockaddr.socksymbol
  method ldap_timeout : float
  method ldap_peer_name : string option
  method ldap_tls_config : (module Netsys_crypto_types.TLS_CONFIG) option
  method ldap_tls_mode : tls_mode
end

val ldap_server : ?timeout:float ->
                  ?peer_name:string ->
                  ?tls_config:(module Netsys_crypto_types.TLS_CONFIG) ->
                  ?tls_mode:tls_mode ->
                  Netsockaddr.socksymbol -> ldap_server
  (** Specifies how to reach the server: e.g.

      {[
let server = ldap_server (`Inet_byname("hostname", 389))
      ]}

      Options:

       - [timeout]: The timeout for connecting and for subsequent 
         request/response cycles. Defaults to 15 seconds.
       - [peer_name]: The expected domain name in the certificate for
         TLS-secured connections. If not passed, the name is derived from
         the socksymbol argument.
       - [tls_config]: The TLS configuration (i.e. the TLS provider and
         how to use it). Defaults to the provider set in {!Netsys_crypto},
         and to requiring valid server certificates.
       - [tls_mode]: Whether and how to negotiate TLS. Defaults to
         [`StartTLS_if_possible].
   *)

val ldap_server_of_url : ?timeout:float ->
                         ?tls_config:(module Netsys_crypto_types.TLS_CONFIG) ->
                         ?tls_mode:tls_mode ->
                         Neturl.url -> ldap_server
  (** Gets the host and port from an LDAP URL. Otherwise the same as
      [ldap_server].

      The URL can have schemes "ldap" or "ldaps". In the latter case, the
      [tls_mode] is automatically adjusted to [`Immediate].
   *)

(** {2 Specifying LDAP credentials} *)

type bind_creds

val anon_bind_creds : bind_creds
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
  (** Close the connection using the close protocol *)

val close : ldap_connection -> unit
  (** Same as synchronous function *)

val abort : ldap_connection -> unit
  (** Close the connection immediately *)

val conn_bind_e : ldap_connection -> bind_creds -> unit Uq_engines.engine
  (** Bind the connection to credentials *)

val conn_bind : ldap_connection -> bind_creds -> unit
  (** Same as synchronous function *)

val tls_session_props : ldap_connection -> Nettls_support.tls_session_props option
  (** Returns the TLS session properties *)

(** {2 LDAP results} *)

(** A class type for encapsulating results *)
class type ['a] ldap_result =
  object
    method code : result_code
      (** The code, [`Success] on success *)
    method matched_dn : string
      (** The matchedDN field sent with some codes *)
    method diag_msg : string
      (** diagnostic message *)
    method referral : string list
      (** if non-empty, a list of URIs where to find more results *)
    method value : 'a
      (** the value when [code=`Success]. Raises [LDAP_error] for other
          codes *)
    method partial_value : 'a
      (** the value so far available, independently of the code *)
  end

exception Notification of string ldap_result
  (** An unsolicited notification. The string is the OID. Best reaction is
      to terminate the connection. This is e.g. sent when the server cannot
      decode the client message, but also for other special conditions.
      [Notification] exception are directly raised by the LDAP client functions.
   *)


(** {2 LDAP searches} *)

type scope = [ `Base | `One | `Sub ]
  (** The scope of the search:
       - [`Base]: only the base object
       - [`One]: only the direct children of the base object
       - [`Sub]: the base object and all direct and indirect children
   *)

type deref_aliases = [ `Never | `In_searching | `Finding_base_obj | `Always ]
  (** What to do when aliases (server-dereferenced symbolic links) are found
      in the tree:
       - [`Never]: do not dereference aliases but return them as part of the
         search result
       - [`In_searching]: when aliases are found in the children of the base
         object dereference the aliases, and continue the search there, and
         repeat this recursively if needed
       - [`Finding_base_obj]: dereference alises in base objects but not in
         children
       - [`Always]: always dereference aliases
   *)

type filter = 
  [ `And of filter list
  | `Or of filter list
  | `Not of filter
  | `Equality_match of string * string
  | `Substrings of string * string option * string list * string option
  | `Greater_or_equal of string * string
  | `Less_or_equal of string * string
  | `Present of string
  | `Approx_match of string * string
  | `Extensible_match of string option * string option * string * bool
  ]
  (** Filter:
       - [`Equality_match(attr_descr, value)]
       - [`Substrings(attr_descr, prefix_match, substring_matches, suffix_match)]
       - [`Greater_or_equal(attr_descr,value)]
       - [`Less_or_equal(attr_descr,value)]
       - [`Present(attr_descr)]
       - [`Approx_match(attr_descr,value)]
       - [`Extensible_match(matching_rule_id, attr_descr, value, dn_attrs)]

     Here, [attr_descr] is the name of the attribute, either given by
     an OID (in dotted representation) or a by a descriptive name. There
     can be options, separated from the name by a semicolon.

     The [value] is the value to filter with (an UTF-8 string).
   *)

type search_result =
  [ `Entry of string * (string * string list) list
  | `Reference of string list
  ]
  (** Search results are either entries or references:
       - [`Entry(object_dn, [(attr_descr, values); ...])]
       - [`Reference urls]: The entry is not present on this server but can
         be looked up by following one of the [urls]
   *)

val search_e : ldap_connection ->
               base:string ->
               scope:scope ->
               deref_aliases:deref_aliases ->
               size_limit:int ->
               time_limit:int ->
               types_only:bool ->
               filter:filter ->
               attributes:string list ->
               unit ->
               search_result list ldap_result Uq_engines.engine
  (** Run the specified search: Search at [base] according to [scope] for
      entries matching the [filter] and return their [attributes].

      If the [base] object is not present on the server but somewhere else
      (redirection) the result will be empty and the referral is set in the
      response. If children
      of the base object are redirected to another server, the result will
      contain [`Reference] elements. 

      Note that [time_limit] is a server-enforced limit (in seconds; 0 for
      no limit). Independently of that
      this client employs the timeout set in the [ldap_connection]. This timeout
      limits the time between two consecutive server messages.

      The [size_limit] limits the number of returned entries (0 for no limit).

      If [types_only] there will not be values in the result (instead, empty
      lists are returned).

      A [filter] is mandatory. If you want to get all results, specify a
      useless filter like [`Present("objectclass")].

      If you pass an empty [attributes] list, no attributes will be
      returned.  In order to get all attributes, pass the list
      [["*"]]. The asterisk can also be appended to a non-empty list
      to get all remaining attributes in any order.
  *)

val search : ldap_connection ->
               base:string ->
               scope:scope ->
               deref_aliases:deref_aliases ->
               size_limit:int ->
               time_limit:int ->
               types_only:bool ->
               filter:filter ->
               attributes:string list ->
               unit ->
               search_result list ldap_result
  (** Same as synchronous function *)

val compare_e : ldap_connection ->
                dn:string ->
                attr:string ->
                value:string ->
                unit ->
                  bool ldap_result Uq_engines.engine
  (** [compare_e conn ~dn ~attr ~value ()]: returns true if the attribute
      [attr] of entry [dn] has [value] (according to equality matching)
   *)

val compare : ldap_connection ->
              dn:string ->
              attr:string ->
              value:string ->
              unit ->
                bool ldap_result
  (** Same as synchronous function *)


(** {2 LDAP updates} *)

(** Although updates do not return a regular result, there might be an
    error message. An exception is not automatically raised. It is done,
    though, when the [value] method of the result is invoked (returning
    normally just [()]). Example:

{[
let () = (add conn ~dn ~attributes) # value
]}

 *)

val add_e : ldap_connection ->
            dn:string ->
            attributes:(string * string list) list ->
            unit ->
              unit ldap_result Uq_engines.engine
 (** [add_e conn ~dn ~attributes]: Adds a new entry under [dn] with the
     [attributes], given as list [(attr_descr, values)].
  *)

val add : ldap_connection ->
          dn:string ->
          attributes:(string * string list) list ->
          unit ->
            unit ldap_result
  (** Same as synchronous function *)

val delete_e : ldap_connection ->
               dn:string ->
               unit ->
                 unit ldap_result Uq_engines.engine
 (** [delete_e conn ~dn]: Deletes the entry [dn]
  *)

val delete : ldap_connection ->
             dn:string ->
             unit ->
               unit ldap_result
  (** Same as synchronous function *)

type operation = [`Add|`Delete|`Replace]

val modify_e : ldap_connection -> 
               dn:string -> 
               changes:(operation * (string * string list)) list ->
               unit ->
                 unit ldap_result Uq_engines.engine
  (** [modify_e conn ~dn ~changes ()]: Modifies attributes of the entry for
      [dn]. The [changes] are given as a list [(op, (attr_descr, values))].
      Here, [op] is the operation to do. [attr_descr] identifies the attribute
      to add/delete/replace. The [values] are the additional values, or the
      values to delete, or the values to substitute. In case of "delete",
      an empty [values] list means to delete the whole attribute.
   *)

val modify : ldap_connection -> 
             dn:string -> 
             changes:(operation * (string * string list)) list ->
             unit ->
               unit ldap_result
  (** Same as synchronous function *)


val modify_dn_e : ldap_connection ->
                  dn:string ->
                  new_rdn:string ->
                  delete_old_rdn:bool ->
                  new_superior:string option ->
                  unit ->
                    unit ldap_result Uq_engines.engine
  (** [modify_dn_e conn ~dn ~new_rdn ~delete_old_rdn ~new_superior]:
      renames and/or moves the entry in the tree. The entry under [dn]
      is the modified entry. The [new_rdn] is the new name of the leaf
      (renaming). If [delete_old_rdn], the attributes describing the old
      name of the leaf are deleted, and otherwise retained. If
      [new_superior] is set, the entry is additionally moved to this
      new parent entry.
   *)

val modify_dn : ldap_connection ->
                dn:string ->
                new_rdn:string ->
                delete_old_rdn:bool ->
                new_superior:string option ->
                unit ->
                  unit ldap_result
  (** Same as synchronous function *)


val modify_password_e : ldap_connection ->
                        uid:string option ->
                        old_pw:string option ->
                        new_pw:string option ->
                        unit ->
                          string option ldap_result Uq_engines.engine
  (** This is the LDAP extension for modifying passwords (potentially
      outside the tree; RFC 3062). [uid] is the user ID to modify
      (which can be a DN but needs not to). The old password can be
      specified in [old_pw]. The new password is in [new_pw].

      In cases where the server generates a password, this one is contained
      in the returned result.
   *)

val modify_password : ldap_connection ->
                      uid:string option ->
                      old_pw:string option ->
                      new_pw:string option ->
                      unit ->
                        string option ldap_result
  (** Same as synchronous function *)


(** {2 LDAP routines} *)

val test_bind_e : ?proxy:#Uq_engines.client_endpoint_connector ->
                  ldap_server -> bind_creds -> 
                  Unixqueue.event_system -> bool Uq_engines.engine
  (** Tries to bind to the server with the given credentials. Returns whether
      successful.
   *)

val test_bind : ?proxy:#Uq_engines.client_endpoint_connector ->
                ldap_server -> bind_creds -> bool
  (** Same as synchronous function *)

val retr_password_e : dn:string -> ldap_server -> bind_creds ->
                      Unixqueue.event_system -> 
                      (string * string * (string * string) list) list Uq_engines.engine
  (** Connects and binds to the server, and retrieves the [userPassword] and
      [authPassword] attributes of the entry referenced by [dn]. The
      passwords are returned in the format outlined in {!Credentials}.
      This function can process these password formats:
       - [userPassword] in RFC-2307 format using any schemes
       - [authPassword] in RFC-3112 format using any schemes

      Raises an [LDAP_error] exception when problems occur.
   *)

val retr_password : dn:string -> ldap_server -> bind_creds ->
                      (string * string * (string * string) list) list
  (** Same as synchronous function *)

(** {1 Debugging} *)

module Debug : sig
  val enable : bool ref
    (** Enables {!Netlog}-style debugging of this module *)
end
