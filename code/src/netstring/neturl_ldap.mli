(** LDAP-specific URLs *)

(** This is an extension of {!Neturl} for LDAP. Note that you can simply
    use {!Neturl.parse_url} to parse LDAP URLs. Find useful accessor
    functions below to get LDAP-specific parts.
 *)

val ldap_url_dn         : ?encoded:bool -> Neturl.url -> string
val ldap_url_attributes : ?encoded:bool -> Neturl.url -> string list
val ldap_url_scope      :                  Neturl.url -> [ `Base | `One | `Sub ]
val ldap_url_filter     : ?encoded:bool -> Neturl.url -> string
val ldap_url_extensions : ?encoded:bool -> Neturl.url -> (bool * string * string option) list
  (** Return components of the URL. The functions return decoded strings
      unless [encoded:true] is set.
      If the component does not exist, the exception [Not_found]
      is raised. If the component cannot be parsed, [Malformed_URL] is
      raised.
   *)

val ldap_url_provides : ?dn:bool -> ?attributes:bool -> ?scope:bool ->
                        ?filter:bool -> ?extensions:bool -> Neturl.url -> bool
  (** Whether all the selected URL components are present and the accessor
      can return them (even if empty)
   *)

val make_ldap_url :
      ?encoded:bool ->
      ?host:string ->
      ?addr:Unix.inet_addr ->
      ?port:int ->
      ?socksymbol: Netsockaddr.socksymbol ->
      ?dn:string ->
      ?attributes:string list ->
      ?scope:[ `Base | `One | `Sub ] ->
      ?filter:string ->
      ?extensions:(bool * string * string option) list ->
      unit ->
        Neturl.url
  (** Create an LDAP URL *)

