(* $Id$ *)

(** SCRAM mechanism for authentication (RFC 5802) *)

(** This implements SCRAM for SASL and GSSAPI.

    {b This module needs the SHA-1 hash function. In order to use it,
    initialize crypto support, e.g. by including the [nettls-gnutls]
    packages and calling {!Nettls_gnutls.init}.}

    As for all SASL mechanisms in OCamlnet, SASLprep is not automatically
    called. Users of SCRAM should pass user names and passwords through
    {!Netsaslprep.saslprep}.

 *)

type ptype = [ `GSSAPI | `SASL ]
  (** Profile types:
       - [`GSSAPI]: as defined in RFC 5802, the gs2-header is omitted
       - [`SASL]: as defined in RFC 5802
   *)

type profile =
    { ptype : ptype;
      hash_function : Netsys_digests.iana_hash_fn; (** Which hash function *)
      return_unknown_user : bool;  (** Whether servers exhibit the fact that the
				       user is unknown *)
      iteration_count_limit : int; (** Largest supported iteration number *)
    }
  (** Profile *)

type cb = Netsys_sasl_types.cb
  (** Using the same channel binding type as for SASL *)

type server_error =
    [ `Invalid_encoding
    | `Extensions_not_supported
    | `Invalid_proof
    | `Channel_bindings_dont_match
    | `Server_does_support_channel_binding
    | `Channel_binding_not_supported
    | `Unsupported_channel_binding_type
    | `Unknown_user
    | `Invalid_username_encoding
    | `No_resources
    | `Other_error
    | `Extension of string
    ]
  (** Error codes of this protocol *)

type client_session
  (** Session context for clients *)


type server_session
  (** Session context for servers *)


(** Client exceptions: The exceptions are returned by [client_error_flag],
    but never raised.
 *)

exception Invalid_encoding of string * string
  (** Returned by clients when something cannot be decoded. First string
      is an error message, the second string the raw message that cannot
      be decoded
   *)

exception Invalid_username_encoding of string * string
  (** Returned by clients when the username does not match the requirements.
      Arguments as for [Invalid_encoding].
   *)

exception Extensions_not_supported of string * string
  (** Returned by clients when the server enables an unsupported extension.
      Arguments as for [Invalid_encoding].
   *)

exception Protocol_error of string
  (** Returned by clients when the server violates the protocol. The argument
      is a message.
   *)

exception Invalid_server_signature
  (** Returned by clients when the signature sent by the server is invalid
      (i.e. the server does not know the client password)
   *)

exception Server_error of server_error
  (** Returned by clients when the server sent an error code *)


val error_of_exn : exn -> string
  (** Converts one of the above exceptions to a human-readable string *)


val profile : ?return_unknown_user:bool -> ?iteration_count_limit:int ->
              ptype -> Netsys_digests.iana_hash_fn -> profile
  (** Creates a profile *)

val string_of_server_error : server_error -> string
val server_error_of_string : string -> server_error
  (** Conversion *)

val mechanism_name : profile -> string
  (** The official name of the mechanism *)


(** {2 Clients} *)

(** The idea is to create a client session [s] first. The functions
    [client_emit_flag] and [client_recv_flag] indicate now whether
    the client needs to emit a new message, or whether it needs to
    receive a message, respectively. Emission is done by [client_emit_message],
    reception by [client_recv_message]. If everything goes well, the
    protocol state advances, and finally [client_finish_flag] is true.
    This indicates that the client is authenticated and that the server
    knows the client's password. If an error occurs, an exception is
    raised (see above for possibilities), and [client_error_flag] signals
    [true].
 *)

val create_client_session :
      ?nonce: string ->
      profile -> string -> string -> client_session
  (** [create_client_session p username password]: Creates a new client
      session for profile [p] so that the client authenticates as user
      [username], and proves its identity with the given [password].
   *)

val create_client_session2 :
    ?nonce:string -> 
    profile -> string -> string -> string -> client_session
  (** [create_client_session p username authzname password]: Like
      [create_client_session], but also sets the authorization name
      (only processed for the SASL profile).
   *)

val client_configure_channel_binding : client_session -> cb -> client_session
  (** Sets whether to request channel binding.
   *)

val client_restart : client_session -> string -> client_session
  (** Restart a client session (draft-ietf-httpauth-scram-auth-15).
      The string is the sr attribute.
   *)

val client_restart_stale : client_session -> string -> client_session
  (** Restart a client session after the server indicated that the session
      is stale. The string arg is the new "sr" attribute
      (draft-ietf-httpauth-scram-auth-15).
   *)

val client_emit_flag : client_session -> bool
  (** Whether [client_emit_message] can now be called *)

val client_recv_flag : client_session -> bool
  (** Whether [client_recv_message] can now be called *)

val client_finish_flag : client_session -> bool
  (** Whether the client is authenticated and the server verified *)

val client_semifinish_flag : client_session -> bool
  (** Whether the client is authentication *)

val client_error_flag : client_session -> exn option
  (** Whether an error occurred, and the protocol cannot advance anymore *)

val client_channel_binding : client_session -> cb
  (** Returns the channel binding *)

val client_emit_message : client_session -> client_session * string
  (** Emits the next message to be sent to the server *)

val client_emit_message_kv : client_session -> 
                       client_session * string option * (string * string) list
  (** Emits the next message to be sent to the server. The message is not
      encoded as a single string, but as [(gs2_opt, kv)] where
      [gs2_opt] is the optional GS2 header (the production [gs2-header] from
      the RFC), and [kv] contains the parameters as key/value pairs.
   *)

val client_recv_message : client_session -> string -> client_session
  (** Receives the next message from the server *)

val client_protocol_key : client_session -> string option
  (** The 128-bit protocol key for encrypting messages. This is available 
      as soon as the second client message is emitted.
   *)

val client_user_name : client_session -> string
  (** The user name *)

val client_authz_name : client_session -> string
  (** The authorization name *)

val client_password : client_session -> string
  (** The password *)

val client_export : client_session -> string
val client_import : string -> client_session
  (** Exports a client session as string, and imports the string again.

      The export format is just a marshalled Ocaml value.
   *)

val client_prop : client_session -> string -> string
  (** Returns a property of the client (or Not_found):
       - "snonce": server nonce
       - "cnonce": client nonce
       - "salt": password salt
       - "i": iteration count
       - "client_key": this key is derived from the salted password but
         cannot be derived from the stored key. Its presence proves that the
         password was entered. It is ideal for encrypting data with a per-user
         key. The client key is known both to the client and to the server
         (after running the protocol).
       - "protocol_key": another key defined in RFC-5801 known by both
         sides. The protocol key is additionally also dependent on the nonces.
       - "error"
   *)




(** {2 Servers} *)

(** The idea is to create a server session [s] first. The functions
    [server_emit_flag] and [server_recv_flag] indicate now whether
    the server needs to emit a new message, or whether it needs to
    receive a message, respectively. Emission is done by [server_emit_message],
    reception by [server_recv_message]. If everything goes well, the
    protocol state advances, and finally [server_finish_flag] is true.
    This indicates that the client could be authenticated.

    If an error occurs, {b no} exception is raised, and the protocol
    advances nevertheless, and finally the server sends an error token
    to the client. After this, [server_error_flag] returns true.
 *)

type credentials =
  [ `Salted_password of string * string * int
  | `Stored_creds of string * string * string * int
  ]
  (** Two forms of providing credentials:
       - [`Salted_password(spw,salt,iteration_count)]: get the
         salted password with
         [spw = salt_password h password salt iteration_count]
       - [`Stored(stkey, srvkey, salt, iteration_count)]: get the
         pair (stkey, srvkey) with
         [stored_key h password salt iteration_count]
   *)

val create_server_session : 
      ?nonce:string ->
      profile -> (string -> credentials) -> server_session
  (** [create_server_session p auth]: Creates a new server session with
      profile [p] and authenticator function [auth].

      The function is [auth] is called when the credentials of the
      client have been received to check whether the client can be
      authenticated. It is called as

      {[
      let credentials = auth username
      ]}

      where [username] is the user name. The function can now raise
      [Not_found] if the user is unknown, or it can return the
      credentials. Note that the cleartext password needs not to
      be known. The credentials contain a salt and an iteration count:
      [salt] is a random string, and [iteration_count] a
      security parameter that should be at least 4096. Whereas [salt]
      should be different for each user, the [iteration_count] can be
      chosen as a constant (e.g. 4096). Now [salted_password] can be
      computed from the cleartext password and these two extra parameters.
      See [salt_password] below.
   *)

val create_server_session2 : 
      ?nonce:string ->
      profile -> (string -> string -> credentials) -> server_session
  (** Same as [create_server_session], but the authentication callback
      gets two arguments:

      {[
      let credentials = auth username authzname
      ]}

      where [authzname] is the passed authorization name (or "" if na).
   *)

val create_salt : unit -> string
  (** Creates a random string suited as salt *)

val salt_password :  Netsys_digests.iana_hash_fn -> 
                     string -> string -> int -> string
  (** [let salted_password = salt_password h password salt iteration_count]

      Use this now as credentials
      [`Salted_password(salted_password,salt,iteration_count)].

      As we do not implement [SASLprep] only passwords consisting of
      US-ASCII characters are accepted ([Invalid_encoding] otherwise).
   *)

val stored_key : Netsys_digests.iana_hash_fn -> 
                     string -> string -> int -> string * string

  (** [let stkey,srvkey = stored_key h password salt iteration_count]

      Use this now as credentials
      [`Stored_creds(stkey,srvkey,salt,iteration_count)].
   *)

val server_emit_flag : server_session -> bool
  (** Whether [server_emit_message] can now be called *)

val server_recv_flag : server_session -> bool
  (** Whether [server_recv_message] can now be called *)

val server_finish_flag : server_session -> bool
  (** Whether the client is authenticated *)

val server_error_flag : server_session -> bool
  (** Whether an error occurred, and the protocol cannot advance anymore *)

val server_emit_message : server_session -> server_session * string
  (** Emits the next message to be sent to the client *)

val server_emit_message_kv : server_session -> 
                               server_session * (string * string) list
  (** Emits the next message to be sent to the client. The message is returned
      as a list of key/value pairs.
   *)

val server_recv_message : server_session -> string -> server_session
  (** Receives the next message from the client *)

val server_protocol_key : server_session -> string option
  (** The 128-bit protocol key for encrypting messages. This is available 
      as soon as the second client message has been received.
   *)

val server_channel_binding : server_session -> cb
  (** Returns the channel binding requirement. It is
      up to the application to enforce the binding. This information is 
      available as soon as the second client message has been received
   *)

val server_user_name : server_session -> string option
  (** The user name as transmitted from the client. This is returned here
      even before the authentication is completed!
   *)

val server_authz_name : server_session -> string option
  (** The authorization name as transmitted from the client. This is returned
      here
      even before the authentication is completed!
   *)

val server_export : server_session -> string
val server_import : string -> server_session
val server_import_any : string -> (string -> credentials) ->
                        server_session
val server_import_any2 : string -> (string -> string -> credentials) ->
                         server_session
  (** Exports a server session as string, and imports the string again.
      [server_import] can only import established sessions.
      [server_import_any] can also import unfinished sessions, but one needs
      to pass the authentication function as for [server_create_session].
      [server_import_any2] uses the modified auth function as in
      [server_create_session2].
   *)


val server_prop : server_session -> string -> string
  (** Returns a property of the server (or Not_found) - see also [client_prop]
      above:
       - "snonce"
       - "cnonce"
       - "salt"
       - "i" (iteration_count)
       - "client_key"
       - "protocol_key"
   *)


(** {2 Confidentiality} *)

type specific_keys =
    { kc : string;
      ke : string;
      ki : string
    }
  (** The specific keys to use *)

(** This module implements AES in Ciphertext Stealing mode (see RFC 3962) *)
module AES_CTS : sig
  val c : int
  val m : int
  val encrypt : string -> string -> string
  val encrypt_mstrings : 
    string -> Netxdr_mstring.mstring list -> Netxdr_mstring.mstring list
  val decrypt : string -> string -> string
  val decrypt_mstrings : 
    string -> Netxdr_mstring.mstring list -> Netxdr_mstring.mstring list
  val tests : (string * string * string) list
  val run_tests : unit -> bool
  val run_mtests : unit -> bool
end


(** This is the cryptosystem as defined in RFC 3961, so far needed here.
    This uses [AES_CTS] as cipher, and SHA1-96 for signing.
 *)
module Cryptosystem : sig
  exception Integrity_error

  val derive_keys : string -> int -> specific_keys
    (** [derive_keys protocol_key usage]: Returns the specific keys for
	this [protocol_key] and this [usage] numbers. See RFC 4121 for
	applicable usage numbers
     *)

  val encrypt_and_sign :  specific_keys -> string -> string
    (** Encrypts the plaintext message and adds a signature to the
	ciphertext.

	Returns [ciphertext_with_signature].
     *)

  val encrypt_and_sign_mstrings : 
         specific_keys -> Netxdr_mstring.mstring list -> Netxdr_mstring.mstring list
    (** Same, but with data representation as [mstring list] *)

  val decrypt_and_verify :  specific_keys -> string -> string
    (** Decrypts the ciphertext and verifies the attached signature.
	Returns the restored plaintext. 

	For very short plaintexts (< 16 bytes) there will be some
	padding at the end ("residue"), as returned as [ec] above.
	We ignore this problem generally,
	because GSS-API adds a 16-byte header to the plaintext anyway,
	so these short messages do not occur.

	If the signature is not valid, the exception [Integrity_error]
	is raised.
     *)

  val decrypt_and_verify_mstrings :
         specific_keys -> Netxdr_mstring.mstring list -> Netxdr_mstring.mstring list
    (** Same, but with data representation as [mstring list] *)

  val get_ec : specific_keys -> int -> int
    (** [let ec = get_ec e_keys n]:
        Returns the required value for the "extra count" field of
	RFC 4121 if the plaintext message has size [n]. Here,
	[n] is the size of the payload message plus the token
	header of 16 bytes, i.e. the function is always called with
	[n >= 16].

	Here, the returned [ec] value is always 0.
     *)

  val get_mic : specific_keys -> string -> string
    (** Returns a message integrity code *)

  val get_mic_mstrings :
         specific_keys -> Netxdr_mstring.mstring list -> string
    (** Same, but with data representation as [mstring list] *)
end


module Debug : sig
  val enable : bool ref
    (** Enable debugging of this module *)
end
