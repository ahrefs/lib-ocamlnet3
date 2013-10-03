(* $Id$ *)

module type TLS_PROVIDER =
  sig
    type config
    type credentials
    type endpoint
    type error_code
    type direction = [ `R | `W ]

    exception EAGAIN of direction
    exception EINTR
    exception Switch_request
    exception Error of error_code
    exception Warning of error_code

    val error_message : error_code -> string
    val error_name : error_code -> string

    type dh_params =
        [ `PKCS3_PEM_file of string
        | `PKCS3_DER of string
        | `Generate of int
        ]

    val create_config :
          ?algorithms : string ->
          ?dh_params : dh_params ->
          peer_auth : [ `None | `Optional | `Required ] ->
          credentials : credentials ->
          unit ->
            config

    type crt_list =
        [`PEM_file of string | `DER of string list]
    type crl_list =
        [`PEM_file of string | `DER of string list]
    type private_key =
        [ `PEM_file of string 
        | `RSA of string 
        | `DSA of string
        | `EC of string
        | `PKCS8 of string
        | `PKCS8_encrypted of string
        ]

    val create_x509_credentials :
          ?trust : crt_list list ->
          ?revoke : crl_list list ->
          ?keys : (crt_list * private_key * string option) list ->
          unit ->
            credentials

    val create_endpoint :
          role : [ `Server | `Client ] ->
          recv : (Netsys_types.memory -> int) ->
          send : (Netsys_types.memory -> int -> int) ->
          config ->
            endpoint

    val hello : endpoint -> unit
    val bye : endpoint -> [`W | `RW] -> unit
    val verify : endpoint -> string -> unit
    val get_endpoint_crt : endpoint -> string
    val get_peer_crt_list : endpoint -> string list
    val switch : endpoint -> config -> bool
    val accept_switch : endpoint -> config -> unit
    val refuse_switch : endpoint -> unit
    val send : endpoint -> Netsys_types.memory -> int -> int
    val recv : endpoint -> Netsys_types.memory -> int
    val recv_will_not_block : endpoint -> bool
    val get_cipher_algo : endpoint -> string
    val get_kx_algo : endpoint -> string
    val get_mac_algo : endpoint -> string
    val get_compression_algo : endpoint -> string
    val get_cert_type : endpoint -> string
    val get_protocol : endpoint -> string

    type server_name = [ `Domain of string ]

    val get_addressed_servers : endpoint -> server_name list
    val set_addressed_servers : endpoint -> server_name list -> unit
    val implementation_name : string
    val implementation : unit -> exn
  end


module type TLS_ENDPOINT =
  sig
    module TLS : TLS_PROVIDER
    val endpoint : TLS.endpoint
  end
