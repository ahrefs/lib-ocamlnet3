(* $Id$ *)

type sasl_mechanism = (module Netsys_sasl_types.SASL_MECHANISM)

type credentials =
    (string * string * (string * string) list) list

module Info = struct
  let mechanism_name mech =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    M.mechanism_name

  let client_first mech =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    M.client_first

  let server_sends_final_data mech =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    M.server_sends_final_data

  let supports_authz mech =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    M.supports_authz
end


module Client = struct
  module type SESSION =
    sig
      include Netsys_sasl_types.SASL_MECHANISM
      val s : client_session
    end

  class type session =
    object
      method state : Netsys_sasl_types.client_state
      method configure_channel_binding : Netsys_sasl_types.cb -> unit
      method restart : unit -> unit
      method process_challenge : string -> unit
      method emit_response : unit -> string
      method channel_binding : Netsys_sasl_types.cb
      method user_name : string
      method authz_name : string
      method stash_session : unit -> string
      method session_id : string option
      method prop : string -> string
    end

  let session packed_session : session =
    let module S = (val packed_session : SESSION) in
    object
      method state =
        S.client_state S.s
      method configure_channel_binding cb =
        S.client_configure_channel_binding S.s cb
      method restart() =
        S.client_restart S.s
      method process_challenge msg =
        S.client_process_challenge S.s msg
      method emit_response() =
        S.client_emit_response S.s
      method channel_binding =
        S.client_channel_binding S.s
      method user_name =
        S.client_user_name S.s
      method authz_name =
        S.client_authz_name S.s
      method stash_session() =
        S.client_stash_session S.s
      method session_id =
        S.client_session_id S.s
      method prop key =
        S.client_prop S.s key
    end

  let create_session ~mech ~user ~authz ~creds ~params () =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let c = M.init_credentials creds in
    let s = M.create_client_session ~user ~authz ~creds:c ~params() in
    let module S =
      struct
        include M
        let s = s
      end in
    session (module S)

  let resume_session mech data =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let s = M.client_resume_session data in
    let module S =
      struct
        include M
        let s = s
      end in
    session (module S)

  let state s = s#state
  let configure_channel_binding s cb = s#configure_channel_binding cb
  let restart s = s#restart()
  let process_challenge s msg = s#process_challenge msg
  let emit_response s = s#emit_response()
  let channel_binding s = s#channel_binding
  let user_name s = s#user_name
  let authz_name s = s#authz_name
  let stash_session s = s#stash_session()
  let session_id s = s#session_id
  let prop s key = s#prop key
end


module Server = struct
  module type SESSION =
    sig
      include Netsys_sasl_types.SASL_MECHANISM
      val s : server_session
    end

  class type session =
    object
      method state : Netsys_sasl_types.server_state
      method process_response : string -> unit
      method process_response_restart : string -> bool -> bool
      method emit_challenge : unit -> string
      method stash_session : unit -> string
      method session_id : string option
      method prop : string -> string
      method channel_binding : Netsys_sasl_types.cb
      method user_name : string
      method authz_name : string
    end

  type 'credentials init_credentials =
      (string * string * (string * string) list) list -> 'credentials

  let session packed_session : session =
    let module S = (val packed_session : SESSION) in
    object
      method state =
        S.server_state S.s
      method process_response msg =
        S.server_process_response S.s msg
      method process_response_restart msg stale =
        S.server_process_response_restart S.s msg stale
      method emit_challenge() =
        S.server_emit_challenge S.s
      method stash_session() =
        S.server_stash_session S.s
      method session_id =
        S.server_session_id S.s
      method prop key =
        S.server_prop S.s key
      method channel_binding =
        S.server_channel_binding S.s
      method user_name =
        S.server_user_name S.s
      method authz_name =
        S.server_authz_name S.s
    end

  type lookup =
      { lookup : 'c . sasl_mechanism -> 'c init_credentials -> string ->
                 string -> 'c option
      }

  let create_session ~mech ~lookup ~params () =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let init_creds list =
      M.init_credentials list in
    let server_lookup user authz =
      lookup.lookup mech init_creds user authz in
    let s =
      M.create_server_session ~lookup:server_lookup ~params () in
    let module S =
      struct
        include M
        let s = s
      end in
    session (module S)

  let resume_session ~mech ~lookup data =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let init_creds list =
      M.init_credentials list in
    let server_lookup user authz =
      lookup.lookup mech init_creds user authz in
    let s =
      M.server_resume_session ~lookup:server_lookup data in
    let module S =
      struct
        include M
        let s = s
      end in
    session (module S)

  let state s = s#state
  let process_response s msg = s#process_response msg
  let process_response_restart s msg stale =
    s#process_response_restart msg stale
  let emit_challenge s = s#emit_challenge()
  let channel_binding s = s#channel_binding
  let user_name s = s#user_name
  let authz_name s = s#authz_name
  let stash_session s = s#stash_session()
  let session_id s = s#session_id
  let prop s key = s#prop key
end
