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
      module M : Netsys_sasl_types.SASL_MECHANISM
      val s : M.client_session
    end

  class type session =
    object
      method state : Netsys_sasl_types.client_state
      method configure_channel_binding : Netsys_sasl_types.cb -> session
      method restart : unit -> session
      method process_challenge : string -> session
      method emit_response : unit -> session * string
      method channel_binding : Netsys_sasl_types.cb
      method user_name : string
      method authz_name : string
      method stash_session : unit -> string
      method session_id : string option
      method prop : string -> string
      method gssapi_props : Netsys_gssapi.client_props
    end

  let rec session packed_session : session =
    let module S = (val packed_session : SESSION) in
    let pack s =
      let module S' = struct module M = S.M let s = s end in
      session (module S') in
    object
      method state =
        S.M.client_state S.s
      method configure_channel_binding cb =
        pack (S.M.client_configure_channel_binding S.s cb)
      method restart() =
        pack (S.M.client_restart S.s)
      method process_challenge msg =
        pack (S.M.client_process_challenge S.s msg)
      method emit_response() =
        let (s', resp) = S.M.client_emit_response S.s in
        (pack s', resp)
      method channel_binding =
        S.M.client_channel_binding S.s
      method user_name =
        S.M.client_user_name S.s
      method authz_name =
        S.M.client_authz_name S.s
      method stash_session() =
        S.M.client_stash_session S.s
      method session_id =
        S.M.client_session_id S.s
      method prop key =
        S.M.client_prop S.s key
      method gssapi_props =
        S.M.client_gssapi_props S.s
    end

  let create_session ~mech ~user ~authz ~creds ~params () =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let c = M.init_credentials creds in
    let s = M.create_client_session ~user ~authz ~creds:c ~params() in
    let module S =
      struct
        module M = M
        let s = s
      end in
    session (module S)

  let resume_session mech data =
    let module M = (val mech : Netsys_sasl_types.SASL_MECHANISM) in
    let s = M.client_resume_session data in
    let module S =
      struct
        module M = M
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
  let gssapi_props (s:session) = s#gssapi_props
end


module Server = struct
  module type SESSION =
    sig
      module M : Netsys_sasl_types.SASL_MECHANISM
      val s : M.server_session
    end

  class type session =
    object
      method state : Netsys_sasl_types.server_state
      method process_response : string -> session
      method process_response_restart : string -> bool -> session * bool
      method emit_challenge : unit -> session * string
      method stash_session : unit -> string
      method session_id : string option
      method prop : string -> string
      method channel_binding : Netsys_sasl_types.cb
      method user_name : string
      method authz_name : string
      method gssapi_props : Netsys_gssapi.server_props
    end

  type 'credentials init_credentials =
      (string * string * (string * string) list) list -> 'credentials

  let rec session packed_session : session =
    let module S = (val packed_session : SESSION) in
    let pack s =
      let module S' = struct module M = S.M let s = s end in
      session (module S') in
    object
      method state =
        S.M.server_state S.s
      method process_response msg =
        pack (S.M.server_process_response S.s msg)
      method process_response_restart msg stale =
        let s', success = S.M.server_process_response_restart S.s msg stale in
        (pack s', success)
      method emit_challenge() =
        let s', chall = S.M.server_emit_challenge S.s in
        (pack s', chall)
      method stash_session() =
        S.M.server_stash_session S.s
      method session_id =
        S.M.server_session_id S.s
      method prop key =
        S.M.server_prop S.s key
      method channel_binding =
        S.M.server_channel_binding S.s
      method user_name =
        S.M.server_user_name S.s
      method authz_name =
        S.M.server_authz_name S.s
      method gssapi_props =
        S.M.server_gssapi_props S.s
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
        module M = M
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
        module M = M
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
  let gssapi_props (s:session) = s#gssapi_props
end
