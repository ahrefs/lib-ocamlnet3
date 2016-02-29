(* $Id$ *)

open Netsys_gssapi
open Netgssapi_support
open Rpc_auth_gssapi_aux
open Printf

type support_level =
    [ `Required | `If_possible | `None ]

type user_name_format =
    [ `Exported_name
    | `Prefixed_name
    | `Plain_name
    ]

type user_name_interpretation =
    [ `Exported_name
    | `Prefixed_name
    | `Plain_name of oid
    ]

module Debug = struct
  let enable = ref false
end

let dlog = Netlog.Debug.mk_dlog "Rpc_auth_gssapi" Debug.enable
let dlogr = Netlog.Debug.mk_dlogr "Rpc_auth_gssapi" Debug.enable

let () =
  Netlog.Debug.register_module "Rpc_auth_gssapi" Debug.enable


module Make(G : Netsys_gssapi.GSSAPI) = struct
  module M = Netgssapi_auth.Manage(G)

  type window =
      { window : Bytes.t;
        mutable window_length : int64;
        mutable window_offset : int;
        mutable window_last : int64;
      }

  type rpc_context =
      { context : G.context;
        mutable ctx_continue : bool;
        ctx_handle : string;
        ctx_conn_id : Rpc_server.connection_id option;
        mutable ctx_svc_none : bool;       
          (* whether unprotected messages are ok *)
        mutable ctx_svc_integrity : bool;
          (* whether integrity-protected msgs are ok *)
        mutable ctx_svc_privacy : bool;
          (* whether privacy-protected msgs are ok *)

        ctx_window : window option;
        mutable ctx_expires : float;
        mutable ctx_props : Netsys_gssapi.server_props option;
      }
        
  let split_rpc_gss_data_t ms =
    let ms_len =  Netxdr_mstring.length_mstrings ms in
    if ms_len < 4 then
      failwith "Rpc_auth_gssapi.split_rpc_gss_data_t";
    let seq_s = Netxdr_mstring.prefix_mstrings ms 4 in
    let rest_s = Netxdr_mstring.shared_sub_mstrings ms 4 (ms_len - 4) in
    let seq = Netnumber.BE.read_string_uint4 seq_s 0 in
    (seq, rest_s)
      

  let omax = Netnumber.mk_uint4 ('\255', '\255', '\255', '\255')

  let integrity_encoder (gss_api : G.gss_api)
                        ctx is_server cred1 rpc_gss_integ_data s =
    dlog "integrity_encoder";
    let data =
      Netxdr_mstring.string_to_mstring 
        (Netnumber.BE.uint4_as_string cred1.seq_num) ::  s in
    let mic =
      gss_api # get_mic
        ~context:ctx
        ~qop_req:0l
        ~message:data
        ~out:(fun ~msg_token ~minor_status ~major_status () ->
	        let (c_err, r_err, flags) = major_status in
	        if c_err <> `None || r_err <> `None then (
                  let msg = 
                    M.format_status ~fn:"get_mic" ~minor_status major_status in
		  if is_server then (
		    (* The RFC demands that no response is sent if a
		       get_mic problem occurs in the server
		     *)
		    Netlog.logf `Err "Rpc_auth_gssapi: %s" msg;
		    raise Rpc_server.Late_drop
		  )
		  else
		    failwith("Rpc_auth_gssapi: \
                              Cannot obtain MIC: " ^ msg)
	        );
	        msg_token
	     )
        () in
    (* The commented out code block performs two superflous string copies.
       We avoid this by doing the XDR-ing manually.
     *)
(*
  let integ =
    { databody_integ = (Netxdr_mstring.concat_mstrings data);
      checksum = mic;
    } in
  let xdr_val = Rpc_auth_gssapi_aux._of_rpc_gss_integ_data integ in
  Netxdr.pack_xdr_value_as_string xdr_val rpc_gss_integ_data []
 *)
    let data_len = Netxdr_mstring.length_mstrings data in
    let data_decolen = Netxdr.get_string_decoration_size data_len omax in
    let data_hdr = Netnumber.BE.uint4_as_string (Netnumber.uint4_of_int data_len) in
    let data_padlen = data_decolen - 4 in
    let data_pad = String.make data_padlen '\000' in
    
    let mic_len = String.length mic in
    let mic_decolen =  Netxdr.get_string_decoration_size mic_len omax in
    let mic_hdr = Netnumber.BE.uint4_as_string (Netnumber.uint4_of_int mic_len) in
    let mic_padlen = mic_decolen - 4 in
    let mic_pad = String.make mic_padlen '\000' in
    
    [ Netxdr_mstring.string_to_mstring data_hdr ] @
      data @
        [ Netxdr_mstring.string_to_mstring (data_pad ^ 
				           mic_hdr ^ mic ^ mic_pad)
        ]
          
    

  let ms_factories = Hashtbl.create 3

  let () =
    Hashtbl.add ms_factories "*" Netxdr_mstring.bytes_based_mstrings


  let integrity_decoder (gss_api : G.gss_api)
                        ctx is_server cred1 rpc_gss_integ_data s pos len =
    dlog "integrity_decoder";
    try
      let xdr_val, xdr_len =
        Netxdr.unpack_xdr_value_l
          ~pos ~len ~fast:true s rpc_gss_integ_data ~prefix:true
          ~mstring_factories:ms_factories
          [] in
      let integ =
        _to_rpc_gss_integ_data xdr_val in
      let data =
        integ.databody_integ in
      (* In the server, any integrity problem should be mapped
         to GARBAGE. We get this by raising xdr_format exceptions here.
       *)
      gss_api # verify_mic
        ~context:ctx
        ~message:[data]
        ~token:integ.checksum
        ~out:(fun ~qop_state ~minor_status ~major_status () ->
                let (c_err, r_err, flags) = major_status in
                if c_err <> `None || r_err <> `None then
                  let msg = 
                    M.format_status
                      ~fn:"verify_mic" ~minor_status major_status in
                  raise(Netxdr.Xdr_format(
                          "Rpc_auth_gssapi: \
                            Cannot verify MIC: " ^ msg))
             )
        ();
      let (seq, args) =
        split_rpc_gss_data_t [data] in
      if seq <> cred1.seq_num then
        raise(Netxdr.Xdr_format "Rpc_auth_gssapi: bad sequence number");
      dlog "integrity_decoder returns normally";
      (Netxdr_mstring.concat_mstrings_bytes args, xdr_len)
        (* This "concat" is hard to avoid. We are still decoding strings,
           not mstrings.
         *)
    with
      | Netxdr.Xdr_format _ as e ->
          raise e
      | e ->
          raise(Netxdr.Xdr_format
                  "Rpc_auth_gssapi: cannot decode integrity-proctected message")


  let privacy_encoder (gss_api : G.gss_api)
                       ctx is_server cred1 rpc_gss_priv_data s =
    dlog "privacy_encoder";
    let data =
      Netxdr_mstring.string_to_mstring 
        (Netnumber.BE.uint4_as_string cred1.seq_num) ::  s in
    gss_api # wrap
      ~context:ctx
      ~conf_req:true
      ~qop_req:0l
      ~input_message:data
      ~output_message_preferred_type:`Bytes
      ~out:(fun ~conf_state ~output_message ~minor_status ~major_status () ->
              try
                let (c_err, r_err, flags) = major_status in
                if c_err <> `None || r_err <> `None then (
                  let msg = 
                    M.format_status
                      ~fn:"wrap" ~minor_status major_status in
                  failwith("Rpc_auth_gssapi: \
                            Cannot wrap message: " ^ msg)
                );
                if not conf_state then
                  failwith
                    "Rpc_auth_gssapi: no privacy-ensuring wrapping possible";
    (* The commented out code block performs two superflous string copies.
       We avoid this by doing the XDR-ing manually.
     *)
                let priv_len = Netxdr_mstring.length_mstrings output_message in
                let priv_decolen = Netxdr.get_string_decoration_size priv_len omax in
                let priv_hdr = 
                  Netnumber.BE.uint4_as_string (Netnumber.uint4_of_int priv_len) in
                let priv_padlen = priv_decolen - 4 in
                let priv_pad = String.make priv_padlen '\000' in
                [ Netxdr_mstring.string_to_mstring priv_hdr ] @
                  output_message @
                  [ Netxdr_mstring.string_to_mstring priv_pad ]
  (*
                let priv =
                  { databody_priv = output_message } in
                let xdr_val = Rpc_auth_gssapi_aux._of_rpc_gss_priv_data priv in
                Netxdr.pack_xdr_value_as_mstring xdr_val rpc_gss_priv_data []
   *)
              with
                | (Failure s | Netxdr.Xdr_failure s) when is_server ->
                    (* The RFC demands that no response is sent if a
                       wrap problem occurs in the server
                     *)
                    Netlog.log `Err s;
                    raise Rpc_server.Late_drop
           )
      ()

  let privacy_decoder (gss_api : G.gss_api)
                       ctx is_server cred1 rpc_gss_priv_data s pos len =
    dlog "privacy_decoder";
    try
      let xdr_val, xdr_len =
        Netxdr.unpack_xdr_value_l
          ~pos ~len ~fast:true ~prefix:true s rpc_gss_priv_data 
          ~mstring_factories:ms_factories
          [] in
      let priv =
        _to_rpc_gss_priv_data xdr_val in
      let data =
        priv.databody_priv in
      (* In the server, any integrity problem should be mapped
         to GARBAGE. We get this by raising Xdr_format exceptions here.
       *)
      gss_api # unwrap
        ~context:ctx
        ~input_message:[data]
        ~output_message_preferred_type:`Bytes
        ~out:(fun ~output_message ~conf_state ~qop_state ~minor_status 
                ~major_status
                () ->
                  let (c_err, r_err, flags) = major_status in
                  if c_err <> `None || r_err <> `None then (
                    let msg = 
                      M.format_status
                        ~fn:"unwrap" ~minor_status major_status in
                    raise(Netxdr.Xdr_format
                            ("Rpc_auth_gssapi: \
                              Cannot unwrap message: " ^ msg))
                  );
                  if not conf_state then
                    raise
                      (Netxdr.Xdr_format
                         "Rpc_auth_gssapi: no privacy-ensuring unwrapping \
                          possible");
                  let (seq, args) =
                    split_rpc_gss_data_t output_message in
                  if seq <> cred1.seq_num then
                    raise(Netxdr.Xdr_format "Rpc_auth_gssapi: bad sequence number");
                  dlog "privacy_decoder returns normally";
                  (Netxdr_mstring.concat_mstrings_bytes args, xdr_len)
             )
        ()
    with
      | Netxdr.Xdr_format _ as e ->
          raise e
      | e ->
          raise(Netxdr.Xdr_format
                  "Rpc_auth_gssapi: cannot decode privacy-proctected message")


  let init_window n =
    let n' = ((n-1) / 8) + 1 in
    { window = Bytes.make n' '\000';
      window_length = 0L;
      window_offset = 0;
      window_last = 0L;
    }


  let check_seq_num w seq_num =
    (* The interpretation is as follows:
       - The window starts at window_last - window_length + 1
       - The window ends at window_last
       - The string window is seen as a bit string
       - The first bit of the window is mapped to the bit window_offset
         in window

       returns true if the seq num is ok
     *)
    let l = Bytes.length w.window * 8 in
    let lL = Int64.of_int l in
    let seq_numL = Netnumber.int64_of_uint4 seq_num in
    if w.window_length = 0L then (
      (* initialization. Assume ctx.ctx_window is filled with zeros *)
      if seq_numL >= lL then
        w.window_length <- lL
      else
        w.window_length <- Int64.succ seq_numL;
      w.window_offset <- 0;
      w.window_last <- seq_numL;
      let n2 = Int64.to_int w.window_length - 1 in
      let k = n2 lsr 3 in
      let j = n2 land 7 in
      let c = Char.code (Bytes.get w.window k) in
      let c' =  c lor (1 lsl j) in
      Bytes.set w.window k (Char.chr c');
      true
    )
    else
      if seq_numL > w.window_last then (
        (* all ok, just advance the window *)
        while seq_numL > w.window_last do
          let next = Int64.succ w.window_last in
          if w.window_length < lL then
            w.window_length <- Int64.succ w.window_length
          else
            w.window_offset <- (succ w.window_offset) mod l;
          let n2 = 
            (w.window_offset + Int64.to_int w.window_length - 1) mod l in
          let k = n2 lsr 3 in
          let j = n2 land 7 in
          let c = Char.code (Bytes.get w.window k) in
          let c' = 
            if seq_numL = next then
              c lor (1 lsl j) 
          else
            c land (lnot (1 lsl j)) in
          Bytes.set w.window k (Char.chr c');
          w.window_last <- next
        done;
        true
      ) else
        let before_start =
          Int64.sub w.window_last w.window_length in
        seq_numL > before_start && (
          let n1 = Int64.to_int (Int64.pred (Int64.sub seq_numL before_start)) in
          let n2 = (w.window_offset + n1) mod l in
          let k = n2 lsr 3 in
          let j = n2 land 7 in
          let c = Char.code (Bytes.get w.window k) in
          let ok = (c land (1 lsl j)) = 0 in
          if ok then (
            let c' = c lor (1 lsl j) in
            Bytes.set w.window k (Char.chr c');
          );
          ok
        )


  let server_auth_method 
        ?(shared_context=false)
        ?(user_name_format = `Prefixed_name)
        ?seq_number_window
        ?(max_age = 1E99)
        (gss_api : G.gss_api)
        (sconf : Netsys_gssapi.server_config) : Rpc_server.auth_method =

    let module C = struct
      let raise_error msg =
        failwith ("Rpc_auth_gssapi: " ^ msg)
    end in
    let module A = Netgssapi_auth.Auth(G)(C) in

    let acceptor_name = A.get_acceptor_name sconf in
    let acceptor_cred = A.get_acceptor_cred ~acceptor_name sconf in
    let require_privacy = sconf # privacy = `Required in
    let require_integrity = sconf # integrity = `Required in

    let rpc_gss_cred_t =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_cred_t in

    let rpc_gss_init_arg =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_init_arg in

    let rpc_gss_init_res =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_init_res in

    let rpc_gss_integ_data =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_integ_data in

    let rpc_gss_priv_data =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_priv_data in


    let ctx_by_handle = Hashtbl.create 42 in

    let handle_nr = ref 0 in
    let last_gc = ref 0.0 in

    let new_handle() =
      let n = !handle_nr in
      incr handle_nr;
      let random = Bytes.make 16 '\000' in
      Netsys_rng.fill_random random;
      sprintf "%6d_%s" n (Digest.to_hex (Bytes.to_string random)) in

    ( object(self)
        method name = "RPCSEC_GSS"

        method flavors = [ "RPCSEC_GSS" ]

        method peek = `None

        method authenticate srv conn_id (details:Rpc_server.auth_details) auth =
          dlog "authenticate";
          self # collect();
          (* First decode the rpc_gss_cred_t structure in the header: *)
          try
            let (_, cred_data) = details # credential in
            let cred_data = Bytes.of_string cred_data in
            let xdr_val =
              try
                Netxdr.unpack_xdr_value
                  ~fast:true
                  cred_data
                  rpc_gss_cred_t
                  [] 
              with _ ->
                (* Bad credential *)
                raise(Rpc.Rpc_server Rpc.Auth_bad_cred) in
            let cred =
              _to_rpc_gss_cred_t xdr_val in
            match cred with
              | `_1 cred1 ->
                  let r =
                    match cred1.gss_proc with
                      | `rpcsec_gss_init ->
                          self # auth_init srv conn_id details cred1
                      | `rpcsec_gss_continue_init ->
                          self # auth_cont_init srv conn_id details cred1
                      | `rpcsec_gss_destroy ->
                          self # auth_destroy srv conn_id details cred1
                      | `rpcsec_gss_data ->
                          self # auth_data srv conn_id details cred1
                  in
                  let () = auth r in
                  dlog "authenticate returns normally";
                  ()
          with
            | Rpc.Rpc_server code ->
                auth(Rpc_server.Auth_negative code)
            | error ->
                Netlog.logf `Err
                  "Failed RPC authentication (GSS-API): %s"
                  (Netexn.to_string error);
                auth(Rpc_server.Auth_negative Rpc.Auth_failed)


        method invalidate() =
          Hashtbl.iter
            (fun handle ctx ->
               M.delete_context (Some ctx.context) ()
            )
            ctx_by_handle;
          Hashtbl.clear ctx_by_handle


        method invalidate_connection conn_id =
          self # collect ~conn_id ()


        method private collect ?conn_id () =
          let t = Unix.time() in
          if t > !last_gc +. 60.0 || conn_id<>None then ( (* FIXME: arbitrary *)
            let l = ref [] in
            Hashtbl.iter
              (fun handle ctx ->
                 let del =
                   t > ctx.ctx_expires ||
                     match conn_id with
                       | None -> false
                       | Some cid -> ctx.ctx_conn_id = Some cid in
                 if del then (
                   M.delete_context (Some ctx.context) ();
                   l := handle :: !l
                 )
              )
              ctx_by_handle;
            List.iter
              (fun handle ->
                 Hashtbl.remove ctx_by_handle handle
              )
              !l;
            last_gc := t
          )

        method private get_token details =
          let body_data =
            Rpc_packer.unpack_call_body_raw_bytes
              details#message details#frame_len in
          let xdr_val =
            Netxdr.unpack_xdr_value
              ~fast:true
              body_data
              rpc_gss_init_arg
              [] in
          let token_struct =
            _to_rpc_gss_init_arg xdr_val in
          token_struct.gss_token


        method private fixup_svc_flags ctx ret_flags =
          let have_privacy = List.mem `Conf_flag ret_flags in
          let have_integrity = List.mem `Integ_flag ret_flags in

          if require_privacy && not have_privacy then
            failwith
              "Rpc_auth_gssapi: Privacy requested but unavailable";
          if require_integrity && not have_integrity then
            failwith
              "Rpc_auth_gssapi: Integrity requested but unavailable";

          ctx.ctx_svc_none      <- not require_privacy && not require_integrity;
          ctx.ctx_svc_integrity <- not require_privacy && have_integrity;
          ctx.ctx_svc_privacy   <- have_privacy;


        method private fixup_expiration ctx =
          match ctx.ctx_props with
            | None -> ()
            | Some p ->
                let t =
                  match p # time with
                    | `This t -> min t max_age
                    | `Indefinite -> max_age in
                ctx.ctx_expires <- Unix.time() +. t


        method private verify_context ctx conn_id =
          ( match ctx.ctx_conn_id with
              | None -> ()
              | Some id ->
                  if id <> conn_id then
                    failwith "Rpc_auth_gssapi: this context is unavailable \
                              to this connection"
          );
          let t = Unix.time() in
          if t -. 10.0 > ctx.ctx_expires then
            raise(Rpc.Rpc_server Rpc.RPCSEC_GSS_ctxproblem)

        method private get_user ctx =
          let name =
            gss_api # inquire_context
              ~context:ctx.context
              ~out:(fun ~src_name ~targ_name ~lifetime_req ~mech_type
                      ~ctx_flags ~locally_initiated ~is_open 
                      ~minor_status ~major_status
                      ()
                      ->
                        A.check_status
                          ~fn:"inquire_context" ~minor_status major_status;
                        if not is_open then
                          failwith("Rpc_auth_gssapi: get_user: context is not \
                                 fully established");
                        src_name
                          (* this is guaranteed to be a mechanism name (MN),
                             so it is already canonicalized
                           *)
                 )
            () in
          if user_name_format = `Exported_name then
            A.get_exported_name name
          else (
            let (output_name,output_name_type) = A.get_display_name name in
            match user_name_format with
              | `Exported_name -> assert false
              | `Prefixed_name ->
                  let oid_s =
                    Netoid.to_string_curly output_name_type in
                  oid_s ^ output_name
              | `Plain_name ->
                  output_name
          )

        method private auth_init srv conn_id details cred1 =
          dlog "auth_init";
          let (verf_flav, verf_data) = details # verifier in
          if details#procedure <> Netnumber.uint4_of_int 0 then
            failwith "For context initialization the RPC procedure must be 0";
          if cred1.handle <> "" then
            failwith "Context handle is not empty";
          if verf_flav <> "AUTH_NONE" then
            failwith "Bad verifier (1)";
          if verf_data <> "" then
            failwith "Bad verifier (2)";
          let (context, output_token, ret_flags, props_opt) =
            A.accept_sec_context
              ~context:None
              ~acceptor_cred
              ~input_token:(self # get_token details)
              ~chan_bindings:None
              sconf in
          let h = new_handle() in
          let cont = (props_opt = None) in
          let ctx =
            { context = context;
              ctx_continue = cont;
              ctx_handle = h;
              ctx_conn_id = 
                if shared_context then None else Some conn_id;
              ctx_svc_none = false;
              ctx_svc_integrity = false;
              ctx_svc_privacy = false;
              ctx_window = ( match seq_number_window with
                               | None -> None
                               | Some n -> Some(init_window n)
                           );
              ctx_expires = 1E99;
              ctx_props = props_opt;
            } in
          if not cont then (
            self#fixup_svc_flags ctx ret_flags;
            self#fixup_expiration ctx;
          );
          Hashtbl.replace ctx_by_handle h ctx;
          let reply =
            { res_handle = h;
              res_major =
                if ctx.ctx_continue 
                then gss_s_continue_needed
                else gss_s_complete;
              res_minor = zero;
              res_seq_window = ( match seq_number_window with
                                   | None ->
                                       maxseq
                                   | Some n -> 
                                       Netnumber.uint4_of_int n
                               );
              res_token = output_token
            } in
          self # auth_init_result ctx reply


        method private auth_cont_init srv conn_id details cred1 =
          dlog "auth_cont_init";
          let (verf_flav, verf_data) = details # verifier in
          if details#procedure <> Netnumber.uint4_of_int 0 then
            failwith "For context initialization the RPC procedure must be 0";
          if verf_flav <> "AUTH_NONE" then
            failwith "Bad verifier (1)";
          if verf_data <> "" then
            failwith "Bad verifier (2)";
          let h = cred1.handle in
          let ctx =
            try Hashtbl.find ctx_by_handle h
            with Not_found ->
              failwith "Rpc_auth_gssapi: unknown context handle" in
          if not ctx.ctx_continue then
            failwith "Rpc_auth_gssapi: cannot continue context establishment";
          self # verify_context ctx conn_id;
          let (context, output_token, ret_flags, props_opt) =
            A.accept_sec_context
              ~context:(Some ctx.context)
              ~acceptor_cred
              ~input_token:(self # get_token details)
              ~chan_bindings:None
              sconf in
          ctx.ctx_continue <- (props_opt = None);
          ctx.ctx_props <- props_opt;
          if not ctx.ctx_continue then (
            self#fixup_svc_flags ctx ret_flags;
            self#fixup_expiration ctx;
          );
          let reply =
            { res_handle = h;
              res_major =
                if ctx.ctx_continue 
                then gss_s_continue_needed
                else gss_s_complete;
              res_minor = zero;
              res_seq_window = ( match seq_number_window with
                                   | None ->
                                       maxseq
                                   | Some n -> 
                                       Netnumber.uint4_of_int n
                               );
              res_token = output_token
            } in
          self # auth_init_result ctx reply

        method private auth_init_result ctx reply =
          dlog "auth_init_result";
          let xdr_val =
            Rpc_auth_gssapi_aux._of_rpc_gss_init_res reply in
          let m =
            Netxdr.pack_xdr_value_as_mstrings
              xdr_val rpc_gss_init_res [] in
          let (verf_flav, verf_data) =
            if ctx.ctx_continue  then
              ("AUTH_NONE", "")
            else
              let window_s =
                Netnumber.BE.uint4_as_string reply.res_seq_window in
              let mic =
                gss_api # get_mic
                  ~context:ctx.context
                  ~qop_req:0l
                  ~message:[Netxdr_mstring.string_to_mstring window_s]
                  ~out:(fun ~msg_token ~minor_status ~major_status () ->
                          A.check_status ~fn:"get_mic"
                                         ~minor_status major_status;
                          msg_token
                       )
                  () in
              ("RPCSEC_GSS", mic) in
          Rpc_server.Auth_reply(m, verf_flav, verf_data)

        method private auth_data srv conn_id details cred1 =
          dlog "auth_data";
          (* Get context: *)
          let h = cred1.handle in
          let ctx =
            try Hashtbl.find ctx_by_handle h
            with Not_found ->
              raise(Rpc.Rpc_server Rpc.RPCSEC_GSS_ctxproblem) in
          self # verify_context ctx conn_id;

          (* Verify the header first *)
          let (verf_flav, verf_data) = details # verifier in
          if verf_flav <> "RPCSEC_GSS" then
            failwith "Rpc_auth_gssapi: Bad type of verifier";
          let pv = details # message in
          let n = Rpc_packer.extract_call_gssapi_header pv in
          let s = Rpc_packer.prefix_of_packed_value pv n in

          gss_api # verify_mic
            ~context:ctx.context
            ~message:[Netxdr_mstring.string_to_mstring s]
            ~token:verf_data
            ~out:(fun ~qop_state ~minor_status ~major_status () ->
                    let (c_err, r_err, flags) = major_status in
                    if c_err <> `None || r_err <> `None then
                      raise(Rpc.Rpc_server Rpc.RPCSEC_GSS_credproblem)
                        (* demanded by the RFC *)
                 )
            ();

          (* FIXME: we should also check here whether the credentials'
             lifetime is over, and if so, report RPCSEC_GSS_ctxproblem.
             We cannot delay this until encoding/decoding because the
             exception handling would not work by then. So it must
             happen now. I have no idea how to do so, though.

             CHECK: there is now a check on ctx_expires in verify_context.
             Good enough?
           *)

          (* Check sequence number *)
          if Netnumber.gt_uint4 cred1.seq_num maxseq then
            raise(Rpc.Rpc_server Rpc.RPCSEC_GSS_ctxproblem);

          let drop =
            match ctx.ctx_window with
              | None -> false
              | Some w ->
                  not (check_seq_num w cred1.seq_num) in

          if drop then
            Rpc_server.Auth_drop
          else
            match cred1.service with
              | `rpc_gss_svc_none ->
                  if not ctx.ctx_svc_none then
                    failwith "Rpc_auth_gssapi: unexpected unprotected message";
                  self#auth_data_result ctx cred1.seq_num None None;

              | `rpc_gss_svc_integrity ->
                  if not ctx.ctx_svc_integrity then
                    failwith "Rpc_auth_gssapi: unexpected integrity-proctected \
                            message";
                  let encoder =
                    integrity_encoder 
                      gss_api ctx.context true cred1 rpc_gss_integ_data in
                  let decoder =
                    integrity_decoder 
                      gss_api ctx.context true cred1 rpc_gss_integ_data in
                  self#auth_data_result
                    ctx cred1.seq_num (Some encoder) (Some decoder)

              | `rpc_gss_svc_privacy ->
                  if not ctx.ctx_svc_privacy then
                    failwith "Rpc_auth_gssapi: unexpected privacy-proctected \
                            message";
                  let encoder =
                    privacy_encoder
                      gss_api ctx.context true cred1 rpc_gss_priv_data in
                  let decoder =
                    privacy_decoder gss_api ctx.context true
                      cred1 rpc_gss_priv_data in
                  self # auth_data_result
                    ctx cred1.seq_num (Some encoder) (Some decoder)


        method private auth_data_result ctx seq enc_opt dec_opt =
          dlog "auth_data_result";
          let seq_s =
            Netnumber.BE.uint4_as_string seq in
          let mic =
            gss_api # get_mic
              ~context:ctx.context
              ~qop_req:0l
              ~message:[Netxdr_mstring.string_to_mstring seq_s]
              ~out:(fun ~msg_token ~minor_status ~major_status () ->
                      let (c_err, r_err, flags) = major_status in
                      if c_err <> `None || r_err <> `None then
                        raise(Rpc.Rpc_server Rpc.RPCSEC_GSS_ctxproblem);
                      msg_token
                   )
              () in
          Rpc_server.Auth_positive(
            self#get_user ctx,
            "RPCSEC_GSS", mic, enc_opt, dec_opt, ctx.ctx_props
          )

        method private auth_destroy srv conn_id details cred1 =
          dlog "auth_destroy";
          if details#procedure <> Netnumber.uint4_of_int 0 then
            failwith "For context destruction the RPC procedure must be 0";
          let r =
            self # auth_data srv conn_id details cred1 in
          match r with
            | Rpc_server.Auth_positive(_, flav, mic, enc_opt, dec_opt, _) ->
                (* Check that the input args are empty: *)
                let raw_body =
                  Rpc_packer.unpack_call_body_raw_bytes
                    details#message details#frame_len in
                let body_length =
                  match dec_opt with
                    | None -> Bytes.length raw_body
                    | Some dec -> 
                        let (b,n) = dec raw_body 0 (Bytes.length raw_body) in
                        n in
                if body_length <> 0 then
                  failwith "Rpc_auth_gssapi: invalid destroy request";

                (* Now destroy: *)
                let h = cred1.handle in
                ( try 
                    let ctx = Hashtbl.find ctx_by_handle h in
                    M.delete_context (Some ctx.context) ();
                    Hashtbl.remove ctx_by_handle h;
                  with Not_found -> ()
                );

                (* Create response: *)
                let encoded_emptiness =
                  match enc_opt with
                    | None -> []
                    | Some enc -> enc [] in

                (* Respond: *)
                Rpc_server.Auth_reply(encoded_emptiness, flav, mic)
            | _ ->
                r
      end
    )


  let client_auth_method 
        ?(user_name_interpretation = `Prefixed_name)
        (gss_api : G.gss_api) (cconf : Netsys_gssapi.client_config)
          : Rpc_client.auth_method =

    let privacy = cconf#privacy in
    let integrity = cconf#integrity in

    let rpc_gss_cred_t =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_cred_t in

    let rpc_gss_integ_data =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_integ_data in

    let rpc_gss_priv_data =
      Netxdr.validate_xdr_type
        Rpc_auth_gssapi_aux.xdrt_rpc_gss_priv_data in

    let session (m:Rpc_client.auth_method)
                (p:Rpc_client.auth_protocol)
                ctx service handle cur_seq_num
          : Rpc_client.auth_session =
      let module C = struct
        let raise_error msg =
          failwith ("Rpc_auth_gssapi: " ^ msg)
      end in
      let module A = Netgssapi_auth.Auth(G)(C) in
      let seq_num_of_xid = Hashtbl.create 15 in
      ( object(self)
          method next_credentials client prog proc xid =
            (* N.B. Exceptions raised here probably abort the client,
               and fall through to the event loop
             *)

            dlogr
              (fun () ->
                 sprintf "next_credentials proc=%s xid=%Ld"
                   proc (Netnumber.int64_of_uint4 xid)
              );

            let cred1 =
              { gss_proc = `rpcsec_gss_data;
                seq_num = !cur_seq_num;
                service = service;
                handle = handle
              } in
            let cred1_xdr = _of_rpc_gss_cred_t (`_1 cred1) in
            let cred1_s =
              Netxdr.pack_xdr_value_as_string
                cred1_xdr rpc_gss_cred_t [] in

            let h_pv =
              Rpc_packer.pack_call_gssapi_header
                prog xid proc "RPCSEC_GSS" cred1_s in
            let h =
              Rpc_packer.string_of_packed_value h_pv in
            let mic =
              gss_api # get_mic
                ~context:ctx
                ~qop_req:0l
                ~message:[Netxdr_mstring.string_to_mstring h]
                ~out:(fun ~msg_token ~minor_status ~major_status () ->
                        A.check_status ~fn:"get_mic" ~minor_status major_status;
                        msg_token
                     )
                () in

            (* Save seq_num: *)
            Hashtbl.replace seq_num_of_xid xid !cur_seq_num;

            (* Increment cur_seq_num: *)
            cur_seq_num := 
              Netnumber.uint4_of_int64(
                Int64.logand
                  (Int64.succ (Netnumber.int64_of_uint4 !cur_seq_num))
                  0xFFFF_FFFFL
              );

            let enc_opt, dec_opt =
              match service with
                | `rpc_gss_svc_none ->
                    None, None

                | `rpc_gss_svc_integrity ->
                    let encoder =
                      integrity_encoder 
                        gss_api ctx false cred1 rpc_gss_integ_data in
                    let decoder =
                      integrity_decoder 
                        gss_api ctx false cred1 rpc_gss_integ_data in
                    (Some encoder), (Some decoder)

                | `rpc_gss_svc_privacy ->
                    let encoder =
                      privacy_encoder gss_api ctx false cred1 rpc_gss_priv_data in
                    let decoder =
                      privacy_decoder gss_api ctx false cred1 rpc_gss_priv_data in
                    (Some encoder), (Some decoder) in

            dlogr
              (fun () ->
                 sprintf "next_credentials returns normally"
              );

            ("RPCSEC_GSS", cred1_s,
             "RPCSEC_GSS", mic,
             enc_opt, dec_opt
            )

          method server_rejects client xid code =
            dlogr
              (fun () ->
                 sprintf "server_rejects xid=%Ld"
                   (Netnumber.int64_of_uint4 xid)
              );
            Hashtbl.remove seq_num_of_xid xid;
            match code with
              | Rpc.RPCSEC_GSS_credproblem | Rpc.RPCSEC_GSS_ctxproblem ->
                  `Renew
              | Rpc.Auth_too_weak ->
                  `Next
              | _ ->
                  `Fail

          method server_accepts client xid verf_flav verf_data =
            dlogr
              (fun () ->
                 sprintf "server_accepts xid=%Ld"
                   (Netnumber.int64_of_uint4 xid)
              );
            if verf_flav <> "RPCSEC_GSS" then
              raise(Rpc.Rpc_server Rpc.Auth_invalid_resp);
            let seq =
              try Hashtbl.find seq_num_of_xid xid
              with Not_found -> 
                raise(Rpc.Rpc_server Rpc.Auth_invalid_resp) in
            let seq_s =
              Netnumber.BE.uint4_as_string seq in
            Hashtbl.remove seq_num_of_xid xid;
            gss_api # verify_mic
              ~context:ctx
              ~message:[Netxdr_mstring.string_to_mstring seq_s]
              ~token:verf_data
              ~out:(fun ~qop_state ~minor_status ~major_status () ->
                      A.check_status 
                        ~fn:"verify_mic" ~minor_status major_status;
                   )
              ();
            dlog "server_accepts returns normally"

          method auth_protocol = p

        end
      ) in

    let protocol (m:Rpc_client.auth_method) client cred target
         : Rpc_client.auth_protocol =
      let first = ref true in
      let state = ref `Emit in
      let ctx = ref None in
      let input_token = ref "" in
      let output_token = ref "" in
      let handle = ref "" in
      let init_prog = ref None in
      let init_service = ref None in
      let init_props = ref None in

      let delete_context() =
        M.delete_context !ctx ();
        ctx := None in
      let module C = struct
        let raise_error msg =
          delete_context();
          failwith ("Rpc_auth_gssapi: " ^ msg)
      end in
      let module A = Netgssapi_auth.Auth(G)(C) in
          

      let get_context() =
        match !ctx with Some c -> c | None -> assert false in
      let get_service() =
        match !init_service with Some s -> s | None -> assert false in
      let get_prog() =
        match !init_prog with Some p -> p | None -> assert false in
(*
      let get_props() =
        match !init_props with Some p -> p | None -> assert false in
 *)

      (* CHECK: what happens with exceptions thrown here? *)

      let init_sec_context_step() =
        (* let prog = get_prog() in *)
        let req_flags = A.get_client_flags cconf in
        let (output_ctx, output_tok, ret_flags, props_opt) =
          A.init_sec_context
            ~initiator_cred:cred
            ~context:!ctx
            ~target_name:target
            ~req_flags
            ~chan_bindings:None
            ~input_token:(if !first then None else Some !input_token)
            cconf in
        let have_priv = List.mem `Conf_flag ret_flags in
        let have_integ = List.mem `Integ_flag ret_flags in
        let service_i =
          match integrity with
            | `Required ->
                if not have_integ && not have_priv then
                  failwith "Rpc_auth_gssapi: Integrity is not available";
                `rpc_gss_svc_integrity
            | `If_possible ->
                if have_integ then
                  `rpc_gss_svc_integrity
                else
                  `rpc_gss_svc_none
            | `None ->
                `rpc_gss_svc_none in
        let service =
          match privacy with
            | `Required ->
                if not have_priv then
                  failwith "Rpc_auth_gssapi: Privacy is not available";
                `rpc_gss_svc_privacy
            | `If_possible ->
                if have_priv then
                  `rpc_gss_svc_privacy
                else
                  service_i
            | `None ->
                service_i in
        ctx := Some output_ctx;
        init_service := Some service;
        output_token := output_tok;
        init_props := props_opt
      in

      ( object(self)
          method state = !state

          method emit xid prog_nr vers_nr =
            assert(!state = `Emit);
            dlogr
              (fun () ->
                 sprintf "emit prog_nr=%Ld vers_nr=%Ld xid=%Ld"
                   (Netnumber.int64_of_uint4 prog_nr)
                   (Netnumber.int64_of_uint4 vers_nr)
                   (Netnumber.int64_of_uint4 xid)
              );
            if !init_prog = None then (
              let p =
                Rpc_program.create
                  prog_nr
                  vers_nr
                  (Netxdr.validate_xdr_type_system [])
                  [ "init", 
                    (  (Netnumber.uint4_of_int 0), 
                       Rpc_auth_gssapi_aux.xdrt_rpc_gss_init_arg,
                       Rpc_auth_gssapi_aux.xdrt_rpc_gss_init_res
                    );
                  ] in
              init_prog := Some p;
            );
            let prog = get_prog() in

            try
              if !first then
                init_sec_context_step();
              assert(!output_token <> "");
              let cred1 =
                `_1 { gss_proc = ( if !first then `rpcsec_gss_init
                                   else `rpcsec_gss_continue_init );
                      seq_num = Netnumber.uint4_of_int 0;  (* FIXME *)
                      service = get_service();
                      handle = !handle
                    } in
              let cred1_xdr = _of_rpc_gss_cred_t cred1 in
              let cred1_s =
                Netxdr.pack_xdr_value_as_string
                  cred1_xdr rpc_gss_cred_t [] in
              let pv =
                Rpc_packer.pack_call
                  prog xid "init"
                  "RPCSEC_GSS" cred1_s
                  "AUTH_NONE" ""
                  (Netxdr.XV_struct_fast [| Netxdr.XV_opaque !output_token |] ) in
              first := false;
              state := `Receive xid;
              dlog "emit returns normally";
              pv
            with error ->
              Netlog.logf `Err
                "Rpc_auth_gssapi: Error during message preparation: %s"
                (Netexn.to_string error);
              state := `Error;
              delete_context();
              raise error


          method receive pv =
            try
              dlog "receive";
              let prog = get_prog() in
              let (xid, flav_name, flav_data, result_xdr) =
                Rpc_packer.unpack_reply prog "init" pv in
              assert( !state = `Receive xid );

              dlogr
                (fun () ->
                   sprintf "receive xid=%Ld"
                     (Netnumber.int64_of_uint4 xid)
                );

              let res = _to_rpc_gss_init_res result_xdr in
              let cont_needed =
                res.res_major = gss_s_continue_needed in

              if not cont_needed && res.res_major <> gss_s_complete then
                failwith
                  (sprintf "Rpc_auth_gssapi: Got GSS-API error code %Ld"
                     (Netnumber.int64_of_uint4 res.res_major));

              input_token := res.res_token;
              if !init_props = None then (
                init_sec_context_step();
                if cont_needed <> (!output_token <> "") then
                  failwith "Rpc_auth_gssapi: server expects token but the \
                            mechanism does not provide one"
              ) else
                if !input_token <> "" then
                  failwith "Rpc_auth_gssapi: unexpected input token";

              if cont_needed then (
                if flav_name <> "AUTH_NONE" || flav_data <> "" then
                  failwith "Rpc_auth_gssapi: bad verifier";
              )
              else (
                if flav_name <> "RPCSEC_GSS" then
                  failwith "Rpc_auth_gssapi: bad verifier";
                if !init_props = None then
                  failwith "Rpc_auth_gssapi: protocol finished but no complete \
                            context";
                let window_s =
                  Netnumber.BE.uint4_as_string res.res_seq_window in
                gss_api # verify_mic
                  ~context:(get_context())
                  ~message:[Netxdr_mstring.string_to_mstring window_s]
                  ~token:flav_data
                  ~out:(fun ~qop_state ~minor_status ~major_status () ->
                          A.check_status ~fn:"verify_mic" 
                                         ~minor_status major_status;
                       )
                  ()
              );

              handle := res.res_handle;	  

              if cont_needed then
                state := `Emit
              else
                let c = get_context () in
                let service = get_service() in
                let cs = ref (Netnumber.uint4_of_int 0) in
                let s = 
                  session 
                    m (self :> Rpc_client.auth_protocol) c service
                    !handle cs in
                state := `Done s;
                dlog "receive returns normally";
            with error ->
              Netlog.logf `Err
                "Rpc_auth_gssapi: Error during message verification: %s"
                (Netexn.to_string error);
              state := `Error;
              delete_context();
              raise error

          method gssapi_props = !init_props
          method destroy() = delete_context()

          method auth_method = m

        end
      ) in

    ( object(self)
        method name = "RPCSEC_GSS"

        method new_session client user_opt =
          let module C = struct
            let raise_error msg =
              failwith ("Rpc_auth_gssapi: " ^ msg)
          end in
          let module A = Netgssapi_auth.Auth(G)(C) in
          dlogr
            (fun () ->
               sprintf "new_session user=%s"
                 (match user_opt with
                    | None -> "-" | Some u -> u
                 )
            );

          let target = A.get_target_name cconf in

          let cred =
            match user_opt with
              | None ->
                  let n = A.get_initiator_name cconf in
                  A.get_initiator_cred ~initiator_name:n cconf
              | Some user ->
                  let (input_name, input_name_type) =
                    match user_name_interpretation with
                      | `Exported_name ->
                          (user, nt_export_name)
                      | `Prefixed_name ->
                          let l = String.length user in
                          ( try
                              let k = String.index user '}' in
                              let oid = 
                                Netoid.of_string_curly (String.sub user 0 (k+1)) in
                              let n = String.sub user (k+1) (l-k-1) in
                              (n, oid)
                            with _ ->
                              failwith
                                ("Rpc_auth_gssapi: cannot parse user name")
                          )
                      | `Plain_name input_name_type ->
                          (user, input_name_type) in
                  let name =
                    gss_api # import_name
                      ~input_name
                      ~input_name_type
                      ~out:(fun ~output_name ~minor_status ~major_status
                              () ->
                                A.check_status ~fn:"import_name"
                                               ~minor_status major_status;
                                output_name
                           )
                      () in
                  A.acquire_initiator_cred ~initiator_name:name cconf in
          protocol (self :> Rpc_client.auth_method) client cred target
                   
      end
    )
end


let client_auth_method
      ?user_name_interpretation
      (g : (module Netsys_gssapi.GSSAPI)) cconf =
  let module G = (val g : Netsys_gssapi.GSSAPI) in
  let module A = Make(G) in
  A.client_auth_method
    ?user_name_interpretation G.interface cconf


let server_auth_method
      ?shared_context
      ?user_name_format ?seq_number_window ?max_age
      (g : (module Netsys_gssapi.GSSAPI)) sconf =
  let module G = (val g : Netsys_gssapi.GSSAPI) in
  let module A = Make(G) in
  A.server_auth_method
    ?shared_context
    ?user_name_format ?seq_number_window ?max_age
    G.interface sconf
