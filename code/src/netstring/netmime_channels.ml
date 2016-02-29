(* $Id$ *)

open Netmime
open Netchannels

let read_mime_header ?(unfold=false) ?(strip=true) ?(ro=false) stream =
  let h = Netmime_string.read_header ~downcase:false ~unfold ~strip stream in
  let hobj = new basic_mime_header h in
  if ro then
    wrap_mime_header_ro hobj
  else
    hobj
;;


type multipart_style = [ `None | `Flat | `Deep ] ;;


let decode_mime_body hdr =
  let encoding =
    try Netmime_header.get_content_transfer_encoding hdr
    with Not_found -> "7bit"
  in
  match encoding with
      ("7bit"|"8bit"|"binary") ->
	(fun s -> s)
    | "base64" ->
	(fun s -> 
	   new output_filter 
	     (new Netencoding.Base64.decoding_pipe 
	        ~accept_spaces:true ()) s)
    | "quoted-printable" ->
	(fun s ->
	   new output_filter
	     (new Netencoding.QuotedPrintable.decoding_pipe()) s)
    | _ ->
	failwith "Netmime.decode_mime_body: Unknown Content-transfer-encoding"
;;


let encode_mime_body ?(crlf = true) hdr =
  let encoding =
    try Netmime_header.get_content_transfer_encoding hdr
    with Not_found -> "7bit"
  in
  match encoding with
      ("7bit"|"8bit"|"binary") ->
	(fun s -> s)
    | "base64" ->
	(fun s -> 
	   new output_filter 
	     (new Netencoding.Base64.encoding_pipe 
	       ~linelength:76 ~crlf ()) s)
    | "quoted-printable" ->
	(fun s ->
	   new output_filter
	     (new Netencoding.QuotedPrintable.encoding_pipe ~crlf ()) s)
    | _ ->
	failwith "Netmime.encode_mime_body: Unknown Content-transfer-encoding"
;;


let storage ?fin : store -> (mime_body * out_obj_channel) = function
    `Memory ->
      let body = new memory_mime_body "" in
      let body_ch = body#open_value_wr() in
      body, body_ch
  | `File filename ->
      let body = new file_mime_body ?fin filename in
      let body_ch = body#open_value_wr() in
      body, body_ch
;;


let rec read_mime_message1
      ?unfold ?strip
      ?(multipart_style = (`Deep : multipart_style))
      ?(storage_style = fun _ -> storage `Memory)
      stream : complex_mime_message =
  
  (* First read the header: *)
  let h_obj = read_mime_header ?unfold ?strip ~ro:false stream in

  let mime_type, mime_type_params = 
    try Netmime_header.get_content_type h_obj with Not_found -> "", [] in

  let multipart = "multipart/" in
  let is_multipart_type = 
    (String.length mime_type >= String.length multipart) &&
    (String.sub mime_type 0 (String.length multipart) = multipart) in

  (* Now parse the body, (with multiparts or without) *)
  let body =
    if is_multipart_type && multipart_style <> `None then begin
      (* --- Divide the message into parts: --- *)
      let boundary = 
	try List.assoc "boundary" mime_type_params 
	with Not_found -> failwith "Netmime.read_mime_message: missing boundary parameter"
      in
      let multipart_style =  (* of the sub parser *)
	if multipart_style = `Flat then `None else multipart_style in
      `Parts
	(Netmime_string.read_multipart_body
	   (read_mime_message1 ~multipart_style ~storage_style)
	   (Netmime_string.param_value boundary)
	   stream
	)
    end
    else begin
      (* --- Read the body and optionally decode it: --- *)
      (* Where to store the body: *)
      let decoder = decode_mime_body h_obj in
      let body, body_ch = storage_style h_obj in
      if 
	with_out_obj_channel 
	  (decoder body_ch)
	  (fun body_ch' ->
	     body_ch' # output_channel (stream :> in_obj_channel);
	     body_ch' <> body_ch
	  )
      then
	body_ch # close_out();
      `Body body
    end
  in

  (h_obj, body)
;;


let read_mime_message
      ?unfold ?strip ?(ro=false) ?multipart_style ?storage_style
      stream =
  let msg = 
    read_mime_message1 ?unfold ?strip ?multipart_style ?storage_style stream in
  if ro then
    wrap_complex_mime_message_ro (msg :> complex_mime_message_ro)
  else
    msg


let rec augment_message (hdr,cbody) =
  (* Computes the content-transfer-encoding field for multipart messages.
   * The resulting message uses `Parts_ag(cte,parts) instead of `Parts(parts)
   * where cte is the content-transfer-encoding field.
   *)
  match cbody with
      `Body _ as b -> (hdr,b)
    | `Parts p ->
	let p' = List.map augment_message p in
	let mp_cte_id =
	  List.fold_left
	    (fun x (hdr,body) ->
	       let cte = 
		 match body with
		     `Body _ -> 
		       (try Netmime_header.get_content_transfer_encoding hdr
			with Not_found -> "7bit")
		   | `Parts_ag(cte,_) -> cte
	       in
	       let cte_id =
		 match cte with
		     "7bit" | "quoted-printable" | "base64" -> 0
		   | "8bit" -> 1
		   | _ -> 2
	       in
	       max x cte_id
	    )
	    0
	    p' in
	let mp_cte = match mp_cte_id with
	    0 -> "7bit"
	  | 1 -> "8bit"
	  | 2 -> "binary"
	  | _ -> assert false
	in
	(hdr, `Parts_ag(mp_cte,p'))
;;


let rec write_mime_message_int ?(wr_header = true) ?(wr_body = true) ?(nr = 0) 
                               ?ret_boundary ?(crlf = true)
                               outch (hdr,cbody) =

  let eol = if crlf then "\r\n" else "\n" in

  let mk_boundary parts =
    (* For performance reasons, gather random data only from the first
     * `Body
     *)
    let rec gather_data parts =
      match parts with
	  (_,`Body body) :: parts' ->
	    let s = Bytes.make 240 ' ' in  (* So it is in the minor heap *)
	    with_in_obj_channel
	      (body # open_value_rd())
	      (fun ch ->
		 try 
		   ignore(ch # input s 0 240)
		 with
		     End_of_file -> ()  (* When body is empty *)
	      );
	    [Bytes.unsafe_to_string s]
	| (_,`Parts_ag(_, parts'')) :: parts' ->
	    (try gather_data parts'' with Not_found -> gather_data parts')
	| [] ->
	    raise Not_found
    in
    let data = try gather_data parts with Not_found -> [] in
    Netmime_string.create_boundary ~random:data ~nr ()
  in

  match cbody with
      `Body body ->
	(* Write the header as it is, and append the body *)
	if wr_header then
	  Netmime_string.write_header ~eol ~soft_eol:eol outch hdr#fields;
	if wr_body then begin
	  let outch' = encode_mime_body ~crlf hdr outch in
	  with_in_obj_channel
	    (body # open_value_rd())
	    (fun bodych -> outch' # output_channel bodych);
	  if outch' <> outch then outch' # close_out();
	end

    | `Parts_ag(cte,parts) ->
	if parts = [] then
	  failwith "Netmime.write_mime_message: Cannot write multipart message with empty list of parts";
	(* If the header does not include a proper content-type field, repair
	 * this now.
	 *)
	let hdr' = new basic_mime_header hdr#fields in
	    (* hdr' will contain the repaired header as side effect *)
	let boundary =
	  try
	    let ctype,params = 
	      try
		Netmime_header.get_content_type hdr   (* or Not_found *)
	      with
		  Not_found as ex -> raise ex  (* falls through to next [try] *)
		| ex ->
		    failwith ("Netmime.write_mime_message: Cannot parse content-type field: " ^ Netexn.to_string ex)
	    in  
	    if String.length ctype < 10 || String.sub ctype 0 10 <> "multipart/"
	    then 
	      failwith "Netmime.write_mime_message: The content type of a multipart message must be 'multipart/*'";
	    try
	      let b = List.assoc "boundary" params in   (* or Not_found *)
	      Netmime_string.param_value b
	    with
		Not_found ->
		  (* Add the missing boundary parameter: *)
		  let b = mk_boundary parts in
		  let ctype_field = 
		    hdr # field "content-type" ^ 
		    ";" ^ eol ^ " boundary=\"" ^ b ^ "\""  in
		  hdr' # update_field "content-type" ctype_field;
		  b
	  with
	      Not_found ->
		(* Add the missing content-type header: *)
		let b = mk_boundary parts in
		let ctype_field = 
		  "multipart/mixed;" ^ eol ^ " boundary=\"" ^ b ^ "\"" in
		hdr' # update_field "content-type" ctype_field;
		b
	in
	(* Now fix the content-transfer-encoding field *)
	hdr' # update_field "content-transfer-encoding" cte;
	(* Write now the header fields *)
	if wr_header then
	  Netmime_string.write_header ~eol ~soft_eol:eol outch hdr'#fields;
	(* Write the parts: *)
	if wr_body then begin
	  let boundary_string = "--" ^ boundary ^ eol in
	  List.iter
	    (fun part ->
	       outch # output_string boundary_string;
	       write_mime_message_int 
	         ~wr_header:true ~wr_body:true ~nr:(nr + 1) ~crlf outch part;
	       outch # output_string eol;
	    )
	    parts;
	  outch # output_string ("--" ^ boundary ^ "--" ^ eol);
	end;
	( match ret_boundary with
	      None -> ()
	    | Some r -> r := boundary
	)
;;


let write_mime_message ?wr_header ?wr_body ?nr ?ret_boundary ?crlf ch msg =
  write_mime_message_int 
     ?wr_header ?wr_body ?nr ?ret_boundary ?crlf
     ch (augment_message msg)
;;
