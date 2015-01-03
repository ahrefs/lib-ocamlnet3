(* $Id$ *)

(** MIME: parsing and printing for channels *)

open Netmime
open Netchannels

(** {1:parsing Parsing MIME messages} *)

val read_mime_header :
      ?unfold:bool ->                        (* default: false *)
      ?strip:bool ->                         (* default: true *)
      ?ro:bool ->                            (* default: false *)
      Netstream.in_obj_stream -> 
	mime_header
  (** Decodes the MIME header that begins at the current position of the
   * netstream, and returns the header as class [basic_mime_header].
   * After returning, the stream is advanced to the byte following the 
   * empty line terminating the header.
   *
   * Example: To read the header at the beginning of the file "f", use:
   * {[ 
   * let ch = new Netchannels.input_channel (open_in "f") in
   * let stream = new Netstream.input_stream ch in
   * let h = read_mime_header stream in
   * ...
   * stream#close_in();    (* no need to close ch *)
   * ]}
   *
   * Note that although the [stream] position after parsing is exactly 
   * known, the position of [ch] cannot be predicted.
   *
   * @param unfold whether linefeeds are replaced by spaces in the values of the
   *   header fields (Note: defaults to [false] here in contrast to
   *   [Netmime_string.scan_header]!)
   * @param strip whether whitespace at the beginning and at the end of the 
   *   header fields is stripped
   * @param ro whether the returned header is read-only (default: false)
   *)

(** Hint: To write the header [h] into the channel [ch], use
 * {[ Netmime_string.write_header ch h#fields ]}
 *
 * Link: {!Netmime_string.write_header}
 *)

type multipart_style = [ `None | `Flat | `Deep ]
  (** How to parse multipart messages:
   * - [`None]: Do not handle multipart messages specially. Multipart bodies
   *    are not further decoded, and returned as [`Body b] where [b] is
   *    the transfer-encoded text representation.
   * - [`Flat]: If the top-level message is a multipart message, the parts
   *    are separated and returned as list. If the parts are again multipart
   *    messages, these inner multipart messages are not furher decoded 
   *    and returned as [`Body b].
   * - [`Deep]: Multipart messages are recursively decoded and returned as
   *    tree structure.
   *
   * This value determines how far the [complex_mime_message] structure
   * is created for a parsed MIME message. [`None] means that no parts
   * are decoded, and messages have always only a simple [`Body b],
   * even if [b] is in reality a multi-part body. With [`Flat], the
   * top-level multi-part bodies are decoded (if found), and messages
   * can have a structured [`Parts [_, `Body b1; _, `Body b1; ...]]
   * body. Finally, [`Deep] allows that inner multi-part bodies are
   * recursively decoded, and messages can have an arbitrarily complex
   * form.
   *)

val decode_mime_body : #mime_header_ro -> out_obj_channel -> out_obj_channel
  (** [let ch' = decode_mime_body hdr ch]:
   * According to the value of the Content-transfer-encoding header field
   * in [hdr] the encoded MIME body written to [ch'] is decoded and transferred
   * to [ch].
   * 
   * Handles 7bit, 8bit, binary, quoted-printable, base64.
   *
   * Example: The file "f" contains base64-encoded data, and is to be decoded 
   * and to be stored in "g":
   *
   * {[ 
   * let ch_f = new Netchannels.input_channel (open_in "f") in
   * let ch_g = new Netchannels.output_channel (open_out "g") in
   * let hdr = new basic_mime_header ["content-transfer-encoding", "base64" ] in
   * let ch = decode_mime_body hdr ch_g in
   * ch # output_channel ch_f;
   * ch # close_out();
   * ch_g # close_out();
   * ch_f # close_in();
   * ]}
   *
   * Note: This function is internally used by [read_mime_message] to
   * decode bodies. There is usually no need to call it directly.
   *)


val storage : ?fin:bool -> store -> (mime_body * out_obj_channel)
  (** Creates a new storage facility for a mime body according to [store].
   * This function can be used to build the [storage_style] argument 
   * of the class [read_mime_message] (below). For example, this is
   * useful to store large attachments in external files, as in:
   *
   * {[ 
   * let storage_style hdr = 
   *   let filename = hdr ... (* extract from hdr *) in
   *   storage (`File filename)
   * ]}
   *
   * @param fin whether to finalize bodies stored in files.
   *   Default: false
   *)

val read_mime_message : 
      ?unfold:bool ->                                     (* Default: false *)
      ?strip:bool ->                                      (* default: true *)
      ?ro:bool ->                                         (* Default: false *)
      ?multipart_style:multipart_style ->                 (* Default: `Deep *)
      ?storage_style:(mime_header -> (mime_body * out_obj_channel)) ->
      Netstream.in_obj_stream -> 
        complex_mime_message
  (** Decodes the MIME message that begins at the current position of the
   * passed netstream. It is expected that the message continues until
   * EOF of the netstream.
   *
   * Multipart messages are decoded as specified by [multipart_style] (see
   * above).
   *
   * Message bodies with content-transfer-encodings of 7bit, 8bit, binary,
   * base64, and quoted-printable can be processed. The bodies are stored
   * without content-transfer-encoding (i.e. in decoded form), but the
   * content-transfer-encoding header field is not removed from the header.
   *
   * The [storage_style] function determines where every message body is
   * stored. The corresponding header of the body is passed to the function
   * as argument; the result of the function is a pair of a new [mime_body]
   * and an [out_obj_channel] writing into this body. You can create such a
   * pair by calling [storage] (above).
   *
   * By default, the [storage_style] is [storage ?ro `Memory] for every header. 
   * Here, the designator [`Memory] means that the body will be stored in an
   * O'Caml string. The designator [`File fn] would mean that the body will be stored in the
   * file [fn]. The file would be created if it did not yet exist, and
   * it would be overwritten if it did already exist.
   *
   * Note that the [storage_style] function is called for every non-multipart
   * body part.
   *
   * Large message bodies (> maximum string length) are supported if the
   * bodies are stored in files. The memory consumption is optimized for
   * this case, and usually only a small constant amount of memory is needed.
   *
   * Example:
   *
   * Parse the MIME message stored in the file f:
   *
   * {[
   * let m = read_mime_message 
   *           (new input_stream (new input_channel (open_in f)))
   * ]}
   *
   * @param unfold whether linefeeds are replaced by spaces in the values of the
   *   header fields (Note: defaults to [false] here in contrast to
   *   {!Netmime_string.scan_header}!)
   * @param strip whether whitespace at the beginning and at the end of the 
   *   header fields is stripped
   * @param ro Whether the created MIME message is read-only
   *
   *)

  (* TODO: what about messages with type "message/*"? It may be possible that
   * they can be recursively decoded, but it is also legal for some media
   * types that they are "partial".
   * Currently the type "message/*" is NOT decoded.
   *)

(** {1:printing Printing MIME Messages} *)

val encode_mime_body : ?crlf:bool -> #mime_header_ro -> out_obj_channel -> out_obj_channel
  (** [let ch' = encode_mime_body hdr ch]:
   * According to the value of the Content-transfer-encoding header field
   * in [hdr] the unencoded MIME body written to ch' is encoded and transferred
   * to ch.
   *
   * Handles 7bit, 8bit, binary, quoted-printable, base64.
   *
   * For an example, see [decode_mime_body] which works in a similar way
   * but performs decoding instead of encoding.
   *
   * @param crlf if set (this is by default the case) CR/LF will be used for
   *   end-of-line (eol) termination, if not set LF will be used. For 7bit, 8bit and
   *   binary encoding the existing eol delimiters are not rewritten, so this option
   *   has only an effect for quoted-printable and base64.
   *)


val write_mime_message :
      ?wr_header:bool ->                       (* default: true *)
      ?wr_body:bool ->                         (* default: true *)
      ?nr:int ->                               (* default: 0 *)
      ?ret_boundary:string ref ->              (* default: do not return it *)
      ?crlf:bool ->                            (* default: true *)
      Netchannels.out_obj_channel ->
      complex_mime_message ->
        unit
  (** Writes the MIME message to the output channel. The content-transfer-
   * encoding of the leaves is respected, and their bodies are encoded
   * accordingly. The content-transfer-encoding of multipart messages is
   * always "fixed", i.e. set to "7bit", "8bit", or "binary" depending
   * on the contents.
   *
   * The function fails if multipart messages do not have a multipart
   * content type field (i.e. the content type does not begin with "multipart").
   * If only the boundary parameter is missing, a good boundary parameter is
   * added to the content type. "Good" means here that it is impossible
   * that the boundary string occurs in the message body if the
   * content-transfer-encoding is quoted-printable or base64, and that
   * such an occurrence is very unlikely if the body is not encoded.
   * If the whole content type field is missing, a "multipart/mixed" type
   * with a boundary parameter is added to the printed header.
   *
   * Note that already existing boundaries are used, no matter whether
   * they are of good quality or not.
   *
   * No other header fields are added, deleted or modified. The mentioned
   * modifications are _not_ written back to the passed MIME message but
   * only added to the generated message text.
   *
   * It is possible in some cases that the boundary does not work (both
   * the existing boundary, and the added boundary). This causes that a wrong
   * and unparseable MIME message is written. In order to ensure a correct
   * MIME message, it is recommended to parse the written text, and to compare
   * the structure of the message trees. It is, however, very unlikely that
   * a problem arises.
   *
   * Note that if the passed message is a simple message like (_,`Body _),
   * and if no content-transfer-encoding is set, the written message might
   * not end with a linefeed character.
   *
   * @param wr_header If true, the outermost header is written. Inner headers
   *   of the message parts are written unless ~wr_body=false.
   * @param wr_body If true, the body of the whole message is written; if false,
   *   no body is written at all.
   * @param nr This argument sets the counter that is included in generated
   *   boundaries to a certain minimum value.
   * @param ret_boundary if passed, the boundary of the outermost multipart
   *   message is written to this reference. (Internally used.)
   * @param crlf if set (this is by default the case) CR/LF will be used for
   *   end-of-line (eol) termination, if not set LF will be used. The eol 
   *   separator is used for the header, the multipart framing, and for
   *   bodies encoded as quoted-printable or base64. Other eol separators are
   *   left untouched.
   *)
