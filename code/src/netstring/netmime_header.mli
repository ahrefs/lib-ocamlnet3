(* $Id$ *)

(** MIME: Access methods for frequent standard fields.
 *
 * These functions will raise [Not_found] if the fields are not
 * present.
 *
 * Many HTTP-specific header functions can be found in {!Nethttp.Header}.
 *)

open Netmime

val get_content_length : #mime_header_ro -> int
(** Returns the Content-length field as integer *)

val get_content_type : 
           #mime_header_ro -> (string * (string * Netmime_string.s_param)list)
    (** Returns the Content-type as parsed value. The left value of the
     * pair is the main type, and the right value is the list of 
     * parameters. For example, for the field value
     * ["text/plain; charset=utf-8"] this method returns
     * [("text/plain", ["charset", p])] where [p] is an opaque value
     * with [Netmime_string.param_value p = "utf-8"]. 
     *)

val get_content_disposition : 
           #mime_header_ro -> (string * (string * Netmime_string.s_param)list)
    (** Returns the Content-disposition field as parsed value. The
     * left value is the main disposition, and the right value is the
     * list of parameters. For example, for the field value
     * ["attachment; filename=xy.dat"] this method returns
     * [("attachment", ["filename", p])] where [p] is an opaque value
     * with [Netmime_string.param_value p = "xy.dat"].
     *)

val get_content_transfer_encoding : #mime_header_ro -> string
    (** Returns the Content-transfer-encoding as string *)
