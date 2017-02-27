(* $Id$ *)

open Netmime

let drop_ws_re = 
  Netstring_str.regexp "^[ \t\r\n]*\\(.*[^ \t\r\n]\\)[ \t\r\n]*$";;

let drop_ws s =
  (* Deletes whitespace at the beginning and at the end of s, and returns
   * the new string
   *)
  match Netstring_str.string_match drop_ws_re s 0 with
      None -> ""
    | Some r -> Netstring_str.matched_group r 1 s
;;
  

let get_content_length hdr = 
  int_of_string (drop_ws(hdr # field "content-length"))

let get_content_type hdr =
  Netmime_string.scan_mime_type_ep (hdr#field "content-type") []

let get_content_disposition hdr =
  Netmime_string.scan_mime_type_ep (hdr#field "content-disposition") []

let get_content_transfer_encoding hdr = 
  STRING_LOWERCASE (hdr # field "content-transfer-encoding")
