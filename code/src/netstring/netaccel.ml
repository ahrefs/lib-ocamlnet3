(* $Id$ *)

external int_blit
  : int array -> int -> int array -> int -> int -> unit
  = "netstring_int_blit_ml" ;;

external int_series
  : int array -> int -> int array -> int -> int -> int -> unit
  = "netstring_int_series_byte"  "netstring_int_series_ml";;


external read_iso88591_str
  : int -> Netconversion.encoding -> int array -> int array -> string -> int -> int -> 
    (int*int*Netconversion.encoding)
  = "netstring_read_iso88591_byte" "netstring_read_iso88591_ml" ;;

external read_utf8_str
  : bool -> int array -> int array -> string -> int -> int -> 
    (int*int*Netconversion.encoding)
  = "netstring_read_utf8_byte" "netstring_read_utf8_ml" ;;

let read_iso88591 limit enc =
  let open Netstring_tstring in
  let open Netconversion in
  let read : type s . s tstring_ops -> _ -> _ -> s -> _ -> _ -> _ =
    fun ops chars blen s pos len ->
      match ops.kind with
        | Some String_kind ->
            read_iso88591_str limit enc chars blen s pos len
        | _ ->
            (Netconversion.read_iso88591 limit enc).read 
               ops chars blen s pos len in
  { Netconversion.read }


let read_utf8 is_java =
  let open Netstring_tstring in
  let open Netconversion in
  let read : type s . s tstring_ops -> _ -> _ -> s -> _ -> _ -> _ =
    fun ops chars blen s pos len ->
      match ops.kind with
        | Some String_kind ->
            read_utf8_str is_java chars blen s pos len
        | _ ->
            (Netconversion.read_utf8 is_java).read 
               ops chars blen s pos len in
  { Netconversion.read }



let init() =
  Netaux.ArrayAux.int_blit_ref := int_blit;
  Netaux.ArrayAux.int_series_ref := int_series;
  Netconversion.read_iso88591_ref := read_iso88591;
  Netconversion.read_utf8_ref := read_utf8;;
