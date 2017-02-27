(* $Id$ *)

open Printf

type oid = Netoid.t

type dn = (oid * Netasn1.Value.value) list list

module type AT_LOOKUP = sig
  val attribute_types : (oid * string * string list) list
  val lookup_attribute_type_by_oid : oid -> string * string list
  val lookup_attribute_type_by_name : string -> oid * string * string list
end

module type DN_string = sig
  val parse : string -> dn
  val print : dn -> string
end


let () =
  Netmappings_asn1.init()
    (* ensure that asn1 tables are linked in *)

let directory_string_from_ASN1 value =
  let fail_enc() =
    failwith "Netx509.directory_string_from_ASN1: bad input encoding" in
  match value with
    | Netasn1.Value.UTF8String s ->
         ( try Netconversion.verify `Enc_utf8 s
           with Netconversion.Malformed_code_at _ -> fail_enc()
         );
         s
    | Netasn1.Value.PrintableString s ->
         ( try Netconversion.convert 
                 ~in_enc:`Enc_asn1_printable ~out_enc:`Enc_utf8 s
           with Netconversion.Malformed_code -> fail_enc()
         )
    | Netasn1.Value.IA5String s ->
         ( try Netconversion.convert 
                 ~in_enc:`Enc_usascii ~out_enc:`Enc_utf8 s
           with Netconversion.Malformed_code -> fail_enc()
         )
    | Netasn1.Value.TeletexString s ->
         ( try Netconversion.convert 
                 ~in_enc:`Enc_asn1_T61 ~out_enc:`Enc_utf8 s
           with Netconversion.Malformed_code -> fail_enc()
         )
    | Netasn1.Value.BMPString s ->
         ( try Netconversion.convert 
                 ~in_enc:`Enc_utf16_be ~out_enc:`Enc_utf8 s
           with Netconversion.Malformed_code -> fail_enc()
         )
    | Netasn1.Value.UniversalString s ->
         ( try Netconversion.convert 
                 ~in_enc:`Enc_utf32_be ~out_enc:`Enc_utf8 s
           with Netconversion.Malformed_code -> fail_enc()
         )
    | _ ->
         failwith "Netx509.directory_string_from_ASN1: \
                   unsupported ASN.1 value type"


module DN_string_generic(L : AT_LOOKUP) = struct
  type token =
    | Space
    | Quote
    | Hash
    | Plus
    | Comma
    | Semi
    | Less
    | Equal
    | Greater
    | Text of (string * bool)
        (* bool: whether there were escaped chars when decoding the text *)

  let illegal_esc() =
    failwith "Netdn.DN_string.parse: illegal escape sequence"

  let syntax_error() =
    failwith "Netdn.DN_string.parse: syntax error"

  let hex_val s = int_of_string ("0x" ^ s)


  let tokenize s =
    let l = String.length s in
    let b = Buffer.create 80 in
    let b_esc = ref false in

    let rec next k =
      if k < l then (
        match s.[k] with
          | ' ' -> special Space (k+1)
          | '"' -> special Quote (k+1)
          | '#' -> special Hash (k+1)
          | '+' -> special Plus (k+1)
          | ',' -> special Comma (k+1)
          | ';' -> special Semi (k+1)
          | '<' -> special Less (k+1)
          | '=' -> special Equal (k+1)
          | '>' -> special Greater (k+1)
          | '\\' ->
              if k+1 < l then
                match s.[k+1] with
                  | ( ' ' | '"' | '#' | '+' | ',' | ';' | '<' | '=' | '>' 
                      | '\\'
                    )  as c ->
                      Buffer.add_char b c;
                      b_esc := true;
                      next (k+2)
                  | ( '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' ) as c1 ->
                      if k+2 < l then
                        match s.[k+2] with
                          | ( '0' .. '9' | 'A' .. 'F' | 'a' .. 'f' ) as c2 ->
                              let h = Bytes.create 2 in
                              Bytes.set h 0 c1;
                              Bytes.set h 1 c2;
                              let v = hex_val (Bytes.to_string h) in
                              Buffer.add_char b (Char.chr v);
                              b_esc := true;
                              next (k+3)
                          | _ ->
                              illegal_esc()
                      else
                        illegal_esc()
                  | _ ->
                      illegal_esc()
              else
                illegal_esc()
          | c ->
              Buffer.add_char b c;
              next (k+1)
      )
      else
        if Buffer.length b > 0 then
          [ Text (Buffer.contents b, !b_esc) ]
        else
          []

    and special token k =
      if Buffer.length b > 0 then (
        let u = Buffer.contents b in
        let e = !b_esc in
        Buffer.clear b;
        b_esc := false;
        Text(u,e) :: token :: next k
      )
      else
        token :: next k

    in

    next 0


  let rec skip_spaces toks =
    (* until the next Equal token *)
    match toks with
      | Space :: toks' ->
          skip_spaces toks'
      | Equal :: toks' ->
          toks
      | other :: toks' ->
          other :: skip_spaces toks'
      | [] ->
          []


  let descr_re =
    Netstring_str.regexp "^[A-Za-z][A-Za-z0-9-]*$"


  let parse s =
    let rec parse_rdn cur toks =
      let toks = skip_spaces toks in
      match toks with
        | Text(name,esc) :: Equal :: toks1 ->
            if esc then illegal_esc();
            if Netstring_str.string_match descr_re name 0 <> None then (
              (* it's a descr *)
              let name_uc = STRING_UPPERCASE name in
              let (oid, _, _) =
                try L.lookup_attribute_type_by_name name_uc
                with Not_found ->
                  failwith ("Netdn.DN_string.parse: unknown attribute '" ^ 
                              name ^ "'") in
              parse_value cur oid toks1                
            )
            else (
              try
                let oid = Netoid.of_string name in
                parse_value cur oid toks1
              with
                | _ ->
                    syntax_error()
            )
        | _ ->
            syntax_error()


      and parse_value cur oid toks =
        match toks with
          | Hash :: _ ->
              failwith "Netdn.DN_string.parse: hex-encoded values are not \
                        supported by this parser"
          | Space :: toks1 ->
              (* CHECK *)
              parse_value cur oid toks1
          | _ ->
              parse_value_rest cur oid [] toks

      and parse_value_rest cur oid value toks =
        match toks with
          | Plus :: toks1 ->
              let ava = (oid, utf8 (String.concat "" (List.rev value))) in
              parse_rdn (ava :: cur) toks1
          | Comma :: toks1 ->
              let ava = (oid, utf8 (String.concat "" (List.rev value))) in
              let rdn = List.rev (ava :: cur) in
              rdn :: parse_rdn [] toks1
          | Text(s,_) :: toks1 ->
              parse_value_rest cur oid (s :: value) toks1
          | Hash :: toks1 ->
              parse_value_rest cur oid ("#" :: value) toks1
          | Equal :: toks1 ->
              parse_value_rest cur oid ("=" :: value) toks1
          | Space :: toks1 ->
              parse_value_rest cur oid (" " :: value) toks1
          | (Quote | Semi | Less | Greater) :: toks1 ->
              syntax_error()
          | [] ->
              let ava = (oid, utf8 (String.concat "" (List.rev value))) in
              let rdn = List.rev (ava :: cur) in
              [ rdn ]

      and utf8 s =
        try
          Netconversion.verify `Enc_utf8 s;
          Netasn1.Value.UTF8String s
        with 
          | Netconversion.Malformed_code_at _ ->
              failwith "Netdn.DN_string.parse: not in UTF-8"

    in
    parse_rdn [] (tokenize s)



  let string_of_ava (oid, value) =
    let oid_str =
      try
        let (_, l) = L.lookup_attribute_type_by_oid oid in
        if l = [] then raise Not_found;
        List.hd l
      with Not_found -> Netoid.to_string oid in
    let u = directory_string_from_ASN1 value in
    let b = Buffer.create 80 in
    Buffer.add_string b oid_str;
    Buffer.add_char b '=';
    let l = String.length u in
    for k = 0 to l - 1 do
      match String.unsafe_get u k with
        | ' ' ->
            if k=0 || k=l-1 then
              Buffer.add_string b "\\20"
            else
              Buffer.add_char b ' '
        | '#' ->
            if k=0 then
              Buffer.add_string b "\\23"
            else
              Buffer.add_char b '#'
        | ('"' | '+' | ',' | ';' | '<' | '>' | '\\') as c ->
            Buffer.add_string b (sprintf "\\%02x" (Char.code c))
        | c ->
            Buffer.add_char b c
    done;
    Buffer.contents b
        


  let print dn =
    String.concat
      ","
      (List.map
         (fun rdn ->
            String.concat
              "+"
              (List.map string_of_ava rdn)
         )
         dn
      )


end
