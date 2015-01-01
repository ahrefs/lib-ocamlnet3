(* $Id$ *)

type t = int array

let equal oid1 oid2 = (oid1 = oid2)

let compare oid1 oid2 =
  let l1 = Array.length oid1 in
  let l2 = Array.length oid2 in

  let rec cmp k =
    if k >= l1 || k >= l2 then
      if k >= l1 then (
        if k >= l2 then
          0
        else
          (-1)
      )
      else (* k >= l2 *)
        1
    else
      let p = oid1.(k) - oid2.(k) in
      if p = 0 then
        cmp (k+1)
      else
        p in
  cmp 0


let dec_re = Netstring_str.regexp "^[0-9]+$"


let int_of_decimal s =
  match Netstring_str.string_match dec_re s 0 with
    | Some _ ->
        int_of_string s
    | None ->
        raise Not_found


let split_re = Netstring_str.regexp "[.]"

let of_string s =
  try
    Array.of_list (List.map int_of_decimal (Netstring_str.split split_re s))
  with _ ->
    failwith "Netoid.of_string"


let to_string oid =
  String.concat "." (List.map string_of_int (Array.to_list oid))

(* Curly notation follows RFC 2078, but additional information about DER
   can also be found in ITU-T X.690:

     http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *)

let of_string_curly s =
  let oid_str_re = Netstring_str.regexp "[ \t\r\n]+\\|{\\|}" in
  let rec cont1 l =
    match l with
      | Netstring_str.Delim "{" :: l' -> cont2 l'
      | Netstring_str.Delim "}" :: _ -> raise Not_found
      | Netstring_str.Delim _ :: l' -> cont1 l'   (* whitespace *)
      | _ -> raise Not_found 
  and cont2 l =  (* after "{" *)
    match l with
      | Netstring_str.Delim "{" :: _ -> raise Not_found
      | Netstring_str.Delim "}" :: l' -> cont3 l'
      | Netstring_str.Delim _ :: l' -> cont2 l'
      | Netstring_str.Text s :: l' -> int_of_string s :: cont2 l'
      | _ -> raise Not_found
  and cont3 l = (* after "}" *)
    match l with
      | Netstring_str.Delim ("{" | "}") :: _ -> raise Not_found
      | Netstring_str.Delim _ :: l' -> cont3 l'
      | [] -> []
      | _ -> raise Not_found 
  in

  let l =
    Netstring_str.full_split oid_str_re s in
  try
    Array.of_list(cont1 l)
  with
    | _ -> failwith "Netoid.of_string_curly"

let to_string_curly oid =
  "{" ^ String.concat " " (List.map string_of_int (Array.to_list oid)) ^ "}"
