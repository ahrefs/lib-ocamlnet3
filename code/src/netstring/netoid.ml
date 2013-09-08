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
