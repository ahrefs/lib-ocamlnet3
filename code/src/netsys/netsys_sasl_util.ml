(* $Id$ *)

(* Internal module *)

type credentials =
    (string * string * (string * string) list) list

let extract_password2 (c:credentials) =
  let (_, value, params) =
    List.find
      (function
        | ("password", _, _) -> true
        | _ -> false
      )
      c in
  (value,params)

let extract_password (c:credentials) =
  fst(extract_password2 c)
    

let preprocess_params err_prefix known_params params =
  List.iter
    (fun (name,_,critical) ->
       if critical && not(List.mem name known_params) then
         failwith (err_prefix ^ " Cannot process critical parameter: " ^ name)
    )
    params;
  List.map (fun (n,v,_) -> (n,v)) params


let string_of_server_state =
  function
  | `OK -> "*"
  | `Wait -> "w"
  | `Emit -> "e"
  | `Auth_error s -> "F" ^ s
  | `Restart s -> "r" ^ s

let server_state_of_string s =
  try
    if String.length s < 1 then raise Not_found;
    match s.[0] with
      | '*' -> `OK
      | 'w' -> `Wait
      | 'e' -> `Emit
      | 'F' -> `Auth_error (String.sub s 1 (String.length s - 1))
      | 'r' -> `Restart (String.sub s 1 (String.length s - 1))
      | _ -> raise Not_found
  with
    | Not_found ->
         invalid_arg "Netsys_sasl_util.server_state_of_string"

let string_of_client_state =
  function
  | `OK -> "*"
  | `Wait -> "w"
  | `Emit -> "e"
  | `Auth_error s -> "F" ^ s
  | `Stale -> "s"

let client_state_of_string s =
  try
    if String.length s < 1 then raise Not_found;
    match s.[0] with
      | '*' -> `OK
      | 'w' -> `Wait
      | 'e' -> `Emit
      | 'F' -> `Auth_error (String.sub s 1 (String.length s - 1))
      | 's' -> `Stale
      | _ -> raise Not_found
  with
    | Not_found ->
         invalid_arg "Netsys_sasl_util.client_state_of_string"

