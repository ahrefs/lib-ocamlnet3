(* $Id$ *)

open Netmcore_heap

type ('e,'h) t =
    { mutable array : 'e array;
      header : 'h
    }

type ('e,'h) sarray = ('e,'h) t heap

let create res_id a h =
  let ra = { array = a; header = h } in
  create_heap 
    res_id 
    (minimum_size ra)
    ra

let make res_id n x h =
  let ra = { array = [| |]; header = h } in
  let sa = create_heap res_id 4096 ra in
  modify
    sa
    (fun mut ->
       let a = add_uniform_array mut n x in
       (root sa).array <- a
    );
  sa
    
let init res_id n f h =
  let ra = { array = [| |]; header = h } in
  let sa = create_heap res_id 4096 ra in
  modify
    sa
    (fun mut ->
       let a = add_init_array mut n f in
       (root sa).array <- a
    );
  sa

let grow sa n x =
  modify
    sa
    (fun mut ->
       let ra = root sa in
       let old_n = Array.length ra.array in
       if n > old_n then (
	 let new_a = add_uniform_array mut n x in
	 Array.blit ra.array 0 new_a 0 old_n;
	 ra.array <- new_a
       )
    )


let set sa k x =
  modify
    sa
    (fun mut ->
       let a = (root sa).array in
       a.(k) <- add mut x
    )

let get sa k =
  let a = (root sa).array in
  a.(k)

let get_p sa k f =
  with_value
    sa
    (fun () ->
       let a = (root sa).array in
       a.(k)
    )
    f

let get_c sa k =
  get_p sa k copy

let length sa =
  let a = (root sa).array in
  Array.length a

let deref sa =
  (root sa).array

let header sa =
  (root sa).header

let heap sa =
  Obj.magic sa
