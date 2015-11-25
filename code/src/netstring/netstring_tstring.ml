(* $Id$ *)

open Netsys_types

type _ tstring_kind =
  | String_kind : string tstring_kind
  | Bytes_kind : Bytes.t tstring_kind
  | Memory_kind : memory tstring_kind

type 't tstring_ops =
    { kind : 't tstring_kind option;
      length : 't -> int;
      get : 't -> int -> char;
      unsafe_get : 't -> int -> char;
      unsafe_get3 : 't -> int -> int; (* get 3 chars packed into one int *)
      copy : 't -> 't;
      string : 't -> string;
      bytes : 't -> Bytes.t;
      sub : 't -> int -> int -> 't;
      substring : 't -> int -> int -> string;
      subbytes : 't -> int -> int -> Bytes.t;
      subpoly : 'u . 'u tstring_kind -> 't -> int -> int -> 'u;
      blit_to_bytes : 't -> int -> Bytes.t -> int -> int -> unit;
      blit_to_memory : 't -> int -> memory -> int -> int -> unit;
      index_from : 't -> int -> char -> int;
      rindex_from : 't -> int -> char -> int;
    }

type tstring_ops_box =
  | Tstring_ops_box : 't tstring_kind * 't tstring_ops -> tstring_ops_box

let str_subpoly : type u . u tstring_kind -> string -> int -> int -> u =
  function
  | String_kind -> String.sub
  | Bytes_kind -> (fun s pos len ->
                     let b = Bytes.create len in
                     Bytes.blit_string s pos b 0 len;
                     b
                  )
  | Memory_kind -> (fun s pos len ->
                      let m =
                        Bigarray.Array1.create Bigarray.char Bigarray.c_layout
                                               len in
                      Netsys_mem.blit_string_to_memory s pos m 0 len;
                      m
                   )

let string_ops =
  { kind = Some String_kind;
    length = String.length;
    get = String.get;
    unsafe_get = String.unsafe_get;
    unsafe_get3 = (fun s k ->
                     let c0 = Char.code (String.unsafe_get s k) in
                     let c1 = Char.code (String.unsafe_get s (k+1)) in
                     let c2 = Char.code (String.unsafe_get s (k+2)) in
                     (c0 lsl 16) lor (c1 lsl 8) lor c2
                  );
    copy = String.copy;
    string = String.copy;    (* for the time being; later: identity (TODO) *)
    bytes = Bytes.of_string;
    sub = String.sub;
    substring = String.sub;
    subbytes = (fun s p l ->
                  let b = Bytes.create l in
                  Bytes.blit_string s p b 0 l;
                  b
               );
    subpoly = str_subpoly;
    blit_to_bytes = Bytes.blit_string;
    blit_to_memory = Netsys_mem.blit_string_to_memory;
    index_from = String.index_from;
    rindex_from = String.rindex_from;
  }

let bytes_subpoly : type u . u tstring_kind -> Bytes.t -> int -> int -> u =
  function
  | String_kind -> Bytes.sub_string
  | Bytes_kind -> Bytes.sub
  | Memory_kind -> (fun s pos len ->
                      let m =
                        Bigarray.Array1.create Bigarray.char Bigarray.c_layout
                                               len in
                      Netsys_mem.blit_bytes_to_memory s pos m 0 len;
                      m
                   )

let bytes_ops =
  { kind = Some Bytes_kind;
    length = Bytes.length;
    get = Bytes.get;
    unsafe_get = Bytes.unsafe_get;
    unsafe_get3 = (fun s k ->
                     let c0 = Char.code (Bytes.unsafe_get s k) in
                     let c1 = Char.code (Bytes.unsafe_get s (k+1)) in
                     let c2 = Char.code (Bytes.unsafe_get s (k+2)) in
                     (c0 lsl 16) lor (c1 lsl 8) lor c2
                  );
    copy = Bytes.copy;
    string = Bytes.to_string;
    bytes = Bytes.copy;
    sub = Bytes.sub;
    substring = Bytes.sub_string;
    subbytes = Bytes.sub;
    subpoly = bytes_subpoly;
    blit_to_bytes = Bytes.blit;
    blit_to_memory = Netsys_mem.blit_bytes_to_memory;
    index_from = Bytes.index_from;
    rindex_from = Bytes.rindex_from;
  }

let mem_index_from m p c =
  (* FIXME: implement in C *)
  let n = Bigarray.Array1.dim m in
  if p < 0 || p > n then
    invalid_arg "index_from";
  let p = ref p in
  while !p < n && Bigarray.Array1.unsafe_get m !p <> c do
    incr p
  done;
  if !p >= n then raise Not_found;
  !p

let mem_rindex_from m p c =
  (* FIXME: implement in C *)
  let n = Bigarray.Array1.dim m in
  if p < -1 || p >= n then
    invalid_arg "rindex_from";
  let p = ref p in
  while !p >= 0 && Bigarray.Array1.unsafe_get m !p <> c do
    decr p
  done;
  if !p < 0 then raise Not_found;
  !p

let mem_sub m1 p len = 
  let m2 =
    Bigarray.Array1.create Bigarray.char Bigarray.c_layout len in
  Bigarray.Array1.blit
    (Bigarray.Array1.sub m1 p len)
    m2;
  m2

let mem_subpoly : type u . u tstring_kind -> memory -> int -> int -> u =
  function
  | String_kind -> (fun m pos len ->
                     Netsys_mem.string_of_memory
                       (Bigarray.Array1.sub m pos len)
                   )
  | Bytes_kind -> (fun m pos len ->
                     Netsys_mem.bytes_of_memory
                       (Bigarray.Array1.sub m pos len)
                  )
  | Memory_kind -> mem_sub

let memory_ops =
  { kind = Some Memory_kind;
    length = (Bigarray.Array1.dim : memory -> int);
    get = Bigarray.Array1.get;
    unsafe_get = Bigarray.Array1.unsafe_get;
    unsafe_get3 = (fun s k ->
                     let c0 = Char.code (Bigarray.Array1.unsafe_get s k) in
                     let c1 = Char.code (Bigarray.Array1.unsafe_get s (k+1)) in
                     let c2 = Char.code (Bigarray.Array1.unsafe_get s (k+2)) in
                     (c0 lsl 16) lor (c1 lsl 8) lor c2
                  );
    copy = (fun m1 ->
              let n = Bigarray.Array1.dim m1 in
              mem_sub m1 0 n
           );
    string = Netsys_mem.string_of_memory;
    bytes = Netsys_mem.bytes_of_memory;
    sub = mem_sub;
    substring = (fun m p l ->
                   let m1 = Bigarray.Array1.sub m p l in
                   Netsys_mem.string_of_memory m1
                );
    subbytes = (fun m p l ->
                  let m1 = Bigarray.Array1.sub m p l in
                  Netsys_mem.bytes_of_memory m1
               );
    subpoly = mem_subpoly;
    blit_to_bytes = Netsys_mem.blit_memory_to_bytes;
    blit_to_memory = (fun m1 p1 m2 p2 l ->
                        let sub1 = Bigarray.Array1.sub m1 p1 l in
                        let sub2 = Bigarray.Array1.sub m2 p2 l in
                        Bigarray.Array1.blit sub1 sub2
                     );
    index_from = mem_index_from;
    rindex_from = mem_rindex_from;
  }

let ops_of_tstring =
  function
  | `String _ ->
      Tstring_ops_box(String_kind, string_ops)
  | `Bytes _ ->
      Tstring_ops_box(Bytes_kind, bytes_ops)
  | `Memory _ ->
      Tstring_ops_box(Memory_kind, memory_ops)


type 'a with_fun =
    { with_fun : 's . 's tstring_ops -> 's -> 'a }

let with_tstring : 'a with_fun -> tstring -> 'a =
  fun f ->
    function
    | `String s ->
        f.with_fun string_ops s
    | `Bytes s ->
        f.with_fun bytes_ops s
    | `Memory s ->
        f.with_fun memory_ops s

