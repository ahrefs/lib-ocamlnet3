(* $Id$ *)

open Netsys_types

type iana_hash_fn =
  [ `MD2 | `MD5 | `SHA_1 | `SHA_224 | `SHA_256 | `SHA_384 | `SHA_512 ]

class type digest_ctx =
object
  method add_memory : Netsys_types.memory -> unit
  method add_subbytes : Bytes.t -> int -> int -> unit
  method add_substring : string -> int -> int -> unit
  method add_tstring : tstring -> int -> int -> unit
  method finish : unit -> string
end


class type digest =
object
  method name : string
  method iana_hash_fn : iana_hash_fn option
  method iana_name : string option
  method oid : int array option
  method size : int
  method block_length : int
  method create : unit -> digest_ctx
end

let iana_alist =
  [ "md2",      `MD2;
    "md5",      `MD5;
    "sha-1",    `SHA_1;
    "sha-224",  `SHA_224;
    "sha-256",  `SHA_256;
    "sha-384",  `SHA_384;
    "sha-512",  `SHA_512;
  ]

let iana_rev_alist =
  List.map (fun (a,b) -> (b,a)) iana_alist

let oid_alist =
  [ [| 1;2;840;113549;2;2 |],     `MD2;
    [| 1;2;840;113549;2;5 |],     `MD5;
    [| 1;3;14;3;2;26 |],          `SHA_1;
    [| 2;16;840;1;101;3;4;2;4 |], `SHA_224;
    [| 2;16;840;1;101;3;4;2;1 |], `SHA_256;
    [| 2;16;840;1;101;3;4;2;2 |], `SHA_384;
    [| 2;16;840;1;101;3;4;2;3 |], `SHA_512;
  ]

let oid_rev_alist =
  List.map (fun (a,b) -> (b,a)) oid_alist

let name_alist =
  [ "MD2-128",      `MD2;
    "MD5-128",      `MD5;
    "SHA1-160",     `SHA_1;
    "SHA2-224",     `SHA_224;
    "SHA2-256",     `SHA_256;
    "SHA2-384",     `SHA_384;
    "SHA2-512",     `SHA_512;
  ]

let name_rev_alist =
  List.map (fun (a,b) -> (b,a)) name_alist

module Digest(Impl : Netsys_crypto_types.DIGESTS) = struct

  let digest_ctx (dg : Impl.digest) (ctx : Impl.digest_ctx) : digest_ctx =
    ( object(self)
        method add_memory mem =
          Impl.add ctx mem
        method add_subbytes s pos len =
          let mem, free = Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
          let n = ref len in
          let p = ref pos in
          while !n > 0 do
            let r = min !n (Bigarray.Array1.dim mem) in
            Netsys_mem.blit_bytes_to_memory s !p mem 0 r;
            Impl.add ctx (Bigarray.Array1.sub mem 0 r);
            n := !n - r;
            p := !p + r;
          done;
          free()
        method add_substring s pos len =
          self # add_subbytes (Bytes.unsafe_of_string s) pos len
        method add_tstring s pos len =
          match s with
            | `Bytes u ->
                self # add_subbytes u pos len
            | `Memory u ->
                self # add_memory (Bigarray.Array1.sub u pos len)
            | `String u ->
                self # add_substring u pos len
        method finish() =
          Impl.finish ctx
      end
    )

  let digest (dg : Impl.digest) =
    let name = Impl.name dg in
    let iana_hash_fn, iana_name, oid =
      try 
        let h = List.assoc name name_alist in
        let n = List.assoc h iana_rev_alist in
        let o = List.assoc h oid_rev_alist in
        (Some h, Some n, Some o)
      with Not_found -> 
        (None, None, None) in
    ( object
        method name = name
        method iana_hash_fn = iana_hash_fn
        method iana_name = iana_name
        method oid = oid
        method size = Impl.size dg
        method block_length = Impl.block_length dg
        method create() = digest_ctx dg (Impl.create dg)
      end
    )

  let list() =
    List.map digest Impl.digests

  let find name =
    digest (Impl.find name)

end


let digests ?(impl = Netsys_crypto.current_digests()) () =
  let module I = (val impl : Netsys_crypto_types.DIGESTS) in
  let module C = Digest(I) in
  C.list()


let find ?(impl = Netsys_crypto.current_digests()) name =
  let module I = (val impl : Netsys_crypto_types.DIGESTS) in
  let module C = Digest(I) in
  C.find name

let iana_find ?impl iana_name =
  let name = List.assoc iana_name name_rev_alist in
  find ?impl name


let digest_something adder length (dg : digest) s =
  let ctx = dg # create() in
  adder ctx s 0 (length s);
  ctx # finish()

let digest_bytes dg s =
  digest_something (fun ctx -> ctx#add_subbytes) Bytes.length dg s

let digest_string dg s =
  digest_something (fun ctx -> ctx#add_substring) String.length dg s

let digest_tstring dg s =
  digest_something (fun ctx -> ctx#add_tstring)
                   Netsys_impl_util.tstring_length dg s


let digest_mstrings (hash:digest) ms_list =
  (* Like Netsys_digests.digest_string, but for "mstring list" *)
  let ctx = hash#create() in

  let rec loop in_list =
    match in_list with
      | ms :: in_list' ->
	  let ms_len = ms#length in
	  ( match ms#preferred with
	      | `Bytes ->
		  let (s,start) = ms#as_bytes in
		  ctx#add_subbytes s start ms_len;
		  loop in_list'
	      | `Memory ->
		  let (m,start) = ms#as_memory in
                  ctx#add_memory m;
		  loop in_list'
	  )
      | [] ->
	  ctx#finish() in
  loop ms_list
  

let xor_s s u =
  let s_len = String.length s in
  let u_len = String.length u in
  assert(s_len = u_len);
  let x = Bytes.create s_len in
  for k = 0 to s_len-1 do
    Bytes.set x k (Char.chr ((Char.code s.[k]) lxor (Char.code u.[k])))
  done;
  Bytes.to_string x

let hmac_ctx dg key =
  let b = dg # block_length in
  if String.length key > b then
    invalid_arg "Netsys_digests.hmac: key too long";
  
  let k_padded = key ^ String.make (b - String.length key) '\000' in
  let ipad = String.make b '\x36' in
  let opad = String.make b '\x5c' in

  let ictx = dg#create() in
  let k_ipad = xor_s k_padded ipad in
  ictx # add_substring k_ipad 0 (String.length ipad);
  
  ( object
      method add_memory m =
        ictx # add_memory m
      method add_subbytes s pos len =
        ictx # add_subbytes s pos len
      method add_substring s pos len =
        ictx # add_substring s pos len
      method add_tstring s pos len =
        ictx # add_tstring s pos len
      method finish() =
        let ires = ictx # finish() in
        digest_string dg ((xor_s k_padded opad) ^ ires)
    end
  )

let hmac dg key =
  ( object
      method name = "HMAC-" ^ dg#name
      method iana_hash_fn = None
      method iana_name = None
      method oid = None
      method size = dg#size
      method block_length = dg#block_length
      method create() = hmac_ctx dg key
    end
  )
