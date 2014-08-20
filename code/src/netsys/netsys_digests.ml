(* $Id$ *)

class type digest_ctx =
object
  method add_memory : Netsys_types.memory -> unit
  method add_substring : string -> int -> int -> unit
  method finish : unit -> string
end


class type digest =
object
  method name : string
  method size : int
  method create : unit -> digest_ctx
end


module Digest(Impl : Netsys_crypto_types.DIGESTS) = struct

  let digest_ctx (dg : Impl.digest) (ctx : Impl.digest_ctx) =
    ( object
        method add_memory mem =
          Impl.add ctx mem
        method add_substring s pos len =
          let mem, free = Netsys_mem.pool_alloc_memory2 Netsys_mem.small_pool in
          let n = ref len in
          let p = ref pos in
          while !n > 0 do
            let r = min !n (Bigarray.Array1.dim mem) in
            Netsys_mem.blit_string_to_memory s !p mem 0 r;
            Impl.add ctx (Bigarray.Array1.sub mem 0 r);
            n := !n - r;
            p := !p + r;
          done;
          free()
        method finish() =
          Impl.finish ctx
      end
    )

  let digest (dg : Impl.digest) =
    ( object
        method name = Impl.name dg
        method size = Impl.size dg
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


let digest_string dg s =
  let ctx = dg # create() in
  ctx # add_substring s 0 (String.length s);
  ctx # finish()
