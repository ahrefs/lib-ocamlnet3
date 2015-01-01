(* $Id$ *)

exception SASLprepError

open Netsaslprep_data

let map (u : int array) =
  let to_space = Hashtbl.create 41 in
  let to_nothing = Hashtbl.create 41 in
  Array.iter (fun p -> Hashtbl.add to_space p ()) map_to_space;
  Array.iter (fun p -> Hashtbl.add to_nothing p ()) map_to_nothing;
  let u0 = Array.to_list u in
  let u1 =
    List.filter
      (fun p -> not (Hashtbl.mem to_nothing p))
      u0 in
  let u2 =
    List.map
      (fun p ->
         if Hashtbl.mem to_space p then
           32
         else
           p
      )
      u1 in
  Array.of_list u2


(* The KC normalizer follows roughly
  https://web.archive.org/web/20070514031407/http://www.unicode.org/unicode/reports/tr15/Normalizer.html
 *)


type buffer =
    { mutable buf : int array;
      mutable len : int
    }


let create_buffer() =
  { buf = Array.make 42 0;
    len = 0
  }

let buffer_at buf k =
  assert(k >= 0 && k < buf.len);
  buf.buf.(k)

let set_buffer_at buf k ch =
  assert(k >= 0 && k < buf.len);
  buf.buf.(k) <- ch

let resize buf =
  let nbuf = Array.make (Array.length buf.buf * 2) 0 in
  Array.blit buf.buf 0 nbuf 0 (Array.length buf.buf);
  buf.buf <- nbuf
             

let insert_at buf k ch =
  assert(k >= 0 && k <= buf.len);
  if buf.len = Array.length buf.buf then resize buf;
  if k < buf.len then
    Array.blit buf.buf k buf.buf (k+1) (buf.len - k);
  buf.buf.(k) <- ch;
  buf.len <- buf.len + 1

let length buf =
  buf.len

let contents buf =
  Array.sub buf.buf 0 buf.len


let get_cano_tab() =
  let cano_tab = Hashtbl.create 41 in
  let last = ref 0 in
  Array.iter
    (fun p ->
       if p < 0 then
         last := -p
       else
         Hashtbl.add cano_tab p !last
    )
    cano_classes;
  cano_tab


let cano_tab =
  (* this table is pretty small *)
  get_cano_tab()



(* Hangul *)
let h_SBase = 0xAC00
let h_LBase = 0x1100
let h_VBase = 0x1161
let h_TBase = 0x11A7
let h_LCount = 19
let h_VCount = 21
let h_TCount = 28
let h_NCount = h_VCount * h_TCount
let h_SCount = h_LCount * h_NCount


let decompose_hangul code =
  if code < h_SBase || code >= h_SBase + h_SCount then raise Not_found;
  let si = code - h_SBase in
  let l = h_LBase + si/h_NCount in
  let v = h_VBase + (si mod h_NCount) / h_TCount in
  let t = h_TBase + si mod h_TCount in
  if t = h_TBase then
    [ l; v ]
  else
    [ l; v; t ]


let compose_hangul first second =
  (* check for L and V *)
  if first >= h_LBase && 
       first < h_LBase + h_LCount &&
         second >= h_VBase &&
           second < h_VBase + h_VCount
  then
    (* create LV syllable *)
    let l = first - h_LBase in
    let v = second - h_VBase in
    h_SBase  +  (l*h_VCount + v) * h_TCount
  else
    (* check for LV and T *)
    let si = first - h_SBase in
    if first >= h_SBase && 
         first < h_SBase + h_SCount && 
           si mod h_TCount = 0
    then
      let ti = second - h_TBase in
      first + ti
    else
      raise Not_found


let decompose (u : int array) =
  (* "compatibility decomposition" as required for NFKC *)
  let decomp_tab = Hashtbl.create 41 in
  let last = ref (ref []) in
  Array.iter
    (fun p ->
       if p < 0 then (
         last := ref [];
         Hashtbl.add decomp_tab ((-p) lsr 1) !last
       )
       else
         !last := p :: ! !last
    )
    decompositions;
  let rec get_recursive_decomp ch =
    try
      let chars = List.rev (! (Hashtbl.find decomp_tab ch)) in
      List.flatten (List.map get_recursive_decomp chars)
    with
      | Not_found ->
           try
             decompose_hangul ch
           with
             | Not_found -> [ch] in
  let get_cc ch = try Hashtbl.find cano_tab ch with Not_found -> 0 in
  let target = create_buffer() in
  for i = 0 to Array.length u - 1 do
    let decomp = get_recursive_decomp u.(i) in
    List.iter
      (fun ch ->
         let cc = get_cc ch in
         let k = ref (length target) in
         if cc <> 0 then (
           while
             !k > 0 &&
               get_cc (buffer_at target (!k-1)) > cc
           do
             decr k
           done
         );
         insert_at target !k ch
      )
      decomp
  done;
  contents target


let compose_1 (u : int array) =
  (* "canonical composition" as required for NFKC *)
  (* u <> [| |] required *)
  let excl_tab = Hashtbl.create 41 in
  Array.iter
    (fun p -> Hashtbl.add excl_tab p ())
    exclusions;
  let comp_tab = Hashtbl.create 41 in
  let last_p = ref 0 in
  let last = ref [] in
  Array.iter
    (fun p ->
       if p < 0 then (
         if !last <> [] then (
           let q = (- !last_p) lsr 1 in
           let is_canonical = (- !last_p) land 1 = 0 in
           let is_excluded = Hashtbl.mem excl_tab q in
           if is_canonical && not is_excluded  then (
             match !last with
               | [ c0 ] ->
                    ()
               | [ c1; c0 ] ->
                    (* NB. We can at most support 15 bits *)
                    assert(c0 < 16384);
                    assert(c1 < 16384);
                    Hashtbl.add comp_tab ((c0 lsl 14) lor c1) q
               | _ ->
                    assert false
           )
         );
         last_p := p;
         last := [];
       )
       else
         last := p :: !last
    )
    decompositions;
  let get_cc ch = try Hashtbl.find cano_tab ch with Not_found -> 0 in
  let target = create_buffer() in
  let starter_pos = ref 0 in
  let starter_ch = ref u.(!starter_pos) in
  let last_class = ref (get_cc !starter_ch) in
  if !last_class <> 0 then last_class := 256;
  insert_at target 0 !starter_ch;
  
  for i = 1 to Array.length u - 1 do
    let ch = u.(i) in
    let cc = get_cc ch in
    try
      let composite =
        try
          if !starter_ch >= 16384 || ch >= 16384 then raise Not_found;
          Hashtbl.find comp_tab ((!starter_ch lsl 14) lor ch)
        with
          | Not_found ->
               compose_hangul !starter_ch ch in
      if !last_class >= cc && !last_class <> 0 then raise Not_found;
      set_buffer_at target !starter_pos composite;
      starter_ch := composite
    with
      | Not_found ->
           if cc = 0 then (
             starter_pos := length target;
             starter_ch := ch;
           );
           last_class := cc;
           insert_at target (length target) ch
  done;
  contents target


let compose u =
  if u = [| |] then [| |] else compose_1 u


let exists f a =
  try
    Array.iter (fun p -> if f p then raise Exit) a;
    false
  with Exit -> true


let norm_needed u =
  (* If the string uses only certain characters we don't need to normalize.
     These are practically all Latin, Greek and Cyrillic characters.
   *)
  let quick_need_norm c =
    not
      ((c >= 0x20 && c <= 0x7e) ||
         (c >= 0xc0 && c <= 0x131) ||
           (c >= 0x134 && c <= 0x13e) ||
             (c >= 0x141 && c <= 0x148) ||
               (c >= 0x14a && c <= 0x17e) ||
                 (c >= 0x180 && c <= 0x1c3) ||
                   (c >= 0x1cd && c <= 0x1f0) ||
                     (c >= 0x1f4 && c <= 0x2ad) ||
                       (c >= 0x374 && c <= 0x375) ||
                         (c = 0x37e) ||
                           (c >= 0x385 && c <= 0x3ce) ||
                             (c >= 0x400 && c <= 0x482) ||
                               (c >= 0x48a && c <= 0x50f)
      ) in
  exists quick_need_norm u


let normalize u =
  (* normalization form KC (NFKC) *)
  if norm_needed u then
    compose (decompose u)
  else
    u


let prohibited u =
  Array.iter
    (fun p -> 
       Array.iter
         (fun (p0, p1) ->
            if p >= p0 && p <= p1 then raise SASLprepError;
         )
         forbidden;
    )
    u;
  u


let is_randalcat c =
  exists
    (fun (c0,c1) -> c >= c0 && c <= c1)
    randalcat


let is_lcat c =
  exists
    (fun (c0,c1) -> c >= c0 && c <= c1)
    lcat


let bidicheck u =
  let u_randalcat =
    Array.map is_randalcat u in
  let u_lcat =
    Array.map is_lcat u in
  let has_randalcat = exists (fun p -> p) u_randalcat in
  let has_lcat = exists (fun p -> p) u_lcat in
  if has_randalcat && has_lcat then raise SASLprepError;
  if has_randalcat && u <> [| |] then (
    if not u_randalcat.(0) || not u_randalcat.(Array.length u - 1) then
      raise SASLprepError
  );
  u


let basecheck u =
  if exists (fun p -> p < 0 || p > 0x10ffff) u then raise SASLprepError;
  ()


let saslprep_a u =
  basecheck u;
  bidicheck ( prohibited (normalize (map u)))


let saslprep s =
  Netconversion.ustring_of_uarray
    `Enc_utf8
    (saslprep_a
       (Netconversion.uarray_of_ustring
          `Enc_utf8
          s
       )
    )
