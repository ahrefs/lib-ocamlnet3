(* $Id$ *)

exception Out_of_range
exception Parse_error of int

module Type_name = struct
  type type_name =
    | Bool
    | Integer
    | Enum
    | Real
    | Bitstring
    | Octetstring
    | Null
    | Seq
    | Set
    | OID
    | ROID
    | ObjectDescriptor
    | External
    | Embedded_PDV
    | NumericString
    | PrintableString
    | TeletexString
    | VideotexString
    | VisibleString
    | IA5String
    | GraphicString
    | GeneralString
    | UniversalString
    | BMPString
    | UTF8String
    | CharString
    | UTCTime
    | GeneralizedTime
end


module Value = struct
  type pc = Primitive | Constructed
  type value =
    | Bool of bool
    | Integer of int_value
    | Enum of int_value
    | Real of real_value
    | Bitstring of bitstring_value
    | Octetstring of string
    | Null
    | Seq of value list
    | Set of value list
    | Tagptr of tag_class * int * pc * string * int * int
    | Tag of tag_class * int * pc * value
    | OID of int array
    | ROID of int array
    | ObjectDescriptor of string
    | External of value list
    | Embedded_PDV of value list
    | NumericString of string
    | PrintableString of string
    | TeletexString of string
    | VideotexString of string
    | VisibleString of string
    | IA5String of string
    | GraphicString of string
    | GeneralString of string
    | UniversalString of string
    | BMPString of string
    | UTF8String of string
    | CharString of string
    | UTCTime of time_value
    | GeneralizedTime of time_value

   and tag_class =
     | Universal | Application | Context | Private

   and int_value = string
   and real_value = string
   and bitstring_value = string
   and time_value = U of string | G of string

  let rec equal v1 v2 =
    match (v1, v2) with
      | (Seq s1, Seq s2) ->
           List.length s1 = List.length s2 &&
             List.for_all2 equal s1 s2
      | (Set s1, Set s2) ->
           (* FIXME: compare the set *)
           List.length s1 = List.length s2 &&
             List.for_all2 equal s1 s2
      | (Tag(c1,t1,pc1,sub1), Tag(c2,t2,pc2,sub2)) ->
           c1=c2 && t1=t2 && pc1=pc2 && equal sub1 sub2
      | (Tagptr(c1,t1,pc1,s1,pos1,len1), Tagptr(c2,t2,pc2,s2,pos2,len2)) ->
           c1=c2 && t1=t2 && pc1=pc2 && 
             String.sub s1 pos1 len1 = String.sub s2 pos2 len2
      | (External s1, External s2) ->
           List.length s1 = List.length s2 &&
             List.for_all2 equal s1 s2
      | (Embedded_PDV s1, Embedded_PDV s2) ->
           List.length s1 = List.length s2 &&
             List.for_all2 equal s1 s2
      | _ ->
           v1 = v2


  let get_int_str v = v
  let get_int_b256 v =
    if v = "\000" then
      [| |]
    else
      Array.init (String.length v) (fun k -> Char.code v.[k])

  let get_int64 v =
    match get_int_b256 v with
      | [| |] ->
          0L
      | [| x0 |] ->
          Int64.shift_right (Int64.shift_left (Int64.of_int x0) 56) 56
      | i when Array.length i <= 8 ->
          let x = ref 0L in
          let shift = ref 64 in
          for k = 0 to Array.length i - 1 do
            shift := !shift - 8;
            x := Int64.logor !x (Int64.shift_left (Int64.of_int i.(k)) !shift);
          done;
          Int64.shift_right !x !shift
      | _ ->
          raise Out_of_range

  let max_intL = Int64.of_int max_int
  let min_intL = Int64.of_int min_int

  let max_int32L = Int64.of_int32 (Int32.max_int)
  let min_int32L = Int64.of_int32 (Int32.min_int)

  let get_int v =
    let x = get_int64 v in
    if x > max_intL || x < min_intL then raise Out_of_range;
    Int64.to_int x

  let get_int32 v =
    let x = get_int64 v in
    if x > max_int32L || x < min_int32L then raise Out_of_range;
    Int64.to_int32 x


  let get_real_str v = v

  let get_bitstring_size v =
    let n_unused = Char.code v.[0] in
    (String.length v - 1) * 8 - n_unused

  let get_bitstring_data v =
    String.sub v 1 (String.length v - 1)

  let get_bitstring_bits v =
    let size = get_bitstring_size v in
    Array.init
      size
      (fun k ->
         let p = k lsr 3 in
         let q = k land 7 in
         let x = Char.code v.[ p + 1 ] in
         (x lsl q) land 0x80 <> 0
      )

  let utc_re = Netstring_str.regexp
                 "^\\([0-9][0-9]\\)\
                  \\([0-9][0-9]\\)\
                  \\([0-9][0-9]\\)\
                  \\([0-9][0-9]\\)\
                  \\([0-9][0-9]\\)\
                  \\([0-9][0-9]\\)Z$"

  let gentime_re = Netstring_str.regexp
                     "^\\([0-9][0-9][0-9][0-9]\\)\
                      \\([0-9][0-9]\\)\
                      \\([0-9][0-9]\\)\
                      \\([0-9][0-9]\\)\
                      \\([0-9][0-9]\\)\
                      \\([0-9][0-9]\\)\
                      \\(.[0-9]+\\)?Z$"


  let get_time_str =
    function
    | U s -> s
    | G s -> s

  let get_time =
    function
    | U s ->
        (match Netstring_str.string_match utc_re s 0 with
           | Some m ->
               let y2 = int_of_string (Netstring_str.matched_group m 1 s) in
               let year = if y2 >= 50 then 1950 + y2 else 2000 + y2 in
               let month = int_of_string (Netstring_str.matched_group m 2 s) in
               let day = int_of_string (Netstring_str.matched_group m 3 s) in
               let hour = int_of_string (Netstring_str.matched_group m 4 s) in
               let minute = int_of_string (Netstring_str.matched_group m 5 s) in
               let second = int_of_string (Netstring_str.matched_group m 6 s) in
               if month = 0 || month > 12 || day = 0 || day > 31 ||
                    hour > 23 || minute > 59 || second > 59 
               then
                 failwith "Netasn1.Value.get_time";
               { Netdate.year; month; day; hour; minute; second;
                 nanos = 0; zone = 0; week_day = (-1)
               }
           | None ->
               failwith "Netasn1.Value.get_time"
        )
        
    | G s ->
        (match Netstring_str.string_match gentime_re s 0 with
           | Some m ->
               let year = int_of_string (Netstring_str.matched_group m 1 s) in
               let month = int_of_string (Netstring_str.matched_group m 2 s) in
               let day = int_of_string (Netstring_str.matched_group m 3 s) in
               let hour = int_of_string (Netstring_str.matched_group m 4 s) in
               let minute = int_of_string (Netstring_str.matched_group m 5 s) in
               let second = int_of_string (Netstring_str.matched_group m 6 s) in
               if month = 0 || month > 12 || day = 0 || day > 31 ||
                    hour > 23 || minute > 59 || second > 59 
               then
                 failwith "Netasn1.Value.get_time";
               let nanos =
                 try
                   let n1 = Netstring_str.matched_group m 7 s in
                   let n2 = String.sub n1 1 (String.length n1 - 1) in
                   let n3 = 
                     if String.length n2 > 9 then String.sub n2 0 9 else n2 in
                   let n4 =
                     n3 ^ String.make (9 - String.length n3) '0' in
                   int_of_string n4
                 with Not_found -> 0 in
               { Netdate.year; month; day; hour; minute; second;
                 nanos; zone = 0; week_day = (-1)
               }
           | None ->
               failwith "Netasn1.Value.get_time"
        )
end


let type_of_tag =
  function
    | 1 -> Type_name.Bool
    | 2 -> Type_name.Integer
    | 3 -> Type_name.Bitstring
    | 4 -> Type_name.Octetstring
    | 5 -> Type_name.Null
    | 6 -> Type_name.OID
    | 7 -> Type_name.ObjectDescriptor
    | 8 -> Type_name.External
    | 9 -> Type_name.Real
    | 10 -> Type_name.Enum
    | 11 -> Type_name.Embedded_PDV
    | 12 -> Type_name.UTF8String
    | 13 -> Type_name.ROID
    | 16 -> Type_name.Seq
    | 17 -> Type_name.Set
    | 18 -> Type_name.NumericString
    | 19 -> Type_name.PrintableString
    | 20 -> Type_name.TeletexString
    | 21 -> Type_name.VideotexString
    | 22 -> Type_name.IA5String
    | 23 -> Type_name.UTCTime
    | 24 -> Type_name.GeneralizedTime
    | 25 -> Type_name.GraphicString
    | 26 -> Type_name.VisibleString
    | 27 -> Type_name.GeneralString
    | 28 -> Type_name.UniversalString
    | 29 -> Type_name.CharString
    | 30 -> Type_name.BMPString
    | _ -> raise Not_found




let n_max =
  if Sys.word_size = 32 then
    3
  else
    7


let decode_rel_oid s =
  (* will raise Not_found on parse error *)
  let cur = ref 0 in
  let end_pos = String.length s in
  let l = ref [] in
  while !cur < end_pos do
    let x = ref 0 in
    while s.[ !cur ] >= '\128' do
      x := (!x lsl 7) lor (Char.code s.[ !cur ] - 128);
      incr cur;
      if !cur > end_pos then raise Not_found;
    done;
    x := (!x lsl 7) lor (Char.code s.[ !cur ]);
    l := !x :: !l;
    incr cur;
  done;
  Array.of_list (List.rev !l)



let decode_region ?(pos=0) ?len s =
  let pos_end =
    match len with
      | None -> String.length s
      | Some n -> pos+n in
  (pos, pos_end)


let decode_ber_header ?pos ?len ?(skip_length_check=false) s =
  let pos, pos_end = decode_region ?pos ?len s in
  let cur = ref pos in
  let next() =
    if !cur < pos_end then (
      let c = Char.code s.[!cur] in
      incr cur;
      c
    )
    else
      raise(Parse_error !cur) in
  let id0 = next() in
  let pc = 
    if (id0 land 0x20) <> 0 then Value.Constructed else Value.Primitive in
  let tc =
    match id0 land 0xc0 with
      | 0x00 -> Value.Universal
      | 0x40 -> Value.Application
      | 0x80 -> Value.Context
      | 0xc0 -> Value.Private
      | _ -> assert false in
  let tag0 =
    id0 land 0x1f in
  let tag = (
    if tag0 < 31 then
      tag0
    else (
      let tag = ref 0 in
      let b = ref (next()) in
      let n = ref 1 in
      while !b > 127 do
        incr n;
        if !n = 5 then raise(Parse_error !cur);  (* impl limit *)
        tag := (!tag lsl 7) lor (!b land 0x7f);
        b := next();
      done;
      tag := (!tag lsl 7) lor !b;
      !tag
    )
  ) in
  let length_opt = (
    let l0 = next() in
    if l0 < 128 then
      Some l0
    else (
      let n = l0-128 in
      if n=0 then
        None  (* indefinite length *)
      else (
        if n > n_max then raise(Parse_error !cur); (* impl limit *)
        let l = ref 0 in
        for k = 1 to n do
          l := (!l lsl 8) lor (next())
        done;
        Some !l
      ) 
    )
  ) in
  ( match length_opt with
      | None -> if pc = Value.Primitive then raise(Parse_error !cur)
      | Some n ->
          if not skip_length_check && n > pos_end - !cur then
            raise(Parse_error !cur)
  );
  let hdr_len = !cur - pos in
  (hdr_len, tc, pc, tag, length_opt)


let rec decode_ber_length ?pos ?len s =
  let pos, pos_end = decode_region ?pos ?len s in
  let (hdr_len, tc, pc, tag, length_opt) =
    decode_ber_header ~pos ~len:(pos_end - pos) s in
  match length_opt with
    | Some n ->
        hdr_len + n
    | None ->
        let cur = ref (pos + hdr_len) in
        let at_end_marker() =
          !cur+2 <= pos_end && 
            s.[ !cur ] = '\000' && s.[ !cur+1 ] = '\000' in
        while not (at_end_marker()) do
          assert(!cur < pos_end);
          let n = decode_ber_length ~pos:!cur ~len:(pos_end - !cur) s in
          cur := !cur + n;
        done;
        (!cur - pos) + 2


let rec decode_homo_construction f pos pos_end indefinite expected_tag s =
  (* A construction where the primitives have all the same tag. The
     depth is arbitrary. [f] is called for every found primitive.
   *)
  let cur = ref pos in
  let at_end() =
    if indefinite then
      !cur+2 <= pos_end && 
        s.[ !cur ] = '\000' && s.[ !cur+1 ] = '\000'
    else
      !cur = pos_end in
  while not (at_end()) do
    assert(!cur < pos_end);
    let (hdr_len, tc, pc, tag, length_opt) =
      decode_ber_header ~pos:!cur ~len:(pos_end - !cur) s in
    if tc <> Value.Universal then raise (Parse_error !cur);
    if tag <> expected_tag then raise (Parse_error !cur);
    ( match pc with
        | Value.Primitive ->
            let n =
              match length_opt with
                | None -> assert false
                | Some n -> n in
            f (!cur + hdr_len) n;
            cur := !cur + hdr_len + n
        | Value.Constructed ->
            let sub_pos_end =
              match length_opt with
                | None -> pos_end
                | Some n -> !cur + hdr_len + n in
            let real_n =
              decode_homo_construction
                f (!cur + hdr_len) sub_pos_end
                (length_opt = None) expected_tag s in
            ( match length_opt with
                | None -> ()
                | Some n -> if n <> real_n then raise (Parse_error !cur)
            );
            cur := !cur + hdr_len + real_n
    );
  done;
  if indefinite then cur := !cur + 2;
  if not indefinite && !cur <> pos_end then raise (Parse_error !cur);
  !cur - pos


let rec decode_ber ?pos ?len s =
  let pos, pos_end = decode_region ?pos ?len s in
  let (hdr_len, tc, pc, tag, length_opt) =
    decode_ber_header ~pos ~len:(pos_end - pos) s in
  match tc with
    | Value.Universal ->
        let cur = pos + hdr_len in
        let ty_name = 
          try type_of_tag tag
          with Not_found -> raise(Parse_error cur) in
        let len =
          match length_opt with
            | None -> pos_end - cur
            | Some n -> n in
        let content_len, value =
          decode_ber_contents
            ~pos:cur
            ~len
            ~indefinite:(length_opt = None)
            s pc ty_name in
        ( match length_opt with
            | None -> ()
            | Some n ->
                if content_len <> n then raise(Parse_error cur)
        );
        (content_len + hdr_len, value)
    | _ ->
        let content_len =
          match length_opt with
            | None -> 
                decode_ber_length ~pos ~len:(pos_end - pos) s - hdr_len - 2
            | Some n -> n in
        let value =
          Value.Tagptr(tc, tag, pc, s, pos+hdr_len, content_len) in
        (content_len + hdr_len, value)


and decode_ber_contents ?pos ?len ?(indefinite=false) s pc ty =
  let pos, pos_end = decode_region ?pos ?len s in
  let len = pos_end - pos in
  if indefinite && pc=Value.Primitive then
    invalid_arg "Netasn1.decode_ber_contents: only constructed values \
                 permit indefinite length";
  match ty with
    | Type_name.Null ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        if len<>0 then raise(Parse_error pos);
        (0, Value.Null)
    | Type_name.Bool ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        if len=0 then raise(Parse_error pos);
        let v = Value.Bool( s.[pos] <> '\000' ) in
        (1, v)
    | Type_name.Integer ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        if len=0 then raise(Parse_error pos);
        let u = String.sub s pos len in
        (* FIXME: value check *)
        let v = Value.Integer u in
        (len, v)
    | Type_name.Enum ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        if len=0 then raise(Parse_error pos);
        let u = String.sub s pos len in
        (* FIXME: value check *)
        let v = Value.Enum u in
        (len, v)
    | Type_name.Real ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        let u = String.sub s pos len in
        (* FIXME: value check *)
        let v = Value.Real u in
        (len, v)
    | Type_name.OID ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        let u = String.sub s pos len in
        let r = 
          try decode_rel_oid u
          with Not_found -> raise(Parse_error pos) in
        if Array.length r < 1 then raise(Parse_error pos);
        let x = if r.(0) < 40 then 0 else if r.(0) < 80 then 1 else 2 in
        let y = if x < 2 then r.(0) mod 40 else r.(0) - 80 in
        let oid = 
          Array.append [| x; y |] (Array.sub r 1 (Array.length r - 1)) in
        let v = Value.OID oid in
        (len, v)
    | Type_name.ROID ->
        if pc <> Value.Primitive then raise(Parse_error pos);
        let u = String.sub s pos len in
        let r = 
          try decode_rel_oid u
          with Not_found -> raise(Parse_error pos) in
        let v = Value.ROID r in
        (len, v)
    | Type_name.Octetstring ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.Octetstring octets)
    | Type_name.ObjectDescriptor ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.ObjectDescriptor octets)
    | Type_name.UTF8String ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.UTF8String octets)
    | Type_name.NumericString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.NumericString octets)
    | Type_name.PrintableString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.PrintableString octets)
    | Type_name.TeletexString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.TeletexString octets)
    | Type_name.VideotexString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.VideotexString octets)
    | Type_name.IA5String ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.IA5String octets)
    | Type_name.GraphicString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.GraphicString octets)
    | Type_name.VisibleString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.VisibleString octets)
    | Type_name.GeneralString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.GeneralString octets)
    | Type_name.UniversalString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.UniversalString octets)
    | Type_name.CharString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.CharString octets)
    | Type_name.BMPString ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.BMPString octets)
    | Type_name.UTCTime ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.UTCTime (Value.U octets))
    | Type_name.GeneralizedTime ->
        let (len, octets) = decode_ber_octets pos pos_end indefinite s pc in
        (len, Value.GeneralizedTime (Value.G octets))
    | Type_name.Bitstring ->
        let (len, bitstring) = decode_ber_bits pos pos_end indefinite s pc in
        (len, Value.Bitstring bitstring)
    | Type_name.Seq ->
        if pc <> Value.Constructed then raise(Parse_error pos);
        let (len, list) = decode_list_construction pos pos_end indefinite s in
        (len, Value.Seq list)
    | Type_name.Set ->
        if pc <> Value.Constructed then raise(Parse_error pos);
        let (len, list) = decode_list_construction pos pos_end indefinite s in
        (len, Value.Set list)
    | Type_name.External ->
        if pc <> Value.Constructed then raise(Parse_error pos);
        let (len, list) = decode_list_construction pos pos_end indefinite s in
        (len, Value.External list)
    | Type_name.Embedded_PDV ->
        if pc <> Value.Constructed then raise(Parse_error pos);
        let (len, list) = decode_list_construction pos pos_end indefinite s in
        (len, Value.Embedded_PDV list)


        
and decode_ber_octets pos pos_end indefinite s pc =
  let len = pos_end - pos in
  match pc with
    | Value.Primitive ->
        (len, String.sub s pos len)
    | Value.Constructed ->
        let buf = Buffer.create 500 in
        let f p l =
          Buffer.add_substring buf s p l in
        let n =
          decode_homo_construction
            f pos pos_end indefinite 4 s in
        (n, Buffer.contents buf)

and decode_ber_bits pos pos_end indefinite s pc =
  let len = pos_end - pos in
  match pc with
    | Value.Primitive ->
        if len = 0 then raise(Parse_error pos);
        let c0 = s.[pos] in
        if c0 >= '\008' || (len = 1 && c0 <> '\000') then
          raise(Parse_error pos);
        (len, String.sub s pos len)
    | Value.Constructed ->
        let c0_prev = ref '\000' in
        let buf = Buffer.create 500 in
        Buffer.add_char buf '\000';
        let f p l =
          if !c0_prev <> '\000' then raise(Parse_error pos);
          if l = 0 then raise(Parse_error pos);
          let c0 = s.[p] in
          if c0 >= '\008' || (l = 1 && c0 <> '\000') then
            raise(Parse_error pos);
          c0_prev := c0;
          Buffer.add_substring buf s (p+1) (l-1) in
        let n =
          decode_homo_construction
            f pos pos_end indefinite 3 s in
        let bitstring = Buffer.contents buf in
        bitstring.[0] <- !c0_prev;
        (n, bitstring)

and decode_list_construction pos pos_end indefinite s =
  let acc = ref [] in
  let cur = ref pos in
  let at_end() =
    if indefinite then
      !cur+2 <= pos_end && 
        s.[ !cur ] = '\000' && s.[ !cur+1 ] = '\000'
    else
      !cur = pos_end in
  while not(at_end()) do
    assert(!cur < pos_end);
    let (ber_len, value) =
      decode_ber ~pos:!cur ~len:(pos_end - !cur) s in
    acc := value :: !acc;
    cur := !cur + ber_len;
  done;
  if indefinite then cur := !cur + 2;
  if not indefinite && !cur <> pos_end then raise (Parse_error !cur);
  (!cur - pos, List.rev !acc)
