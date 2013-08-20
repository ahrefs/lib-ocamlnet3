#directory "+compiler-libs"
(* only for Btype.hash_variant *)

#load "str.cma"
#load "ocamlcommon.cma"

open Printf

let p1_re = Str.regexp "^\\(.*\\)(\\(.*\\))"
let p2_re = Str.regexp "[ \t]*,[ \t]*"
let p3_re = Str.regexp "[ \t]+"

let parse decl =
  try
    if Str.string_match p1_re decl 0 then (
      let part1 = Str.matched_group 1 decl in
      let part2 = Str.matched_group 2 decl in
      let result_name = Str.split p2_re part1 in
      let params =
        List.map
          (fun param_s ->
             let l = Str.split p3_re param_s in
             let n = List.hd (List.rev l) in
             let ty = List.rev (List.tl (List.rev l)) in
             (n, String.concat " " ty)
          )
          (Str.split p3_re part2) in
      let name = List.hd (List.rev result_name) in
      let result = List.rev (List.tl (List.rev result_name)) in
      (name, String.concat " " result, params)
    )
    else raise Not_found
  with
    | Not_found ->
         failwith ("Parse error: " ^ decl)


let has_prefix ~prefix s =
  let l1 = String.length s in
  let l2 = String.length prefix in
  l2 <= l1 && String.sub s 0 l2 = prefix


type abs_ptr =
    { abs_free_fn : string }

let abstract_ptr abs_free_fn =
  `Abstract_ptr { abs_free_fn }

(**********************************************************************)
(* Abstract_enum                                                      *)
(**********************************************************************)

let gen_abstract_enum c mli ml tyname =
  fprintf mli "type %s\n" tyname;
  fprintf ml "type %s\n" tyname;

  fprintf c "/************** %s *************/\n\n" tyname;
  fprintf c "struct enumstruct_%s { %s value; long oid; };\n\n" tyname tyname;
  fprintf c "#define enumstructptr_%s_val(v) \
             ((struct enumstruct_%s *) (Data_custom_val(v)))\n" tyname tyname;
  fprintf c "#define enum_%s_unwrap(v) \
             (enumstructptr_%s_val(v)->value)\n" tyname tyname;
  fprintf c "long enum_%s_oid = 0;\n" tyname;

  fprintf c "\n";
  fprintf c "static int enum_%s_compare(value v1, value v2) {\n" tyname;
  fprintf c "  struct enumstruct_%s *p1;\n" tyname;
  fprintf c "  struct enumstruct_%s *p2;\n" tyname;
  fprintf c "  p1 = enumstructptr_%s_val(v1);\n" tyname;
  fprintf c "  p2 = enumstructptr_%s_val(v2);\n" tyname;
  fprintf c "  return p1->oid - p2->oid;\n";
  fprintf c "}\n\n";

  fprintf c "static struct custom_operations enum_%s_ops = {\n" tyname;
  fprintf c "  \"\",\n";
  fprintf c "  custom_finalize_default,\n";
  fprintf c "  enum_%s_compare,\n" tyname;
  fprintf c "  custom_hash_default,\n";
  fprintf c "  custom_serialize_default,\n";
  fprintf c "  custom_deserialize_default\n";
  fprintf c "};\n\n";

  fprintf c "static value enum_%s_wrap(%s x) {\n" tyname tyname;
  fprintf c "  value v;\n";
  fprintf c "  v = caml_alloc_custom(&enum_%s_ops, \
                                     sizeof(struct enumstruct_%s), 0, 1);\n"
         tyname tyname;
  fprintf c "  enumstructptr_%s_val(v)->value = x;\n" tyname;
  fprintf c "  enumstructptr_%s_val(v)->oid = enum_%s_oid++;\n" tyname tyname;
  fprintf c "  return v;\n";
  fprintf c "}\n\n";

  ()

(**********************************************************************)
(* Abstract_ptr                                                       *)
(**********************************************************************)

let gen_abstract_ptr c mli ml tyname abs =
  fprintf mli "type %s\n" tyname;
  fprintf ml "type %s\n" tyname;

  fprintf c "/************** %s *************/\n\n" tyname;
  fprintf c "struct absstruct_%s { %s value; long oid; };\n\n" tyname tyname;
  fprintf c "#define absstructptr_%s_val(v) \
             ((struct absstruct_%s *) (Data_custom_val(v)))\n" tyname tyname;
  fprintf c "#define abs_%s_unwrap(v) \
             (absstructptr_%s_val(v)->value)\n" tyname tyname;
  fprintf c "long abs_%s_oid = 0;\n" tyname;

  fprintf c "\n";
  fprintf c "static int abs_%s_compare(value v1, value v2) {\n" tyname;
  fprintf c "  struct absstruct_%s *p1;\n" tyname;
  fprintf c "  struct absstruct_%s *p2;\n" tyname;
  fprintf c "  p1 = absstructptr_%s_val(v1);\n" tyname;
  fprintf c "  p2 = absstructptr_%s_val(v2);\n" tyname;
  fprintf c "  return p1->oid - p2->oid;\n";
  fprintf c "}\n\n";

  fprintf c "static void abs_%s_finalize(value v1) {\n" tyname;
  fprintf c "  struct absstruct_%s *p1;\n" tyname;
  fprintf c "  p1 = absstructptr_%s_val(v1);\n" tyname;
  fprintf c "  %s(p1->value);\n" abs.abs_free_fn;
  fprintf c "}\n\n";

  fprintf c "static struct custom_operations abs_%s_ops = {\n" tyname;
  fprintf c "  \"\",\n";
  fprintf c "  abs_%s_finalize,\n" tyname;
  fprintf c "  abs_%s_compare,\n" tyname;
  fprintf c "  custom_hash_default,\n";
  fprintf c "  custom_serialize_default,\n";
  fprintf c "  custom_deserialize_default\n";
  fprintf c "};\n\n";

  fprintf c "static value abs_%s_wrap(%s x) {\n" tyname tyname;
  fprintf c "  value v;\n";
  fprintf c "  v = caml_alloc_custom(&abs_%s_ops, \
                                     sizeof(struct absstruct_%s), 0, 1);\n"
         tyname tyname;
  fprintf c "  absstructptr_%s_val(v)->value = x;\n" tyname;
  fprintf c "  absstructptr_%s_val(v)->oid = abs_%s_oid++;\n" tyname tyname;
  fprintf c "  return v;\n";
  fprintf c "}\n\n";

  ()

(**********************************************************************)
(* Enum                                                               *)
(**********************************************************************)

let vert_re = Str.regexp "[|]"

let c_name_of_enum n =
  Str.replace_first vert_re "" n

let ml_name_of_enum n =
  try
    let l = String.length n in
    let p = String.index n '|' in
    String.capitalize (String.lowercase (String.sub n (p+1) (l-p-1)))
  with
    | Not_found ->
         String.capitalize (String.lowercase n)


let gen_enum c mli ml tyname cases =
  List.iter
    (fun f ->
       fprintf f "type %s =\n" tyname;
       fprintf f "  [ ";
       let first = ref true in
       List.iter
         (fun case ->
            if not !first then fprintf f "  | ";
            first := false;
            fprintf f "`%s\n" (ml_name_of_enum case)
         )
         cases;
       fprintf f "  ]\n";
    )
    [ mli; ml ];

  fprintf c "/************** %s *************/\n\n" tyname;
  fprintf c "static value enum_%s_wrap(%s x) {\n" tyname tyname;
  fprintf c "  switch (x) {\n";
  List.iter
    (fun case ->
       let n1 = c_name_of_enum case in
       let n2 = ml_name_of_enum case in
       let h = Btype.hash_variant n2 in
       fprintf c "    case %s: return Val_long(%d);\n"
               n1 h;
    )
    cases;
  fprintf c "  };\n";
  fprintf c "  failwith(\"abs_%s_wrap: unexpected value\");\n" tyname;
  fprintf c "}\n\n";

  fprintf c "static %s enum_%s_unwrap(value v) {\n" tyname tyname;
  fprintf c "  switch (Long_val(v)) {\n";
  List.iter
    (fun case ->
       let n1 = c_name_of_enum case in
       let n2 = ml_name_of_enum case in
       let h = Btype.hash_variant n2 in
       fprintf c "    case %d: return %s;\n"
               h n1;
    )
    cases;
  fprintf c "  };\n";
  fprintf c "  failwith(\"abs_%s_unwrap: unexpected value\");\n" tyname;
  fprintf c "}\n\n";

  ()

(**********************************************************************)
(* Flags                                                              *)
(**********************************************************************)

let gen_flags c mli ml tyname cases =
  List.iter
    (fun f ->
       fprintf f "type %s_flag =\n" tyname;
       fprintf f "  [ ";
       let first = ref true in
       List.iter
         (fun case ->
            if not !first then fprintf f "  | ";
            first := false;
            fprintf f "`%s\n" (ml_name_of_enum case)
         )
         cases;
       fprintf f "  ]\n";
       fprintf f "type %s = %s_flag list\n" tyname tyname;
    )
    [ mli; ml ];

  fprintf c "/************** %s *************/\n\n" tyname;
  fprintf c "static value flags_%s_wrap(%s x) {\n" tyname tyname;
  fprintf c "  CAMLparam0();\n";
  fprintf c "  CAMLlocal2(v,u);\n";
  fprintf c "  v = Val_long(0);\n";
  List.iter
    (fun case ->
       let n1 = c_name_of_enum case in
       let n2 = ml_name_of_enum case in
       let h = Btype.hash_variant n2 in
       fprintf c "  if (x & %s) {\n" n1;
       fprintf c "    u = caml_alloc(2,0);\n";
       fprintf c "    Field(u, 0) = Val_long(%d);\n" h;
       fprintf c "    Field(u, 1) = v;\n";
       fprintf c "    v = u;\n";
       fprintf c "  };\n";
    )
    cases;
  fprintf c "  CAMLreturn(v);\n";
  fprintf c "}\n\n";

  fprintf c "static %s flags_%s_unwrap(value v) {\n" tyname tyname;
  fprintf c "  %s x = 0;\n" tyname;
  fprintf c "  while (Is_block(v)) {\n";
  fprintf c "    switch (Long_val(Field(v,0))) {\n";
  List.iter
    (fun case ->
       let n1 = c_name_of_enum case in
       let n2 = ml_name_of_enum case in
       let h = Btype.hash_variant n2 in
       fprintf c "      case %d: x |= %s; break;\n"
               h n1;
    )
    cases;
  fprintf c "    };\n";
  fprintf c "    v = Field(v,1);\n";
  fprintf c "  };\n";
  fprintf c "  return x;\n";
  fprintf c "}\n\n";

  ()

(**********************************************************************)

let gen_c_head c =
  fprintf c "#include <stdlib.h>\n\
             #include <stdio.h>\n\
             #include <string.h>\n\
             \n\
             #include \"caml/mlvalues.h\"\n\
             #include \"caml/alloc.h\"\n\
             #include \"caml/memory.h\"\n\
             #include \"caml/misc.h\"\n\
             #include \"caml/custom.h\"\n\
             #include \"caml/fail.h\"\n\
             #include \"caml/unixsupport.h\"\n\
             #include \"caml/callback.h\"\n\
             \n"


let generate ?(c_head="") ~modname ~types ~functions() =
  let c_name = modname ^ "_stubs.c" in
  let ml_name = modname ^ ".ml" in
  let mli_name = modname ^ ".mli" in
  let to_close = ref [] in
  try
    let c = open_out c_name in
    to_close := (fun () -> close_out_noerr c) :: !to_close;
    let ml = open_out ml_name in
    to_close := (fun () -> close_out_noerr ml) :: !to_close;
    let mli = open_out mli_name in
    to_close := (fun () -> close_out_noerr mli) :: !to_close;

    gen_c_head c;
    fprintf c "%s\n" c_head;

    List.iter
      (fun (tyname,tydecl) ->
         match tydecl with
           | `Abstract_enum ->
                gen_abstract_enum c mli ml tyname
           | `Abstract_ptr abs ->
                gen_abstract_ptr c mli ml tyname abs
           | `Enum cases ->
                gen_enum c mli ml tyname cases
           | `Flags cases ->
                gen_flags c mli ml tyname cases
           | _ ->
                ()
      )
      types;

    close_out c;
    close_out ml;
    close_out mli
  with
    | error ->
         List.iter
           (fun f -> f())
           !to_close;
         List.iter
           (fun n -> try Sys.remove n with _ -> ())
           [ c_name; ml_name; mli_name ];
         raise error

