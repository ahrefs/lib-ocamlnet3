open Printf

(* SASLprep requires Unicode-3.2 *)

let exclusions_file =
  "tmp/CompositionExclusions-3.2.0.txt"

let unicode_file =
  "tmp/UnicodeData-3.2.0.txt"

let hex_re =
  Str.regexp "\\([0-9a-fA-F]+\\)"

let ( ||| ) x y =
  if x<>0 then x else y



let print_array l =
  let first = ref true in
  List.iter
    (fun n ->
       if not !first then printf ";\n     ";
       printf "%d" n;
       first := false;
    )
    l


let print_pairs l =
  let first = ref true in
  List.iter
    (fun (p1,p2) ->
       if not !first then printf ";\n     ";
       printf "(%d,%d)" p1 p2;
       first := false;
    )
    l


let exclusions() =
  let f = open_in exclusions_file in
  let l = ref [] in
  ( try
      while true do
        let line = input_line f in
        if line <> "" && line.[0] <> '#' then (
          if Str.string_match hex_re line 0 then (
            let x = Str.matched_group 1 line in
            let n = int_of_string ("0x" ^ x) in
            l := n :: !l
          )
        )
      done
    with End_of_file -> ()
  );
  printf "let exclusions =\n  [| ";
  print_array (List.rev !l);
  printf " |]\n\n%!";
  close_in f



let semi_re = Str.regexp ";"
let space_re = Str.regexp " "

let decompositions() =
  let f = open_in unicode_file in
  let lnr = ref 1 in
  let cano_classes = ref [] in
  let decomps = ref [] in
  let randalcats = ref [] in
  let lcats = ref [] in
  ( try
      while true do
        let line = input_line f in
        if line <> "" && line.[0] <> '#' then (
          let fields = Array.of_list (Str.split_delim semi_re line) in
          if Array.length fields <> 15 then 
            failwith ("bad data line " ^ string_of_int !lnr);
          let code =
            int_of_string ("0x" ^ fields.(0)) in
          let cano_class =
            int_of_string fields.(3) in
          if cano_class <> 0 then
            cano_classes := (code, cano_class) :: !cano_classes;
          let decomp = fields.(5) in
          let is_compat = decomp <> "" && decomp.[0] = '<' in
          let decomp_words1 = Str.split space_re decomp in
          let decomp_words2 =
            List.filter (fun s -> s.[0] <> '<') decomp_words1 in
          let decomp_chars =
            List.map (fun s -> int_of_string ("0x" ^ s)) decomp_words2 in
          if decomp_chars <> [] then
            decomps := (code, is_compat, decomp_chars) :: !decomps;
          let bidi_cat = fields.(4) in
          if bidi_cat = "R" || bidi_cat = "AL" then (
            match !randalcats with
              | (c0, c1) :: l' when c1 = code-1 ->
                   randalcats := (c0, code) :: l'
              | _ -> 
                   randalcats := (code,code) :: !randalcats
          )
          else if bidi_cat = "L" then (
            match !lcats with
              | (c0, c1) :: l' when c1 = code-1 ->
                   lcats := (c0, code) :: l'
              | _ ->
                   lcats := (code,code) :: !lcats
          )
        );
        incr lnr
      done
    with End_of_file -> ()
  );
  cano_classes :=
    List.sort (fun (code1,c1) (code2,c2) -> c1 - c2 ||| code1-code2) !cano_classes;
  let out_classes = ref [] in
  let last_class = ref 0 in
  List.iter
    (fun (code,cls) ->
       if cls <> !last_class then
         out_classes := (-cls) :: !out_classes;
       out_classes := code :: !out_classes;
       last_class := cls;
    )
    !cano_classes;
  printf "let cano_classes =\n  [| ";
  print_array (List.rev !out_classes);
  printf " |]\n\n%!";
  let out_decomps = ref [] in
  List.iter
    (fun (code, is_compat, decomp_chars) ->
       let out_code = (code lsl 1) lor (if is_compat then 1 else 0) in
       out_decomps := List.rev decomp_chars @ [ -out_code ] @ !out_decomps;
    )
    (List.rev !decomps);
  printf "let decompositions =\n  [| ";
  print_array (List.rev !out_decomps);
  printf " |]\n\n%!";
  printf "let randalcat =\n  [| ";
  print_pairs (List.rev !randalcats);
  printf " |]\n\n%!";
  printf "let lcat =\n  [| ";
  print_pairs (List.rev !lcats);
  printf " |]\n\n%!";
  ()

let map_to_nothing_tab =
  (* RFC 3454, B.1 *)
  [ 0x00AD;
    0x034F;
    0x1806;
    0x180B;
    0x180C;
    0x180D;
    0x200B;
    0x200C;
    0x200D;
    0x2060;
    0xFE00;
    0xFE01;
    0xFE02;
    0xFE03;
    0xFE04;
    0xFE05;
    0xFE06;
    0xFE07;
    0xFE08;
    0xFE09;
    0xFE0A;
    0xFE0B;
    0xFE0C;
    0xFE0D;
    0xFE0E;
    0xFE0F;
    0xFEFF;
  ]

let map_to_nothing() =
  printf "let map_to_nothing =\n  [| ";
  print_array map_to_nothing_tab;
  printf " |]\n\n%!"


let map_to_space_tab =
  (* RFC 3454, C.1.2 *)
  [ 0x00A0;
    0x1680;
    0x2000;
    0x2001;
    0x2002;
    0x2003;
    0x2004;
    0x2005;
    0x2006;
    0x2007;
    0x2008;
    0x2009;
    0x200A;
    0x200B;
    0x202F;
    0x205F;
    0x3000;
  ]

let map_to_space() =
  printf "let map_to_space =\n  [| ";
  print_array map_to_space_tab;
  printf " |]\n\n%!"

let forbidden_tab =
  [ (* RFC 3454, C.2.2: Control *)
    0x0000, 0x001f;
    0x007f, 0x007f;
    0x0080, 0x009f;
    0x06DD, 0x06DD;
    0x070F, 0x070F;
    0x180E, 0x180E;
    0x200C, 0x200D;
    0x2028, 0x2029;
    0x2060, 0x2063;
    0x206A, 0x206F;
    0xFEFF, 0xFEFF;
    0xFFF9, 0xFFFC;
    0x1D173, 0x1D17A;
    (* C.3: Private Use *)
    0xE000, 0xF8FF;
    0xF0000, 0xFFFFD;
    0x100000, 0x10FFFD;
    (* C.4: non-characters *)
    0xFDD0, 0xFDEF;
    0xFFFE, 0xFFFF;
    0x1FFFE, 0x1FFFF;
    0x2FFFE, 0x2FFFF;
    0x3FFFE, 0x3FFFF;
    0x4FFFE, 0x4FFFF;
    0x5FFFE, 0x5FFFF;
    0x6FFFE, 0x6FFFF;
    0x7FFFE, 0x7FFFF;
    0x8FFFE, 0x8FFFF;
    0x9FFFE, 0x9FFFF;
    0xAFFFE, 0xAFFFF;
    0xBFFFE, 0xBFFFF;
    0xCFFFE, 0xCFFFF;
    0xDFFFE, 0xDFFFF;
    0xEFFFE, 0xEFFFF;
    0xFFFFE, 0xFFFFF;
    0x10FFFE, 0x10FFFF; 
    (* C.5. surrogate pairs *)
    0xD800, 0xDFFF;
    (* C.6 Inappropriate for plain text *)
    0xFFF9, 0xFFFD;
    (* C.7 Inappropriate for canonical representation *)
    0x2FF0, 0x2FFB;
    (* C.8 Change display properties or are deprecated *)
    0x0340, 0x0341;
    0x200E, 0x200F;
    0x202A, 0x202E;
    0x206A, 0x206F;
    (* C.9 Tagging characters *)
    0xE0001, 0xE0001;
    0xE0020, 0xE007F;
  ]


let forbidden() =
  printf "let forbidden =\n  [| ";
  print_pairs forbidden_tab;
  printf " |]\n\n%!"


let() =
  printf "(* Generated file! *)\n";
  exclusions();
  decompositions();
  map_to_nothing();
  map_to_space();
  forbidden()




  
