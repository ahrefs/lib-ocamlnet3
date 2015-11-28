(* $Id$ *)

let dir = ref Netuniconfig.net_db_dir

let enable() =
  Netdb.enable_db_loaders true

let disable() =
  Netdb.enable_db_loaders false

let net_db_dir() =
  !dir

let set_net_db_dir d =
  dir := d

let load_file key =
  let filename = Filename.concat !dir key ^ ".netdb" in
  if Sys.file_exists filename then (
    let ch = open_in_bin filename in
    try
      let n = in_channel_length ch in
      let v = Bytes.make n '\000' in
      really_input ch v 0 n;
      close_in ch;
      Bytes.unsafe_to_string v
    with exn ->
      close_in ch;
      raise exn
  )
  else
    failwith ("Ocamlnet: Cannot find the lookup table `" ^ key ^ 
		"' which is supposed to be available as file " ^ 
		  filename)

let load key =
  let s = Netdb.read_db key in
  Netdb.set_db key s


let load_charset cs =
  let n = Netconversion.internal_name cs in
  load("cmapf." ^ n);
  load("cmapr." ^ n)
