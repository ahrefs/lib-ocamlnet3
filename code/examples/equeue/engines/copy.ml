(* Copies from stdin to stdout *)

#use "topfind";;
#require "equeue";;

let main() =
  let e = Unixqueue.create_unix_event_system() in
  let _cp = new Uq_transfer.copier (`Unidirectional(Unix.stdin,Unix.stdout)) e in
  Unixqueue.run e
;;


main();;
