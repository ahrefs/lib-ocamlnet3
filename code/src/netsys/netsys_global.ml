(* $Id$ *)

type variable =
    { var_name : string;
      var_value : (string * int64) ref;
    }

class type propagator =
  object
    method propagate : string -> string -> int64
    method update : string -> int64 -> (string * int64) option
  end

type store =
    { table : (string,variable) Hashtbl.t;
      mutex : Netsys_oothr.mutex;
      mutable prop : propagator option;
    }

let globals = ref (None : store option)

let get_store() =
  match !globals with
    | None ->
        let st =
          { table = Hashtbl.create 51;
            mutex = !Netsys_oothr.provider # create_mutex();
            prop = None
          } in
        Netsys_oothr.atomic_init globals st
    | Some st ->
        st

let access name =
  let s = get_store() in
  Netsys_oothr.serialize
    s.mutex
    (fun () ->
       try
         Hashtbl.find s.table name
       with Not_found ->
         let var = { var_name = name; var_value = ref ("", 0L) } in
         Hashtbl.add s.table name var;
         var
    )
    ()

let rec get_v var =
  let s = get_store() in
  ( match s.prop with
      | None ->
          !(var.var_value)
      | Some p ->
          let old = !(var.var_value) in
          let old_value, old_version = old in
          ( match p # update var.var_name old_version with
              | None ->
                  old
              | Some(new_value,new_version) ->
                  let n = (new_value, new_version) in
                  let ok =
                    Netsys_oothr.compare_and_swap
                      var.var_value
                      old
                      n in
                  if ok then
                    n
                  else
                    get_v var
          )
  )

let get var =
  fst(get_v var)

let rec set_local var new_value =
  let old = !(var.var_value) in
  let (_, old_version) = old in
  let new_version = Int64.succ old_version in
  let n = (new_value, new_version) in
  let ok =
    Netsys_oothr.compare_and_swap
      var.var_value
      old
      n in
  if ok then
    new_version
  else
    set_local var new_value

let rec set_v var new_value =
  let s = get_store() in
  ( match s.prop with
      | None ->
          set_local var new_value
      | Some p ->
          let new_version = p # propagate var.var_name new_value in
          var.var_value := (new_value, new_version);
          new_version
  )

let set var new_value =
  ignore(set_v var new_value)

let get_propagator() =
  let s = get_store() in
  s.prop

let set_propagator p_opt =
  let s = get_store() in
  s.prop <- p_opt

let iter f =
  let s = get_store() in
  Hashtbl.iter
    (fun name var ->
       let (value,version) = !(var.var_value) in
       f name value version
    )
    s.table

let internal_set name value version =
  let var = access name in
  var.var_value := (value,version)
