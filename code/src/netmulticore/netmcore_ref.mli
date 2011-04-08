(* $Id$ *)

(** Shared mutable variables *)

type 't sref

val sref : Netmcore.res_id -> 't -> 't sref
  (** The shared version of [ref]: Creates a mutable shared variable in
      the give memory pool
   *)

val assign : 't sref -> 't -> unit
  (** [assign sr x]: Sets the contents of [sr] to a deep copy of [x].
      While performing the assignment the heap is write-locked,
      and no other [assign] can run.
   *)

val deref : 't sref -> 't
  (** Dereferences the variable and returns the contents, comparable to
      [!]. Note that this returns a value that lives in shared memory,
      and there is no guarantee that this value still exists if 
      [assign] operations are done in parallel, and old version are
      garbage-collected.
   *)

val deref_p : 't sref -> ('t -> 'a) -> 'a
  (** [deref_p sr f]: Runs [f] with the contents of [sr], and returns
      the result of [f]. While [f] is being executed, the current contents
      are specially protected so that they cannot be garbage collected,
      even if a parallel [assign] changes the current value of the 
      variable. (Suffix "_p" = pinning version.)
   *)

val deref_c : 't sref -> 't
  (** [deref_c sr]: Returns a copy of the contents of [sr]. The copy is
      created in normal memory. (Suffix "_c" = copying version.)
   *)

val heap : 't sref -> Obj.t Netmcore_heap.heap
  (** Returns the backing heap structure *)
