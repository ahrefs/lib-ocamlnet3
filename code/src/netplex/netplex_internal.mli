(* $Id$ *)

(** Internal services *)

(** Internal services are available to multi-threaded programs only, and
    implemented via {!Netsys_polysocket}.

    See below for an introduction.
 *)

val register_server : string -> Netplex_types.polyserver_box -> unit
  (** [register_server name server]: registers a server under the given
      [name]. It is an error if a server is already registered for the
      same name.

      The registration is thread-safe.
   *)

val connect_client :
      'a Netplex_types.kind_check ->
      int -> string ->
        'a Netsys_polysocket.polyclient
  (** [connect_client is_kind n name]: Creates a new polyclient that is
      connected to the registered service [name]. The arg [is_kind] determines 
      the type of the messages that can be exchanged. The number [n] is the
      size of the pipe buffer, in number of messages.

      The function fails if the service is not registered, or assumes the wrong
      message kind.

      The client lookup is thread-safe.

      Example how to invoke a service exchanging strings (kind [Tstring]):
      {[
let same : type s t . s polysocket_kind * t polysocket_kind -> (s,t) eq =
  function
  | Tstring, Tstring -> Equal
  | _ -> Not_equal

let client =
  Netplex_internal.connect_client
    { Netplex_types.kind_check = fun k -> same(Tstring,k) }
    n
    "name"
      ]}

      (You should strictly stick to this pattern. Any abbreviation will probably
      not type-check.)
   *)


(** {2:intro How to configure and use internal services}

Internal services are a fast mechanism to invoke containers from other
containers. So far, internal services are only available for multi-threaded
programs. The messages can have any type.

You add an internal service by configuring an address "internal" in the
protocol section of the configuration file, e.g.

{[
protocol {
  name = "my-protocol";
  address {
    type = "internal";
    name = "my-identifier";
  }
  address {                    (* other addresses ok *)
    ...
  }
}
]}

The internal service is only activated when multi-threading is selected.
In programs using multi-processing the internal service is simply ignored.

You need to choose the types of your messages. There is the GADT
{!Netplex_types.polysocket_kind} listing possible types. It comes with
the variants [Txdr] (for RPC messaging) and [Tstring] (for any custom strings):

{[
type _ polysocket_kind = ..
type _ polysocket_kind +=
   | Txdr : Netxdr.xdr_value polysocket_kind
   | Tstring : string polysocket_kind
]}

This is an extensible GADT, i.e. you can add more variants with the "+="
notation. (Note that extensible variants are first available since
OCaml-4.02. With older OCaml versions, you cannot extend more variants.)

Let's add integers:

{[
type _ polysocket_kind +=
  | Tint : int polysocket_kind
]}

The connections to the internal services do not arrive via the normal
[process] mechanism. There is a second path using the new processor
hooks [config_internal] and [process_internal]. The hook [config_internal]
defines which message type you are really using. The hook [process_internal]
is invoked when a new connection to the internal service is established.
It works very much like [process], only that it doesn't use file descriptors
but so-called polysockets (see {!Netsys_polysocket}).

{[
class hello_world_processor hooks : processor =
object(self)
  inherit Netplex_kit.processor_base hooks

  method config_internal =
     [ "my-protocol", Polysocket_kind_box Tint ]

  method process_internal ~when_done container srvbox proto_name =
    let Polyserver_box(kind, srv) = srvbox in
    match kind with
      | Tint ->
         let endpoint = Netsys_polysocket.accept ~nonblock:false srv in
         (* Now send and receive messages over endpoint *)
         ...;
         when_done()
      | _ ->
         failwith "wrong kind"

  method process ~when_done container fd proto_name =
    (* this is still invoked when non-internal connections arrive *)
    ...
  method supported_ptypes = 
    ...
end
]}

The [endpoint] is actually a pair of polypipes ({!Netsys_polypipe}):

{[
let (rd, wr) = endpoint
]}

Over [rd] you receive messages of type [int] from the client, and via
[wr] you can send messages to it.

Use {!Netplex_internal.connect_client} to get a client (usually in a
different container, or in an arbitrary other thread):

{[
let same : type s t . s polysocket_kind * t polysocket_kind -> (s,t) eq =
  function
  | Tint, Tint -> Equal
  | _ -> Not_equal

let client =
  Netplex_internal.connect_client
    { Netplex_types.kind_check = fun k -> same(Tint,k) }
    5
    "my-identifier" in
let client_endpoint =
   Netsys_polysocket.endpoint ~synchronous:true ~nonblock:false client
]}

Again, the endpoint is a pair of polypipes in reality:

{[
let (client_rd, client_wr) = client_endpoint
]}

{3 Complete example}

You find a complete example in the distribution tarball at
[code/examples/netplex/internal_service.ml].



{2 Using internal services via RPC}

RPC clients and servers have now support for polysockets. Note that
you need to select [Txdr] as message kind. The messages are not serialized
into strings, but instead the structured XDR format is used as transport
encoding.

XXX TODO

 *)


