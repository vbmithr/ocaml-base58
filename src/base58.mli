(**************************************************************************)
(*                                                                        *)
(*    Copyright (c) 2014 - 2016.                                          *)
(*    Dynamic Ledger Solutions, Inc. <contact@tezos.com>                  *)
(*                                                                        *)
(*    All rights reserved. No warranty, explicit or implicit, provided.   *)
(*                                                                        *)
(**************************************************************************)

module Alphabet : sig
  type t

  val bitcoin : t
  val ripple : t
  val flickr : t
  val default : t
  (** [default] is [bitcoin]. *)
end

type t = [`Base58 of string]
(** Type of Base58Check encoded data. *)

val pp : Format.formatter -> t -> unit

val of_bytes : ?alphabet:Alphabet.t -> string -> t
(** [of_bytes ?alphabet bytes] is the Base58Check encoding of [bytes]
    using alphabet [?alphabet]. *)

val to_bytes : ?alphabet:Alphabet.t -> t -> string option
(** [to_bytes ?alphabet t] is [Some data] if [t] is a valid
    Base58Check encoding of [data] (with correct checksum), or [None]
    otherwise. *)

val to_bytes_exn : ?alphabet:Alphabet.t -> t -> string
(** See [to_bytes].

    @raises [Invalid_argument] on checksum failure. *)

val of_string : string -> t option
(** [of_string b58] is [`Base58 b58] if b58 is a valid Base58Check
    encoding. *)

val of_string_exn : string -> t
(** See [of_string].

    @raises [Invalid_argument] if the first argument is not a valid
    Base58Check encoding. *)

val to_string : t -> string
(** [to_string [`Base58 b58] is [b58]. *)
