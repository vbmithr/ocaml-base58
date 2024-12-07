(**************************************************************************)
(*                                                                        *)
(*    Copyright (c) 2014 - 2016.                                          *)
(*    Dynamic Ledger Solutions, Inc. <contact@tezos.com>                  *)
(*                                                                        *)
(*    All rights reserved. No warranty, explicit or implicit, provided.   *)
(*                                                                        *)
(**************************************************************************)

module type CRYPTO = sig
  val sha256 : string -> string
end

module Alphabet : sig
  type t

  val bitcoin : t
  val ripple : t
  val flickr : t
  val default : t
  (** [default] is [bitcoin]. *)
end

type t = [`Base58 of string]
type base58 = t
(** Type of Base58Check encoded data. *)

val compare : t -> t -> int
val equal : t -> t -> bool
val (=) : t -> t -> bool

val pp : Format.formatter -> t -> unit
val show : t -> string

val to_string : t -> string
(** [to_string [`Base58 b58]] is [b58]. *)

val raw_encode : ?alphabet:Alphabet.t -> string -> string
(** Encode a string, without adding a checksum *)

module Checksummed (_ : CRYPTO) : sig
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

  val of_string : ?alphabet:Alphabet.t -> string -> t option
  (** [of_string b58] is [`Base58 b58] if b58 is a valid Base58Check
      encoding. *)

  val of_string_exn : ?alphabet:Alphabet.t -> string -> t
  (** See [of_string].

      @raises [Invalid_argument] if the first argument is not a valid
      Base58Check encoding. *)
end

(** {1 Tezos prefixes} *)

module Tezos (_ : CRYPTO) : sig
  type version =
    | Block
    | Operation
    | Protocol
    | Address
    | Peer
    | Public_key
    | Secret_key
    | Signature

  type t = private {
    version : version ;
    payload : string ;
  }

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val (=) : t -> t -> bool

  val pp : Format.formatter -> t -> unit
  val show : t -> string

  val create : version:version -> payload:string -> t

  val of_base58     : base58 -> t option
  val of_base58_exn : base58 -> t
  val to_base58     : t -> base58

  val of_string     : string -> t option
  val of_string_exn : string -> t
  val to_string     : t -> string

  module Set : Set.S with type elt := t
  module Map : Map.S with type key := t
end

(** {1 Bitcoin, or one-byte prefixes only} *)

module Bitcoin (_ : CRYPTO) : sig
  type version =
    | P2PKH
    | P2SH
    | Namecoin_P2PKH
    | Privkey
    | BIP32_priv
    | BIP32_pub
    | Testnet_P2PKH
    | Testnet_P2SH
    | Testnet_privkey
    | Testnet_BIP32_priv
    | Testnet_BIP32_pub
    | Unknown of string

  type t = private {
    version : version ;
    payload : string ;
  }

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val (=) : t -> t -> bool

  val create : version:version -> payload:string -> t

  val pp            : Format.formatter -> t -> unit
  val show          : t -> string
  val of_base58     : base58 -> t option
  val of_base58_exn : base58 -> t
  val to_base58     : t -> base58

  val of_string     : string -> t option
  val of_string_exn : string -> t
  val to_string     : t -> string

  module Set : Set.S with type elt := t
  module Map : Map.S with type key := t
end

module Komodo (_ : CRYPTO) : sig
  type version =
    | P2PKH
    | P2SH
    | WIF

  type t = private {
    version : version ;
    payload : string ;
  }

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val (=) : t -> t -> bool

  val create : version:version -> payload:string -> t

  val pp            : Format.formatter -> t -> unit
  val show          : t -> string
  val of_base58     : base58 -> t option
  val of_base58_exn : base58 -> t
  val to_base58     : t -> base58

  val of_string     : string -> t option
  val of_string_exn : string -> t
  val to_string     : t -> string

  module Set : Set.S with type elt := t
  module Map : Map.S with type key := t
end

module Set : Set.S with type elt := t
module Map : Map.S with type key := t
