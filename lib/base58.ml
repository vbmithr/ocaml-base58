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

let base = 58
let zbase = Z.of_int base

module Alphabet = struct
  type t =
    { encode : string
    ; decode : string
    }

  let make alphabet =
    if String.length alphabet <> base then invalid_arg "Base58: invalid alphabet (length)";
    let str = Bytes.make 256 '\255' in
    for i = 0 to String.length alphabet - 1 do
      let char = int_of_char alphabet.[i] in
      if Bytes.get str char <> '\255'
      then
        Format.kasprintf
          invalid_arg
          "Base58: invalid alphabet (dup '%c' %d %d)"
          (char_of_int char)
          (int_of_char @@ Bytes.get str char)
          i;
      Bytes.set str char (char_of_int i)
    done;
    { encode = alphabet; decode = Bytes.to_string str }
  ;;

  let bitcoin = make "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  let ripple = make "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
  let flickr = make "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
  let default = bitcoin
end

let count_trailing_char s c =
  let len = String.length s in
  let rec loop i =
    if i < 0 then len else if String.get s i <> c then len - i - 1 else loop (i - 1)
  in
  loop (len - 1)
;;

let count_leading_char s c =
  let len = String.length s in
  let rec loop i =
    if i = len then len else if String.get s i <> c then i else loop (i + 1)
  in
  loop 0
;;

let of_char ?(alphabet = Alphabet.default) x =
  let pos = String.get alphabet.decode (int_of_char x) in
  if pos = '\255' then failwith "Invalid data";
  int_of_char pos
;;

let to_char ?(alphabet = Alphabet.default) x = alphabet.encode.[x]

let raw_encode ?(alphabet = Alphabet.default) s =
  let len = String.length s in
  let s = String.init len (fun i -> String.get s (len - i - 1)) in
  let zero = alphabet.encode.[0] in
  let zeros = count_trailing_char s '\000' in
  let res_len = ((len * 8) + 4) / 5 in
  let res = Bytes.make res_len '\000' in
  let s = Z.of_bits s in
  let rec loop s =
    if s = Z.zero
    then 0
    else (
      let s, r = Z.div_rem s zbase in
      let i = loop s in
      Bytes.set res i (to_char ~alphabet (Z.to_int r));
      i + 1)
  in
  let i = loop s in
  let res = Bytes.sub_string res 0 i in
  String.make zeros zero ^ res
;;

let raw_decode ?(alphabet = Alphabet.default) s =
  let zero = alphabet.encode.[0] in
  let zeros = count_leading_char s zero in
  let len = String.length s in
  let rec loop res i =
    if i = len
    then res
    else (
      let x = Z.of_int (of_char ~alphabet (String.get s i)) in
      let res = Z.(add x (mul res zbase)) in
      loop res (i + 1))
  in
  let res = Z.to_bits @@ loop Z.zero zeros in
  let res_tzeros = count_trailing_char res '\000' in
  let len = String.length res - res_tzeros in
  String.make zeros '\000' ^ String.init len (fun i -> String.get res (len - i - 1))
;;

type t = [ `Base58 of string ]
type base58 = t

let compare (`Base58 t) (`Base58 t') = String.compare t t'
let equal (`Base58 t) (`Base58 t') = String.equal t t'
let ( = ) = equal
let pp ppf (`Base58 b58) = Format.pp_print_string ppf b58
let to_string (`Base58 b58) = b58
let show = to_string

module Checksummed (C : CRYPTO) = struct
  let checksum s =
    let hash = C.(sha256 (sha256 s)) in
    let res = Bytes.make 4 '\000' in
    Bytes.blit_string hash 0 res 0 4;
    Bytes.unsafe_to_string res
  ;;

  (* Append a 4-bytes cryptographic checksum before encoding string s *)
  let of_bytes ?alphabet s = `Base58 (raw_encode ?alphabet (s ^ checksum s))

  let to_bytes ?alphabet (`Base58 s) =
    let s = raw_decode ?alphabet s in
    let len = String.length s in
    let msg = String.sub s 0 (len - 4) in
    let msg_hash = String.sub s (len - 4) 4 in
    if msg_hash <> checksum msg then None else Some msg
  ;;

  let to_bytes_exn ?alphabet s =
    match to_bytes ?alphabet s with
    | None -> invalid_arg "Base58.safe_decode_exn"
    | Some s -> s
  ;;

  let of_string ?alphabet str =
    match to_bytes ?alphabet (`Base58 str) with
    | None -> None
    | Some _ -> Some (`Base58 str)
  ;;

  let of_string_exn ?alphabet str =
    match to_bytes ?alphabet (`Base58 str) with
    | None -> invalid_arg "Base58.of_string_exn"
    | Some _ -> `Base58 str
  ;;
end

let chars_of_string str =
  let chars = ref [] in
  StringLabels.iter str ~f:(fun c -> chars := c :: !chars);
  List.rev !chars
;;

module type S = sig
  type version

  type t = private
    { version : version
    ; payload : string
    }

  val compare : t -> t -> int
  val equal : t -> t -> bool
  val ( = ) : t -> t -> bool
  val create : version:version -> payload:string -> t
  val pp : Format.formatter -> t -> unit
  val show : t -> string
  val of_base58 : base58 -> t option
  val of_base58_exn : base58 -> t
  val to_base58 : t -> base58
  val of_string : string -> t option
  val of_string_exn : string -> t
  val to_string : t -> string

  module Set : Set.S with type elt := t
  module Map : Map.S with type key := t
end

type tezos_version =
  | Block
  | Operation
  | Protocol
  | Address
  | Peer
  | Public_key
  | Secret_key
  | Signature

module Tezos (C : CRYPTO) = struct
  open Checksummed (C)

  (* 32 *)
  let block_hash = "\001\052" (* B(51) *)
  let operation_hash = "\005\116" (* o(51) *)
  let protocol_hash = "\002\170" (* P(51) *)

  (* 20 *)
  let ed25519_public_key_hash = "\006\161\159" (* tz1(36) *)

  (* 16 *)
  let cryptobox_public_key_hash = "\153\103" (* id(30) *)

  (* 32 *)
  let ed25519_public_key = "\013\015\037\217" (* edpk(54) *)

  (* 64 *)
  let ed25519_secret_key = "\043\246\078\007" (* edsk(98) *)
  let ed25519_signature = "\009\245\205\134\018" (* edsig(99) *)

  type version = tezos_version

  type t =
    { version : version
    ; payload : string
    }

  let compare { version = v1; payload = p1 } { version = v2; payload = p2 } =
    if v1 > v2 then 1 else if v1 < v2 then -1 else String.compare p1 p2
  ;;

  let equal t t' = Stdlib.( = ) t t'
  let ( = ) = equal

  let sub_or_fail str start len error_msg =
    try String.sub str start len with
    | _ ->
      invalid_arg
        (Printf.sprintf
           "Tezos.of_bytes: %s must be %d bytes long"
           error_msg
           (len - start))
  ;;

  let t_of_bytes bytes =
    if String.length bytes < 2 then invalid_arg "Tezos.of_bytes: str < 2";
    match chars_of_string bytes with
    | '\001' :: '\052' :: _ ->
      { version = Block; payload = sub_or_fail bytes 2 32 "block" }
    | '\005' :: '\116' :: _ ->
      { version = Operation; payload = sub_or_fail bytes 2 32 "operation" }
    | '\002' :: '\170' :: _ ->
      { version = Protocol; payload = sub_or_fail bytes 2 32 "protocol" }
    | '\006' :: '\161' :: '\159' :: _ ->
      { version = Address; payload = sub_or_fail bytes 3 20 "address" }
    | '\153' :: '\103' :: _ -> { version = Peer; payload = sub_or_fail bytes 2 16 "peer" }
    | '\013' :: '\015' :: '\037' :: '\217' :: _ ->
      { version = Public_key; payload = sub_or_fail bytes 4 32 "public_key" }
    | '\043' :: '\246' :: '\078' :: '\007' :: _ ->
      { version = Secret_key; payload = sub_or_fail bytes 4 64 "secret_key" }
    | '\009' :: '\245' :: '\205' :: '\134' :: '\018' :: _ ->
      { version = Signature; payload = sub_or_fail bytes 5 64 "signature" }
    | _ -> invalid_arg "Tezos.of_bytes: unknown prefix"
  ;;

  let string_of_version = function
    | Block -> block_hash
    | Operation -> operation_hash
    | Protocol -> protocol_hash
    | Address -> ed25519_public_key_hash
    | Peer -> cryptobox_public_key_hash
    | Public_key -> ed25519_public_key
    | Secret_key -> ed25519_secret_key
    | Signature -> ed25519_signature
  ;;

  let create ~version ~payload = { version; payload }

  let of_base58 b58 =
    match to_bytes b58 with
    | None -> None
    | Some bytes ->
      (try Some (t_of_bytes bytes) with
       | _ -> None)
  ;;

  let of_base58_exn b58 =
    match to_bytes b58 with
    | None -> invalid_arg "Tezos.of_base58_exn: not base58 data"
    | Some bytes -> t_of_bytes bytes
  ;;

  let to_base58 { version; payload } = of_bytes (string_of_version version ^ payload)

  let of_string str =
    match of_string str with
    | None -> None
    | Some b58 -> of_base58 b58
  ;;

  let of_string_exn str =
    match of_string str with
    | None -> invalid_arg "Base58.Tezos.of_string_exn"
    | Some b58 -> b58
  ;;

  let to_string t = to_string (to_base58 t)
  let show = to_string
  let pp ppf t = Format.fprintf ppf "%s" (show t)

  module Set = Set.Make (struct
      type nonrec t = t

      let compare = compare
    end)

  module Map = Map.Make (struct
      type nonrec t = t

      let compare = compare
    end)
end

type bitcoin_version =
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

module Bitcoin (C : CRYPTO) = struct
  open Checksummed (C)

  let string_of_version = function
    | P2PKH -> "\000"
    | P2SH -> "\005"
    | Namecoin_P2PKH -> "\052"
    | Privkey -> "\x80"
    | BIP32_priv -> "\x04\x88\xAD\xE4"
    | BIP32_pub -> "\x04\x88\xB2\x1E"
    | Testnet_P2PKH -> "\111"
    | Testnet_P2SH -> "\196"
    | Testnet_privkey -> "\xef"
    | Testnet_BIP32_priv -> "\x04\x35\x83\x94"
    | Testnet_BIP32_pub -> "\x04\x35\x87\xCF"
    | Unknown i -> i
  ;;

  let t_of_bytes s =
    let len = String.length s in
    match chars_of_string s with
    | '\x00' :: _ -> P2PKH, String.sub s 1 (len - 1)
    | '\005' :: _ -> P2SH, String.sub s 1 (len - 1)
    | '\052' :: _ -> Namecoin_P2PKH, String.sub s 1 (len - 1)
    | '\x80' :: _ -> Privkey, String.sub s 1 (len - 1)
    | '\111' :: _ -> Testnet_P2PKH, String.sub s 1 (len - 1)
    | '\196' :: _ -> Testnet_P2SH, String.sub s 1 (len - 1)
    | '\x04' :: '\x88' :: '\xAD' :: '\xE4' :: _ -> BIP32_priv, String.sub s 4 (len - 4)
    | '\x04' :: '\x88' :: '\xB2' :: '\x1E' :: _ -> BIP32_pub, String.sub s 4 (len - 4)
    | '\x04' :: '\x35' :: '\x83' :: '\x94' :: _ ->
      Testnet_BIP32_priv, String.sub s 4 (len - 4)
    | '\x04' :: '\x35' :: '\x87' :: '\xCF' :: _ ->
      Testnet_BIP32_pub, String.sub s 4 (len - 4)
    | _ -> invalid_arg "Base58.Bitcoin.t_of_bytes: unknown version"
  ;;

  type version = bitcoin_version

  type t =
    { version : version
    ; payload : string
    }

  let compare { version = v1; payload = p1 } { version = v2; payload = p2 } =
    if v1 > v2 then 1 else if v1 < v2 then -1 else String.compare p1 p2
  ;;

  let equal t t' = Stdlib.( = ) t t'
  let ( = ) = equal
  let create ~version ~payload = { version; payload }

  let of_base58_exn b58 =
    let bytes = to_bytes_exn b58 in
    let version, payload = t_of_bytes bytes in
    { version; payload }
  ;;

  let of_base58 b58 =
    try Some (of_base58_exn b58) with
    | _ -> None
  ;;

  let to_base58 { version; payload } = of_bytes (string_of_version version ^ payload)

  let of_string str =
    match of_string str with
    | None -> None
    | Some b58 -> of_base58 b58
  ;;

  let of_string_exn str =
    match of_string str with
    | None -> invalid_arg "Base58.Bitcoin.of_string_exn"
    | Some b58 -> b58
  ;;

  let to_string t = to_string (to_base58 t)
  let show = to_string
  let pp ppf t = Format.fprintf ppf "%s" (show t)

  module Set = Set.Make (struct
      type nonrec t = t

      let compare = compare
    end)

  module Map = Map.Make (struct
      type nonrec t = t

      let compare = compare
    end)
end

type komodo_version =
  | P2PKH
  | P2SH
  | WIF

module Komodo (C : CRYPTO) = struct
  open Checksummed (C)

  let string_of_version = function
    | P2PKH -> "\060"
    | P2SH -> "\085"
    | WIF -> "\128"
  ;;

  let version_of_bytes_exn s =
    let len = String.length s in
    match chars_of_string s with
    | '\060' :: _ -> P2PKH, String.sub s 1 (len - 1)
    | '\085' :: _ -> P2SH, String.sub s 1 (len - 1)
    | '\128' :: _ -> WIF, String.sub s 1 (len - 1)
    | _ -> invalid_arg "Komodo.version_of_string_exn"
  ;;

  type version = komodo_version

  type t =
    { version : version
    ; payload : string
    }

  let compare { version = v1; payload = p1 } { version = v2; payload = p2 } =
    if v1 > v2 then 1 else if v1 < v2 then -1 else String.compare p1 p2
  ;;

  let equal t t' = Stdlib.( = ) t t'
  let ( = ) = equal
  let create ~version ~payload = { version; payload }

  let of_base58_exn b58 =
    let bytes = to_bytes_exn b58 in
    let version, payload = version_of_bytes_exn bytes in
    { version; payload }
  ;;

  let of_base58 b58 =
    try Some (of_base58_exn b58) with
    | _ -> None
  ;;

  let to_base58 { version; payload } = of_bytes (string_of_version version ^ payload)

  let of_string str =
    match of_string str with
    | None -> None
    | Some b58 -> of_base58 b58
  ;;

  let of_string_exn str =
    match of_string str with
    | None -> invalid_arg "Base58.Bitcoin.of_string_exn"
    | Some b58 -> b58
  ;;

  let to_string t = to_string (to_base58 t)
  let show = to_string
  let pp ppf t = Format.fprintf ppf "%s" (show t)

  module Set = Set.Make (struct
      type nonrec t = t

      let compare = compare
    end)

  module Map = Map.Make (struct
      type nonrec t = t

      let compare = compare
    end)
end

module Set = Set.Make (struct
    type t = base58

    let compare = compare
  end)

module Map = Map.Make (struct
    type t = base58

    let compare = compare
  end)
