(**************************************************************************)
(*                                                                        *)
(*    Copyright (c) 2014 - 2016.                                          *)
(*    Dynamic Ledger Solutions, Inc. <contact@tezos.com>                  *)
(*                                                                        *)
(*    All rights reserved. No warranty, explicit or implicit, provided.   *)
(*                                                                        *)
(**************************************************************************)

let base = 58
let zbase = Z.of_int base

let log2 x = log x /. log 2.
let log2_base = log2 (float_of_int base)


module Alphabet = struct

  type t = { encode: string ; decode: string }

  let make alphabet =
    if String.length alphabet <> base then
      invalid_arg "Base58: invalid alphabet (length)" ;
    let str = Bytes.make 256 '\255' in
    for i = 0 to String.length alphabet - 1 do
      let char = int_of_char alphabet.[i] in
      if Bytes.get str char <> '\255' then
        Format.kasprintf invalid_arg
          "Base58: invalid alphabet (dup '%c' %d %d)"
        (char_of_int char) (int_of_char @@ Bytes.get str char) i ;
      Bytes.set str char (char_of_int i) ;
    done ;
    { encode = alphabet ; decode = Bytes.to_string str }

  let bitcoin =
    make "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  let ripple =
    make "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
  let flickr =
    make "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

  let default = bitcoin

end

let count_trailing_char s c =
  let len = String.length s in
  let rec loop i =
    if i < 0 then len
    else if String.get s i <> c then (len-i-1)
    else loop (i-1) in
  loop (len-1)

let count_leading_char s c =
  let len = String.length s in
  let rec loop i =
    if i = len then len
    else if String.get s i <> c then i
    else loop (i+1) in
  loop 0

let of_char ?(alphabet=Alphabet.default) x =
  let pos = String.get alphabet.decode (int_of_char x) in
  if pos = '\255' then failwith "Invalid data" ;
  int_of_char pos

let to_char ?(alphabet=Alphabet.default) x =
  alphabet.encode.[x]

let raw_encode ?(alphabet=Alphabet.default) s =
  let len = String.length s in
  let s = String.init len (fun i -> String.get s (len - i - 1)) in
  let zero = alphabet.encode.[0] in
  let zeros = count_trailing_char s '\000' in
  let res_len = (len * 8 + 4) / 5 in
  let res = Bytes.make res_len '\000' in
  let s = Z.of_bits s in
  let rec loop s =
    if s = Z.zero then 0 else
    let s, r = Z.div_rem s zbase in
    let i = loop s in
    Bytes.set res i (to_char ~alphabet (Z.to_int r)) ;
    i + 1 in
  let i = loop s in
  let res = Bytes.sub_string res 0 i in
  String.make zeros zero ^ res

let raw_decode ?(alphabet=Alphabet.default) s =
  let zero = alphabet.encode.[0] in
  let zeros = count_leading_char s zero in
  let len = String.length s in
  let rec loop res i =
    if i = len then res else
    let x = Z.of_int (of_char ~alphabet (String.get s i)) in
    let res = Z.(add x (mul res zbase)) in
    loop res (i+1)
  in
  let res = Z.to_bits @@ loop Z.zero zeros in
  let res_tzeros = count_trailing_char res '\000' in
  let len = String.length res - res_tzeros in
  String.make zeros '\000' ^
  String.init len (fun i -> String.get res (len - i - 1))

let checksum s =
  let hash = Digestif.SHA256.Bytes.(digest (digest s)) in
  let res = Bytes.make 4 '\000' in
  Bytes.blit hash 0 res 0 4 ;
  Bytes.to_string res

type t = [`Base58 of string]
type base58 = t

let compare (`Base58 t) (`Base58 t') = String.compare t t'
let equal (`Base58 t) (`Base58 t') = String.equal t t'
let (=) = equal

let pp ppf (`Base58 b58) = Format.pp_print_string ppf b58

(* Append a 4-bytes cryptographic checksum before encoding string s *)
let of_bytes ?alphabet s =
  `Base58 (raw_encode ?alphabet (s ^ checksum s))

let to_bytes ?alphabet (`Base58 s) =
  let s = raw_decode ?alphabet s in
  let len = String.length s in
  let msg = String.sub s 0 (len-4) in
  let msg_hash = String.sub s (len-4) 4 in
  if msg_hash <> checksum msg then None
  else Some msg

let to_bytes_exn ?alphabet s =
  match to_bytes ?alphabet s with
  | None -> invalid_arg "Base58.safe_decode_exn"
  | Some s -> s

let of_string ?alphabet str =
  match to_bytes ?alphabet (`Base58 str) with
  | None -> None
  | Some _ -> Some (`Base58 str)

let of_string_exn ?alphabet str =
  match to_bytes ?alphabet (`Base58 str) with
  | None -> invalid_arg "Base58.of_string_exn"
  | Some _ -> `Base58 str

let to_string (`Base58 b58) = b58
let show = to_string

module Tezos = struct
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

  type version =
    | Block
    | Operation
    | Protocol
    | Address
    | Peer
    | Public_key
    | Secret_key
    | Signature

  type t = {
    version : version ;
    payload : string ;
  }

  let compare { version = v1; payload = p1} { version = v2 ; payload = p2 } =
    if v1 > v2 then 1
    else if v1 < v2 then -1
    else String.compare p1 p2

  let equal t t' = Pervasives.(=) t t'
  let (=) = equal

  let sub_or_fail str start len error_msg =
    try String.sub str start len with _ ->
      invalid_arg
        (Printf.sprintf "Tezos.of_bytes: %s must be %d bytes long"
           error_msg (len - start))

  let chars_of_string str =
    let chars = ref [] in
    StringLabels.iter str ~f:(fun c -> chars := c :: !chars) ;
    List.rev !chars

  let t_of_bytes bytes =
    if String.length bytes < 2 then
      invalid_arg "Tezos.of_bytes: str < 2" ;
    match chars_of_string (String.sub bytes 0 5) with
    | '\001' :: '\052' :: _ ->
      { version = Block ; payload = sub_or_fail bytes 2 32 "block" }
    | '\005' :: '\116' :: _ ->
      { version = Operation ; payload = sub_or_fail bytes 2 32 "operation" }
    | '\002' :: '\170' :: _ ->
      { version = Protocol ; payload = sub_or_fail bytes 2 32 "protocol" }
    | '\006' :: '\161' :: '\159' :: _ ->
      { version = Address ; payload = sub_or_fail bytes 3 20 "address" }
    | '\153' :: '\103' :: _ ->
      { version = Peer ; payload = sub_or_fail bytes 2 16 "peer" }
    | '\013' :: '\015' :: '\037' :: '\217' :: _ ->
      { version = Public_key ; payload = sub_or_fail bytes 4 32 "public_key" }
    | '\043' :: '\246' :: '\078' :: '\007' :: _ ->
      { version = Secret_key ; payload = sub_or_fail bytes 4 64 "secret_key" }
    | '\009' :: '\245' :: '\205' :: '\134' :: '\018' :: _ ->
      { version = Signature ; payload = sub_or_fail bytes 5 64 "signature" }
    | _ -> invalid_arg "Tezos.of_bytes: unknown prefix"

  let string_of_version = function
    | Block -> block_hash
    | Operation -> operation_hash
    | Protocol -> protocol_hash
    | Address -> ed25519_public_key_hash
    | Peer -> cryptobox_public_key_hash
    | Public_key -> ed25519_public_key
    | Secret_key -> ed25519_secret_key
    | Signature -> ed25519_signature

  let create ~version ~payload = { version ; payload }

  let of_base58 b58 =
    match to_bytes b58 with
    | None -> None
    | Some bytes -> try Some (t_of_bytes bytes) with _ -> None

  let of_base58_exn b58 =
    match to_bytes b58 with
    | None -> invalid_arg "Tezos.of_base58_exn: not base58 data"
    | Some bytes -> t_of_bytes bytes

  let to_base58 { version ; payload } =
    of_bytes (string_of_version version ^ payload)

  let of_string str =
    match of_string str with
    | None -> None
    | Some b58 -> of_base58 b58

  let of_string_exn str =
    match of_string str with
    | None -> invalid_arg "Base58.Tezos.of_string_exn"
    | Some b58 -> b58

  let to_string t =
    to_base58 t |> to_string

  let show t = to_string t
  let pp ppf t = Format.fprintf ppf "%s" (show t)

  module Set = Set.Make(struct type nonrec t = t let compare = compare end)
  module Map = Map.Make(struct type nonrec t = t let compare = compare end)
end

module Bitcoin = struct
  type version =
    | P2PKH
    | P2SH
    | Namecoin_P2PKH
    | Privkey
    | Testnet_P2PKH
    | Testnet_P2SH
    | Testnet_privkey
    | Unknown of int

  let int_of_version = function
    | P2PKH -> 0
    | P2SH -> 5
    | Namecoin_P2PKH -> 52
    | Privkey -> 0x80
    | Testnet_P2PKH -> 111
    | Testnet_P2SH -> 196
    | Testnet_privkey -> 0xef
    | Unknown i -> i

  let version_of_int = function
    | 0 -> P2PKH
    | 5 -> P2SH
    | 52 -> Namecoin_P2PKH
    | 128 -> Privkey
    | 111 -> Testnet_P2PKH
    | 196 -> Testnet_P2SH
    | i -> Unknown i

  type t = {
    version : version ;
    payload : string ;
  }

  let compare { version = v1; payload = p1} { version = v2 ; payload = p2 } =
    if v1 > v2 then 1
    else if v1 < v2 then -1
    else String.compare p1 p2

  let equal t t' = Pervasives.(=) t t'
  let (=) = equal

  let create ~version ~payload = { version ; payload }

  let of_base58 b58 =
    match to_bytes b58 with
    | None -> None
    | Some bytes ->
      let version = version_of_int (Char.code (String.get bytes 0)) in
      let payload = String.(sub bytes 1 (length bytes - 1)) in
      Some { version ; payload }

  let of_base58_exn b58 =
    match of_base58 b58 with
    | None -> invalid_arg "Base58.Bitcoin.of_base58_exn"
    | Some b58 -> b58

  let to_base58 { version ; payload } =
    of_bytes
      (String.init 1 (fun _ -> int_of_version version |> Char.chr) ^ payload)

  let of_string str =
    match of_string str with
    | None -> None
    | Some b58 -> of_base58 b58

  let of_string_exn str =
    match of_string str with
    | None -> invalid_arg "Base58.Bitcoin.of_string_exn"
    | Some b58 -> b58

  let to_string t =
    to_base58 t |> to_string

  let show t = to_string t
  let pp ppf t = Format.fprintf ppf "%s" (show t)

  module Set = Set.Make(struct type nonrec t = t let compare = compare end)
  module Map = Map.Make(struct type nonrec t = t let compare = compare end)
end

module Set = Set.Make(struct type t = base58 let compare = compare end)
module Map = Map.Make(struct type t = base58 let compare = compare end)
