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
  let hash =
    Nocrypto.Hash.digest `SHA256 @@
    Nocrypto.Hash.digest `SHA256 @@
    Cstruct.of_string s in
  let res = Bytes.make 4 '\000' in
  Cstruct.blit_to_bytes hash 0 res 0 4 ;
  Bytes.to_string res

type t = [`Base58 of string]
type base58 = t

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

module Versioned = struct
  type version =
    | P2PKH
    | P2SH
    | Namecoin_P2PKH
    | Privkey
    | Testnet_P2PKH
    | Testnet_P2SH
    | Unknown of int

  let int_of_version = function
    | P2PKH -> 0
    | P2SH -> 5
    | Namecoin_P2PKH -> 52
    | Privkey -> 128
    | Testnet_P2PKH -> 111
    | Testnet_P2SH -> 196
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

  let create ?(version=P2PKH) payload = { version ; payload }
  let of_base58 ?alphabet b58 =
    match to_bytes ?alphabet b58 with
    | None -> None
    | Some bytes ->
      let version = version_of_int (Char.code (String.get bytes 0)) in
      let payload = String.(sub bytes 1 (length bytes - 1)) in
      Some { version ; payload }

  let of_base58_exn ?alphabet b58 =
    match of_base58 ?alphabet b58 with
    | None -> invalid_arg "Base58.Versioned.of_base58_exn"
    | Some b58 -> b58

  let to_base58 ?alphabet { version ; payload } =
    of_bytes ?alphabet
      (String.init 1 (fun _ -> int_of_version version |> Char.chr) ^ payload)

  let of_string ?alphabet str =
    match of_string ?alphabet str with
    | None -> None
    | Some b58 -> of_base58 ?alphabet b58

  let of_string_exn ?alphabet str =
    match of_string ?alphabet str with
    | None -> invalid_arg "Base58.Versioned.of_string_exn"
    | Some b58 -> b58

  let to_string ?alphabet t =
    to_base58 ?alphabet t |> to_string
end
