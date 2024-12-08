open Alcotest
open Base58

module Crypto = struct
  let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
end

module Chk = Base58.Checksummed (Crypto)

let b58 = testable pp equal

let version_tst =
  testable (Fmt.of_to_string Bitcoin.Version.to_raw_bytes) Bitcoin.Version.equal
;;

let test_btc () =
  let open Chk in
  let module Bitcoin = Bitcoin.Make (Crypto) in
  let addr = "mjVrE2kfz42sLR5gFcfvG6PwbAjhpmsKnn" in
  let addr_encoded = of_string_exn addr in
  let addr_decoded = to_string addr_encoded in
  check string "addr_decoded" addr addr_decoded;
  let addr_bytes = to_bytes_exn addr_encoded in
  let addr_bytes_decoded = of_bytes addr_bytes in
  check b58 "addr_encoded" addr_encoded addr_bytes_decoded;
  check char "" '\x6f' (String.get addr_bytes 0);
  let ({ Bitcoin.version; payload } as versioned) = Bitcoin.of_string_exn addr in
  check version_tst "version" Testnet_P2PKH version;
  check int "payload_len" 20 (String.length payload);
  let addr_versioned_str = Bitcoin.to_string versioned in
  check string "versioned_addr" addr addr_versioned_str
;;

let test_tezos () =
  let open Chk in
  let module Tezos = Tezos.Make (Crypto) in
  let addr = "tz1e5dbxuQ1VBCTvr7DUdahymepWcmFjZcoF" in
  let addr_bytes = to_bytes_exn (B58 addr) in
  let addr' = of_bytes addr_bytes in
  check b58 "decoded" (B58 addr) addr';
  let tezos_addr = Tezos.of_base58_exn addr' in
  let tezos_addr' = Tezos.to_string tezos_addr in
  check string "equal addr" tezos_addr' addr;
  let addr' = Tezos.(to_string (of_string_exn addr)) in
  check string "rdtrip" addr addr'
;;

let suite = [ test_case "btc" `Quick test_btc; test_case "tezos" `Quick test_tezos ]
let () = Alcotest.run "base58" [ "suite", suite ]
