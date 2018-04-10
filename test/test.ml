module Crypto = struct
  let sha256 s =
    let open Digestif.SHA256.Bytes in
    Bytes.(unsafe_to_string (digest (unsafe_of_string s)))
end

let c = (module Crypto : Base58.CRYPTO)

let assert_equal a b = assert (a = b)

let test_btc () =
  let open Base58 in
  let addr = "mjVrE2kfz42sLR5gFcfvG6PwbAjhpmsKnn" in
  let addr_encoded = of_string_exn c addr in
  let addr_decoded = to_string addr_encoded in
  assert_equal addr addr_decoded ;
  let addr_bytes = to_bytes_exn c addr_encoded in
  let addr_bytes_decoded = of_bytes c addr_bytes in
  assert_equal addr_encoded addr_bytes_decoded ;
  assert_equal '\x6f' (String.get addr_bytes 0) ;
  let ({ Bitcoin.version ; payload } as versioned) =
    Bitcoin.of_string_exn c addr in
  assert_equal Bitcoin.Testnet_P2PKH version ;
  assert_equal 20 (String.length payload) ;
  let addr_versioned_str = Bitcoin.to_string c versioned in
  assert_equal addr addr_versioned_str

let test_tezos () =
  let open Base58 in
  let addr = "tz1e5dbxuQ1VBCTvr7DUdahymepWcmFjZcoF" in
  let addr_bytes = to_bytes_exn c (`Base58 addr) in
  let addr' = of_bytes c addr_bytes in
  assert_equal (`Base58 addr) addr' ;
  let tezos_addr = Tezos.of_base58_exn c addr' in
  let tezos_addr' = Tezos.to_string c tezos_addr in
  assert_equal tezos_addr' addr ;
  let addr' = Tezos.(to_string c (of_string_exn c addr)) in
  assert_equal addr addr'

let suite = [
  "btc", `Quick, test_btc ;
  "tezos", `Quick, test_tezos ;
]

let () =
  Alcotest.run "base58" [
    "suite", suite ;
  ]
