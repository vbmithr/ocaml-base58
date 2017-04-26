open Base58
open OUnit2

let test_basic ctx =
  let addr = "mjVrE2kfz42sLR5gFcfvG6PwbAjhpmsKnn" in
  let addr_encoded = of_string_exn addr in
  let addr_decoded = to_string addr_encoded in
  assert_equal addr addr_decoded ;
  let addr_bytes = to_bytes_exn addr_encoded in
  let addr_bytes_decoded = of_bytes addr_bytes in
  assert_equal addr_encoded addr_bytes_decoded ;
  assert_equal '\x6f' (String.get addr_bytes 0)

let suite =
  "base58" >::: [
    "test_basic" >:: test_basic ;
  ]

let () = run_test_tt_main suite
