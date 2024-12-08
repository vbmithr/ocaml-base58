(lang dune 3.16)

(name base58)

(generate_opam_files true)

(source
 (github vbmithr/ocaml-base58))

(authors "Vincent Bernardoff <vb@luminar.eu.org>")

(maintainers "Vincent Bernardoff")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name base58)
 (synopsis "Base58 binary encoding")
 (description "")
 (depends
   ocaml
   dune
   zarith
   ppx_compare
  (alcotest :with-test)
  (digestif :with-test)
 )
 (tags (base58 crypto bitcoin)))
