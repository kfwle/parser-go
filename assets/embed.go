// Package assets embeds static data required at runtime.
package assets

import _ "embed"

// HappCrypt1to4 is the original helpers/crypt/keys/happcrypt.json file.
//
//go:embed keys/happcrypt.json
var HappCrypt1to4 []byte

// HappCrypt5 is the original helpers/crypt/keys/happcrypt5.json file.
//
//go:embed keys/happcrypt5.json
var HappCrypt5 []byte

// Banner is the built-in fallback logo shown when sources/banner.txt is absent.
//
//go:embed banner.txt
var Banner string
