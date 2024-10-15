package gnarkwrapper

import "github.com/consensys/gnark-crypto/ecc"

var CurveMap = map[string]ecc.ID{
	"BN254":     ecc.BN254,
	"BLS12_377": ecc.BLS12_377,
	"BLS12-381": ecc.BLS12_381,
	"BW6_761":   ecc.BW6_761,
	"BLS24_315": ecc.BLS24_315,
	"BW6_633":   ecc.BW6_633,
	"BLS24_317": ecc.BLS24_317,
}
