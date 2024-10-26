package gnarkwrapper

import "github.com/consensys/gnark-crypto/ecc"

var CurveMap = map[string]ecc.ID{
	"BN254":     ecc.BN254,
	"BLS12-377": ecc.BLS12_377,
	"BLS12-381": ecc.BLS12_381,
	"BW6-761":   ecc.BW6_761,
	"BLS24-315": ecc.BLS24_315,
	"BW6-633":   ecc.BW6_633,
	"BLS24-317": ecc.BLS24_317,
}
