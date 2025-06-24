package utils

import "github.com/consensys/gnark-crypto/ecc"

// CurveMap 定义了曲线名称到曲线ID的映射关系
var CurveMap = map[string]ecc.ID{
	"BN254":     ecc.BN254,
	"BLS12-377": ecc.BLS12_377,
	"BLS12-381": ecc.BLS12_381,
	"BW6-761":   ecc.BW6_761,
	"BW6-633":   ecc.BW6_633,
	"BLS24-315": ecc.BLS24_315,
	"BLS24-317": ecc.BLS24_317,
}

var CurveNameList = []string{"BN254", "BLS12-377", "BLS12-381", "BW6-633", "BW6-761", "BLS24-315", "BLS24-317"}

var ShaCurveNameList = []string{"BN254", "BLS12-377", "BLS12-381", "BLS24-315", "BLS24-317"}

var Groth16RecursionCurveList = []string{"BN254", "BLS12-377", "BW6-761"}

var PlonkRecursionMap = map[string]ecc.ID{
	"BN254":     ecc.BN254,
	"BLS12-377": ecc.BW6_761,
	"BW6-761":   ecc.BN254,
}
