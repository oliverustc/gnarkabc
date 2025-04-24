package mimchash

import (
	"hash"
	"math/big"

	"gnarkabc/logger"

	"github.com/consensys/gnark-crypto/ecc"
	gchash "github.com/consensys/gnark-crypto/hash"

	// 导入MiMC哈希函数包以注册它们
	_ "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/mimc"
	_ "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

type MiMCCase struct {
	Curve ecc.ID
	Hash  hash.Hash
}

var MiMCCaseMap = map[string]MiMCCase{
	"BN254":     {ecc.BN254, gchash.MIMC_BN254.New()},
	"BLS12-377": {ecc.BLS12_377, gchash.MIMC_BLS12_377.New()},
	"BLS12-381": {ecc.BLS12_381, gchash.MIMC_BLS12_381.New()},
	"BLS24-315": {ecc.BLS24_315, gchash.MIMC_BLS24_315.New()},
	"BLS24-317": {ecc.BLS24_317, gchash.MIMC_BLS24_317.New()},
	"BW6-633":   {ecc.BW6_633, gchash.MIMC_BW6_633.New()},
	"BW6-761":   {ecc.BW6_761, gchash.MIMC_BW6_761.New()},
}

func ConvertString2Byte(input string, mod *big.Int) [][]byte {
	logger.Debug("input: %s", input)
	inputLen := len(input)
	if inputLen%32 != 0 {
		padding := 32 - (inputLen % 32)
		logger.Debug("padding: %d chars", padding)
		input = string(make([]byte, padding)) + input
	}
	var inputBytes [][]byte
	for i := 0; i < len(input); i += 32 {
		_input := []byte(input[i : i+32])
		logger.Debug("d: %x", _input)
		inputBigInt := new(big.Int).SetBytes(_input)
		if inputBigInt.Cmp(mod) >= 0 {
			logger.Debug("inputBigInt >= mod, %v", inputBigInt)
			inputBigInt.Mod(inputBigInt, mod)
			logger.Debug("after mod, inputBigInt: %v", inputBigInt)
		}
		inputBytes = append(inputBytes, inputBigInt.Bytes())
	}
	return inputBytes
}

func MiMCHash(h hash.Hash, data [][]byte) []byte {
	h.Reset()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}
