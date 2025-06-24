package poseidon2hash

import (
	"testing"

	"gnarkabc/circuits"
	"gnarkabc/hash/mimchash"
	"gnarkabc/logger"
	"gnarkabc/utils"
	"gnarkabc/wrapper"
)

func TestPoseidon2Hash(t *testing.T) {
	input := utils.RandStr(100)

	for curveName := range Poseidon2CaseMap {
		mod := Poseidon2CaseMap[curveName].Curve.ScalarField()
		inputBytes := mimchash.ConvertString2Byte(input, mod)
		hashFunc := Poseidon2CaseMap[curveName].Hash
		expectedHash := Poseidon2Hash(hashFunc, inputBytes)
		logger.Info("curveName: %s, expectedHash: %x", curveName, expectedHash)
	}
}

func TestPoseidon2ZKP(t *testing.T) {
	input := utils.RandStr(32)
	curveName := "BLS12-377"
	logger.Info("poseidon2 hash zkp with string input on curve: [%s]", curveName)
	hashFunc := Poseidon2CaseMap[curveName].Hash
	mod := Poseidon2CaseMap[curveName].Curve.ScalarField()
	inputBytes := mimchash.ConvertString2Byte(input, mod)
	expectedHash := Poseidon2Hash(hashFunc, inputBytes)
	assignParams := []any{inputBytes, expectedHash}
	var mc circuits.Poseidon2Hash
	wrapper.Groth16ZKP(&mc, curveName, nil, assignParams)
	wrapper.PlonkZKP(&mc, curveName, nil, assignParams)
}
