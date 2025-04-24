package mimchash

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	crand "crypto/rand"

	"gnarkabc/circuits"
	"gnarkabc/logger"
	"gnarkabc/utils"
	"gnarkabc/wrapper"
)

func TestConvertString2Byte(t *testing.T) {
	input := strings.Repeat("helloworld", 10)
	logger.Info("input: %s", input)
	for curveName := range MiMCCaseMap {
		mod := MiMCCaseMap[curveName].Curve.ScalarField()
		data := ConvertString2Byte(input, mod)
		logger.Info("curveName: %s, data: %x", curveName, data)
	}
}

func TestMiMCHashString(t *testing.T) {
	input := strings.Repeat("helloworld", 10)
	logger.Info("input: %s", input)
	for curveName := range MiMCCaseMap {
		hashFunc := MiMCCaseMap[curveName].Hash
		mod := MiMCCaseMap[curveName].Curve.ScalarField()
		data := ConvertString2Byte(input, mod)
		expectedHash := MiMCHash(hashFunc, data)
		logger.Info("curveName: %s, expectedHash: %x", curveName, expectedHash)
		logger.Info("hash length: %d", len(expectedHash))
	}
}

func TestMiMCHashStringZKP(t *testing.T) {
	input := "z"
	for curveName := range MiMCCaseMap {
		logger.Info("mimc hash zkp with string input on curve: [%s]", curveName)
		hashFunc := MiMCCaseMap[curveName].Hash
		mod := MiMCCaseMap[curveName].Curve.ScalarField()
		data := ConvertString2Byte(input, mod)
		expectedHash := MiMCHash(hashFunc, data)
		assignParams := []interface{}{data, expectedHash}
		var mc circuits.MimcHash
		wrapper.Groth16ZKP(&mc, curveName, nil, assignParams)
		wrapper.PlonkZKP(&mc, curveName, nil, assignParams)
	}
}

func TestMiMCHashBigIntZKP(t *testing.T) {
	randInt64 := int64(utils.RandInt(0, 100000))
	input := new(big.Int).SetInt64(randInt64)
	for curveName := range MiMCCaseMap {
		logger.Info("mimc hash zkp with bigint input on curve: [%s]", curveName)
		data := input.Bytes()
		expectedHash := MiMCHash(MiMCCaseMap[curveName].Hash, [][]byte{data})
		assignParams := []interface{}{data, expectedHash}
		var mc circuits.MimcHash
		wrapper.Groth16ZKP(&mc, curveName, nil, assignParams)
		wrapper.PlonkZKP(&mc, curveName, nil, assignParams)
	}
}

// 与直接使用big.Int.Bytes()结果一致,弃用
func OldConvertBigInt2Bytes(input *big.Int, mod *big.Int) []byte {
	inputBytes := input.Bytes()
	var expectedByteLen int
	modByteLen := mod.BitLen() / 8
	if modByteLen%2 != 0 {
		expectedByteLen = modByteLen + 1
	} else {
		expectedByteLen = modByteLen
	}
	if len(inputBytes) != expectedByteLen {
		inputBytes = append(make([]byte, expectedByteLen-len(inputBytes)), inputBytes...)
	}
	return inputBytes
}

func TestTwoConvertForBigInt(t *testing.T) {
	for i := 0; i < 1000; i++ {
		mod := MiMCCaseMap["BN254"].Curve.ScalarField()
		input, _ := crand.Int(crand.Reader, mod)
		data1 := OldConvertBigInt2Bytes(input, mod)
		data2 := input.Bytes()
		logger.Debug("input: %v", input)
		logger.Debug("converted data1: %x", data1)
		logger.Debug("converted data2: %x", data2)
		hash1 := MiMCHash(MiMCCaseMap["BN254"].Hash, [][]byte{data1})
		hash2 := MiMCHash(MiMCCaseMap["BN254"].Hash, [][]byte{data2})
		logger.Debug("hash1: %x", hash1)
		logger.Debug("hash2: %x", hash2)
		if !bytes.Equal(hash1, hash2) {
			panic("hash1 != hash2")
		}
	}
	logger.Info("two convert is equal")
}
