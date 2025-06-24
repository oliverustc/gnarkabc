package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gnarkabc/hash/mimchash"
	"gnarkabc/logger"
	"gnarkabc/wrapper"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MiMCHash struct {
	PreImage []frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (c *MiMCHash) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Reset()
	for _, preImage := range c.PreImage {
		mimc.Write(preImage)
	}
	h := mimc.Sum()
	api.AssertIsEqual(c.Hash, h)
	return nil
}

func (c *MiMCHash) PreCompile(params any) {
	args := params.([]interface{})
	inputLen := args[0].(int)
	var preImageLen int
	if inputLen%32 == 0 {
		preImageLen = inputLen / 32
	} else {
		preImageLen = inputLen/32 + 1
	}
	c.PreImage = make([]frontend.Variable, preImageLen)
}

func (c *MiMCHash) Assign(params any) {
	args := params.([]interface{})
	preImage := args[0].([][]byte)
	hash := args[1].([]byte)
	c.PreImage = make([]frontend.Variable, len(preImage))
	for i := range preImage {
		c.PreImage[i] = preImage[i]
	}
	c.Hash = hash
}

type Performance struct {
	Scheme        string `json:"scheme"`
	HashAlg       string `json:"hash_alg"`
	Curve         string `json:"curve"`
	PreImage      string `json:"pre_image"`
	ProveTime     int64  `json:"prove_time"`
	VerifyTime    int64  `json:"verify_time"`
	ConstraintNum int    `json:"constraint_num"`
}

func MiMCHashZKP(input string, curveName string, scheme string) Performance {
	var mc MiMCHash
	inputLen := len(input)
	mod := mimchash.MiMCCaseMap[curveName].Curve.ScalarField()
	inputBytes := mimchash.ConvertString2Byte(input, mod)
	hashFunc := mimchash.MiMCCaseMap[curveName].Hash
	hash := mimchash.MiMCHash(hashFunc, inputBytes)
	preCompileParams := []any{inputLen}
	assignParams := []any{inputBytes, hash}
	switch scheme {
	case "groth16":
		gw := wrapper.Groth16ZKP(&mc, curveName, preCompileParams, assignParams)
		return Performance{
			Scheme:        scheme,
			HashAlg:       "mimc",
			Curve:         curveName,
			PreImage:      input,
			ProveTime:     gw.BenchmarkProve(10).Milliseconds(),
			VerifyTime:    gw.BenchmarkVerify(10).Milliseconds(),
			ConstraintNum: gw.ConstraintNum,
		}
	case "plonk":
		pw := wrapper.PlonkZKP(&mc, curveName, preCompileParams, assignParams)
		return Performance{
			Scheme:        scheme,
			HashAlg:       "mimc",
			Curve:         curveName,
			PreImage:      input,
			ProveTime:     pw.BenchmarkProve(10).Milliseconds(),
			VerifyTime:    pw.BenchmarkVerify(10).Milliseconds(),
			ConstraintNum: pw.ConstraintNum,
		}
	default:
		panic("unknown scheme")
	}
}

func main() {
	input := "hello"
	var p []Performance
	for curveName := range mimchash.MiMCCaseMap {
		logger.Info("mimc hash zkp with string input on curve: [%s]", curveName)
		p = append(p, MiMCHashZKP(input, curveName, "groth16"))
		p = append(p, MiMCHashZKP(input, curveName, "plonk"))
	}
	// 将p写入json文件
	jsonData, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	fileName := fmt.Sprintf("performance_%s.json", time.Now().Format("20060102150405"))
	err = os.WriteFile(fileName, jsonData, 0644)
	if err != nil {
		logger.Error("Failed to write performance data to file: %s", err)
		return
	}
	logger.Info("Performance data saved to %s", fileName)
}
