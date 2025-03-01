package main

import (
	"crypto/rand"
	"math/big"

	"github.com/oliverustc/gnarkabc/gnarkwrapper"
	"github.com/oliverustc/gnarkabc/hash/mimchash"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type SimpleCircuit struct {
	P frontend.Variable
	Q frontend.Variable
	N frontend.Variable `gnark:",public"`
}

func (c *SimpleCircuit) Define(api frontend.API) error {
	n := api.Mul(c.P, c.Q)
	api.AssertIsEqual(n, c.N)
	return nil
}

// empty function
func (c *SimpleCircuit) PreCompile(params ...interface{}) {
}

// random assign
func (c *SimpleCircuit) Assign(curveName string, params ...interface{}) {
	size := params[0].(int)
	// 随机生成size大小的prime
	p, err := rand.Prime(rand.Reader, size)
	if err != nil {
		panic(err)
	}
	q, err := rand.Prime(rand.Reader, size)
	if err != nil {
		panic(err)
	}
	n := new(big.Int).Mul(p, q)
	logger.Info("p: %v, q: %v, n: %v", p, q, n)
	c.P = p
	c.Q = q
	c.N = n
}

type MiMCCircuit struct {
	PreImage []frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *MiMCCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := 0; i < len(circuit.PreImage); i++ {
		mimc.Write(circuit.PreImage[i])
	}
	hash := mimc.Sum()
	api.AssertIsEqual(hash, circuit.Hash)

	return nil
}

func (circuit *MiMCCircuit) PreCompile(params ...interface{}) {
	inputLen := params[0].(int)
	preImageLen := (inputLen + 31) / 32
	circuit.PreImage = make([]frontend.Variable, preImageLen)
}

func (circuit *MiMCCircuit) Assign(curveName string, params ...interface{}) {
	curve := mimchash.MiMCCaseMap[curveName]
	inputLen := params[0].(int)
	input := utils.RandStr(inputLen)
	var preImageByteArr [][]byte
	if len(input)%32 != 0 {
		padding := 32 - (len(input) % 32)
		input += string(make([]byte, padding))
	}
	field := curve.Curve.ScalarField()
	for i := 0; i < len(input); i += 32 {
		end := i + 32
		if end > len(input) {
			end = len(input)
		}
		preImageByteArr = append(preImageByteArr, mimchash.Convert2Byte(input[i:end], field))
	}
	hashFunc := curve.Hash
	hashFunc.Reset()
	circuit.PreImage = make([]frontend.Variable, len(preImageByteArr))
	for i, p := range preImageByteArr {
		circuit.PreImage[i] = p
		hashFunc.Write(p)
	}
	circuit.Hash = hashFunc.Sum(nil)
}

func SimpleCircuitZKP(scheme string, inputLen int) {
	curve := gnarkwrapper.CurveMap["BN254"]
	var circuit SimpleCircuit
	circuit.PreCompile(inputLen)
	zk := gnarkwrapper.NewGnarkWrapper(scheme, &circuit, curve)
	zk.Compile()
	zk.Setup()
	circuit.Assign("BN254", inputLen)
	zk.SetAssignment(&circuit)
	zk.Prove()
	zk.Verify()
	zk.ExportSolidity("")
	prootStr := zk.GenSolProofParams()
	logger.Info("proofStr:\n%s", prootStr)
	inputStr := zk.GenSolInputParams()
	logger.Info("inputStr:\n%s", inputStr)
	zk.SolCompileAndABIgen("")
	zk.SolGenMain()
	zk.SolGenGoMod()
	zk.SolVerify()
}

func MiMCCircuitZKP(scheme string, inputLen int) {
	curve := gnarkwrapper.CurveMap["BN254"]
	var circuit MiMCCircuit
	circuit.PreCompile(inputLen)
	zk := gnarkwrapper.NewGnarkWrapper(scheme, &circuit, curve)
	zk.Compile()
	zk.Setup()
	circuit.Assign("BN254", inputLen)
	zk.SetAssignment(&circuit)
	zk.Prove()
	zk.Verify()
	zk.ExportSolidity("")
	prootStr := zk.GenSolProofParams()
	logger.Info("proofStr:\n%s", prootStr)
	inputStr := zk.GenSolInputParams()
	logger.Info("inputStr:\n%s", inputStr)
	zk.SolCompileAndABIgen("")
	zk.SolGenMain()
	zk.SolGenGoMod()
	zk.SolVerify()
}

func main() {
	utils.RemoveDir("output")
	SimpleCircuitZKP("groth16", 12)
	utils.RemoveDir("output")
	SimpleCircuitZKP("plonk", 12)
	utils.RemoveDir("output")
	MiMCCircuitZKP("groth16", 12)
	utils.RemoveDir("output")
	MiMCCircuitZKP("plonk", 12)
}
