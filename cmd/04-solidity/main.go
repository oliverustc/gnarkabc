package main

import (
	"bytes"
	"crypto/rand"
	"gnarkabc/gnarkwrapper"
	"gnarkabc/hash/mimchash"
	"gnarkabc/logger"
	"math/big"
	"os"

	"github.com/consensys/gnark/frontend"
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

func (c *SimpleCircuit) PreCompile(params ...interface{}) {

}
func (c *SimpleCircuit) Assign(curveName string, params ...interface{}) {
	c.P = 4
	c.Q = 8
	c.N = 32
}

func (c *SimpleCircuit) Assign2(curveName string, params ...interface{}) {
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

func SimpleZKP(scheme string, inputLen int) {
	var circuit SimpleCircuit
	circuit.PreCompile(inputLen)
	curveName := "BN254"
	curve := mimchash.MiMCCaseMap[curveName]
	circuit.PreCompile(inputLen)
	zk := gnarkwrapper.NewGnarkWrapper(scheme, &circuit, curve.Curve)
	zk.Compile()
	zk.Setup()

	var assign SimpleCircuit
	assign.Assign(curveName, inputLen)
	zk.SetAssignment(&assign)
	zk.Prove()
	zk.Verify()
	logger.Info("prove success")

	solidityFile, err := os.OpenFile("solidity/Verifier.sol", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer solidityFile.Close()

	proofFile, err := os.OpenFile("solidity/proof", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer proofFile.Close()

	rawProofFile, err := os.OpenFile("solidity/rawProof", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer rawProofFile.Close()

	publicWitness, err := os.OpenFile("solidity/publicWitness", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer publicWitness.Close()

	var buffer bytes.Buffer
	switch scheme {
	case "groth16":

		wrapper := zk.(*gnarkwrapper.Groth16Wrapper)
		logger.Info("export solidity")
		wrapper.VK.ExportSolidity(solidityFile)
		logger.Info("write proof")

		wrapper.Proof.WriteRawTo(&buffer)
		logger.Info("proof: %v", buffer.Bytes())
		logger.Info("proof len: %v", len(buffer.Bytes()))
		// clean the buffer
		buffer.Reset()
		wrapper.Proof.WriteTo(&buffer)
		logger.Info("proof: %v", buffer.Bytes())
		logger.Info("proof len: %v", len(buffer.Bytes()))
		wrapper.Proof.WriteTo(proofFile)
		wrapper.Proof.WriteRawTo(rawProofFile)
		logger.Info("write public witness")
		wrapper.WitnessPublic.WriteTo(publicWitness)
	case "plonk":
		wrapper := zk.(*gnarkwrapper.PlonkWrapper)
		wrapper.VK.ExportSolidity(solidityFile)
		wrapper.Proof.WriteRawTo(proofFile)
		wrapper.WitnessPublic.WriteTo(publicWitness)
	}

}

func main() {
	SimpleZKP("groth16", 12)
}
