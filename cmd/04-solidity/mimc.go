package main

import (
	"gnarkabc/gnarkwrapper"
	"gnarkabc/hash/mimchash"
	"gnarkabc/utils"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

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
	input := params[0].(string)
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

func MiMCZKP(scheme string, inputLen int) {
	var circuit MiMCCircuit
	circuit.PreCompile(inputLen)
	curveName := "BN254"
	curve := mimchash.MiMCCaseMap[curveName]
	circuit.PreCompile(inputLen)
	zk := gnarkwrapper.NewGnarkWrapper(scheme, &circuit, curve.Curve)
	zk.Compile()
	zk.Setup()

	var assign MiMCCircuit
	input := utils.RandStr(inputLen)
	assign.Assign(curveName, input)
	zk.SetAssignment(&assign)
	zk.Prove()
	zk.Verify()

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

	publicWitness, err := os.OpenFile("solidity/publicWitness", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer publicWitness.Close()

	switch scheme {
	case "groth16":
		wrapper := zk.(*gnarkwrapper.Groth16Wrapper)
		wrapper.VK.ExportSolidity(solidityFile)
		wrapper.Proof.WriteTo(proofFile)
		wrapper.WitnessPublic.WriteTo(publicWitness)
	case "plonk":
		wrapper := zk.(*gnarkwrapper.PlonkWrapper)
		wrapper.VK.ExportSolidity(solidityFile)
		wrapper.Proof.WriteTo(proofFile)
		wrapper.WitnessPublic.WriteTo(publicWitness)
	}

}
