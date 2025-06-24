package groth16wrapper

import (
	"testing"

	"gnarkabc/circuits"
	"gnarkabc/utils"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestRemoveFileGroth16(t *testing.T) {
	utils.RemoveFile("output/Groth16Verifier.sol")
	utils.RemoveFile("output/combined.json")
	utils.RemoveFile("output/gnark_solidity.go")
	utils.RemoveFile("output/main.go")
	utils.RemoveDir("output")
}

func TestGroth16GenSolParams(t *testing.T) {
	TestRemoveFileGroth16(t)
	var circuit circuits.Product
	circuit.PreCompile(nil)
	zk := NewWrapper(&circuit, ecc.BN254)
	zk.Compile()
	zk.Setup()
	assignParams := []any{13, 17}
	circuit.Assign(assignParams)
	zk.SetAssignment(&circuit)
	zk.Prove()
	zk.Verify()
	zk.ExportSolidity("")
	prootStr := zk.GenSolProofParams()
	t.Logf("proofStr:\n%s", prootStr)
	inputStr := zk.GenSolInputParams()
	t.Logf("inputStr:\n%s", inputStr)
	zk.SolCompileAndABIgen("")
	zk.SolGenMain()
	zk.SolGenGoMod()
	zk.SolVerify()
}
