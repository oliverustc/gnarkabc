package groth16wrapper

import (
	"gnarkabc/circuits"
	"gnarkabc/logger"
	"gnarkabc/utils"
	"testing"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

func TestGenerateInnerProofs4Product(t *testing.T) {
	var circuit circuits.Product
	circuit.PreCompile(nil)
	for _, curveName := range utils.Groth16RecursionCurveList {
		curve := utils.CurveMap[curveName]
		zk := NewWrapper(&circuit, curve)
		zk.Compile()
		zk.Setup()
		p := utils.RandInt(0, 1000)
		q := utils.RandInt(0, 1000)
		assignParams := []any{p, q}
		circuit.Assign(assignParams)
		zk.SetAssignment(&circuit)
		zk.Prove()
		zk.Verify()

		zk.WriteCCS("output/product_" + curveName + ".ccs")
		zk.WriteVK("output/product_" + curveName + ".vk")
		zk.WriteProof("output/product_" + curveName + ".proof")
		zk.WriteWitness("output/product_"+curveName+".wit", false)
	}
}

func ReadProductInnerZK(curveName string) *Groth16Wrapper {
	var innerCircuit circuits.Product
	innerCircuit.PreCompile(nil)
	innerCurve := utils.CurveMap[curveName]
	innerZK := NewWrapper(&innerCircuit, innerCurve)
	innerZK.ReadCCS("output/product_" + curveName + ".ccs")
	innerZK.ReadProof("output/product_" + curveName + ".proof")
	innerZK.ReadVK("output/product_" + curveName + ".vk")
	innerZK.ReadWitness("output/product_"+curveName+".wit", false)
	return innerZK
}

func ProductRecursionBN254InBN254() {
	innerZK := ReadProductInnerZK("BN254")

	var outerCircuit OuterCircuit[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	outerCircuit.PreCompile([]any{innerZK.CCS})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BN254"])
	if !utils.CheckFileExists("output/product_recursion_BN254_BN254.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_BN254_BN254.ccs")
		recursionZK.WritePK("output/product_recursion_BN254_BN254.pk")
		recursionZK.WriteVK("output/product_recursion_BN254_BN254.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_BN254_BN254.ccs")
		recursionZK.ReadPK("output/product_recursion_BN254_BN254.pk")
		recursionZK.ReadVK("output/product_recursion_BN254_BN254.vk")
	}

	assignParams := []any{innerZK.VK, innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BN254] innerProof on [BN254] success, took %v", recursionZK.ProveTime)
}

func ProductRecursionBLS12377InBW6761() {
	innerZK := ReadProductInnerZK("BLS12-377")

	var outerCircuit OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	outerCircuit.PreCompile([]any{innerZK.CCS})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BW6-761"])
	if !utils.CheckFileExists("output/product_recursion_BLS12-377_BW6-761.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_BLS12-377_BW6-761.ccs")
		recursionZK.WritePK("output/product_recursion_BLS12-377_BW6-761.pk")
		recursionZK.WriteVK("output/product_recursion_BLS12-377_BW6-761.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_BLS12-377_BW6-761.ccs")
		recursionZK.ReadPK("output/product_recursion_BLS12-377_BW6-761.pk")
		recursionZK.ReadVK("output/product_recursion_BLS12-377_BW6-761.vk")
	}

	assignParams := []any{innerZK.VK, innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BLS12-377] innerProof on [BW6-761] success, took %v", recursionZK.ProveTime)
}

func ProductRecursionBW6761InBN254() {
	innerZK := ReadProductInnerZK("BW6-761")

	var outerCircuit OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]
	outerCircuit.PreCompile([]any{innerZK.CCS})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BN254"])
	if !utils.CheckFileExists("output/product_recursion_BW6-761_BN254.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_BW6-761_BN254.ccs")
		recursionZK.WritePK("output/product_recursion_BW6-761_BN254.pk")
		recursionZK.WriteVK("output/product_recursion_BW6-761_BN254.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_BW6-761_BN254.ccs")
		recursionZK.ReadPK("output/product_recursion_BW6-761_BN254.pk")
		recursionZK.ReadVK("output/product_recursion_BW6-761_BN254.vk")
	}

	assignParams := []any{innerZK.VK, innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BW6-761] innerProof on [BN254] success, took %v", recursionZK.ProveTime)
}

func TestProductRecursion(t *testing.T) {
	// BN254 in BN254
	ProductRecursionBN254InBN254()
	// BLS12377 in BW6
	ProductRecursionBLS12377InBW6761()
	// BW6-761 in BN254
	ProductRecursionBW6761InBN254()
}

func ProductRecursioConstantBN254InBN254() {
	innerZK := ReadProductInnerZK("BN254")

	var outerCircuit OuterCircuitConstant[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	outerCircuit.PreCompile([]any{innerZK.CCS, innerZK.VK})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BN254"])
	if !utils.CheckFileExists("output/product_recursion_constant_BN254_BN254.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_constant_BN254_BN254.ccs")
		recursionZK.WritePK("output/product_recursion_constant_BN254_BN254.pk")
		recursionZK.WriteVK("output/product_recursion_constant_BN254_BN254.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_constant_BN254_BN254.ccs")
		recursionZK.ReadPK("output/product_recursion_constant_BN254_BN254.pk")
		recursionZK.ReadVK("output/product_recursion_constant_BN254_BN254.vk")
	}

	assignParams := []any{innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BN254] innerProof on [BN254] with constant vk success, took %v", recursionZK.ProveTime)
}

func ProductRecursioConstantBLS12377InBW6761() {
	innerZK := ReadProductInnerZK("BLS12-377")

	var outerCircuit OuterCircuitConstant[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]
	outerCircuit.PreCompile([]any{innerZK.CCS, innerZK.VK})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BW6-761"])
	if !utils.CheckFileExists("output/product_recursion_constant_BLS12-377_BW6-761.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_constant_BLS12-377_BW6-761.ccs")
		recursionZK.WritePK("output/product_recursion_constant_BLS12-377_BW6-761.pk")
		recursionZK.WriteVK("output/product_recursion_constant_BLS12-377_BW6-761.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_constant_BLS12-377_BW6-761.ccs")
		recursionZK.ReadPK("output/product_recursion_constant_BLS12-377_BW6-761.pk")
		recursionZK.ReadVK("output/product_recursion_constant_BLS12-377_BW6-761.vk")
	}

	assignParams := []any{innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BLS12-377] innerProof on [BW6-761] with constant vk success, took %v", recursionZK.ProveTime)
}

func ProductRecursioConstantBW6761InBN254() {
	innerZK := ReadProductInnerZK("BW6-761")

	var outerCircuit OuterCircuitConstant[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]
	outerCircuit.PreCompile([]any{innerZK.CCS, innerZK.VK})
	recursionZK := NewWrapper(&outerCircuit, utils.CurveMap["BN254"])
	if !utils.CheckFileExists("output/product_recursion_constant_BW6-761_BN254.vk") {
		recursionZK.Compile()
		recursionZK.Setup()
		recursionZK.WriteCCS("output/product_recursion_constant_BW6-761_BN254.ccs")
		recursionZK.WritePK("output/product_recursion_constant_BW6-761_BN254.pk")
		recursionZK.WriteVK("output/product_recursion_constant_BW6-761_BN254.vk")
	} else {
		recursionZK.ReadCCS("output/product_recursion_constant_BW6-761_BN254.ccs")
		recursionZK.ReadPK("output/product_recursion_constant_BW6-761_BN254.pk")
		recursionZK.ReadVK("output/product_recursion_constant_BW6-761_BN254.vk")
	}

	assignParams := []any{innerZK.WitnessFull, innerZK.Proof}
	outerCircuit.Assign(assignParams)
	recursionZK.SetAssignment(&outerCircuit)
	recursionZK.Prove()
	recursionZK.Verify()
	logger.Info("recursive prove [BW6-761] innerProof on [BN254] with constant vk success, took %v", recursionZK.ProveTime)
}

func TestProductRecursionConstant(t *testing.T) {
	ProductRecursioConstantBN254InBN254()
	ProductRecursioConstantBLS12377InBW6761()
	ProductRecursioConstantBW6761InBN254()
}
