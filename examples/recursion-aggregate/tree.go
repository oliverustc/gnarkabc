package main

import (
	"fmt"

	"gnarkabc/logger"
	"gnarkabc/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	std_groth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type LeafCircuit struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *LeafCircuit) Define(api frontend.API) error {
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

func GenerateLeafProof(num int) {
	curve := ecc.BN254
	field := curve.ScalarField()
	outer := curve.ScalarField()
	leafCCS, _ := frontend.Compile(field, r1cs.NewBuilder, &LeafCircuit{})
	leafPK, leafVK, _ := groth16.Setup(leafCCS)
	WriteCCS(leafCCS, "output/layer_0_ccs")
	WritePK(leafPK, "output/layer_0_pk")
	WriteVK(leafVK, "output/layer_0_vk")
	for i := 0; i < num; i++ {
		p := utils.RandInt(0, 100)
		q := utils.RandInt(0, 100)
		leafAssignment := &LeafCircuit{
			P: p,
			Q: q,
			N: p * q,
		}
		leafWitness, _ := frontend.NewWitness(leafAssignment, field)
		leafProof, _ := groth16.Prove(leafCCS, leafPK, leafWitness, std_groth16.GetNativeProverOptions(outer, field))
		leafPubWitness, _ := leafWitness.Public()
		_ = groth16.Verify(leafProof, leafVK, leafPubWitness, std_groth16.GetNativeVerifierOptions(outer, field))
		WriteProof(leafProof, fmt.Sprintf("output/layer_0_proof_%d", i))
		WriteWitness(leafPubWitness, fmt.Sprintf("output/layer_0_witness_%d", i))
	}
}

type RecursionAggregate[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	LeftProof         std_groth16.Proof[G1El, G2El]
	LeftVerifyingKey  std_groth16.VerifyingKey[G1El, G2El, GtEl]
	LeftWitness       std_groth16.Witness[FR] `gnark:",public"`
	RightProof        std_groth16.Proof[G1El, G2El]
	RightVerifyingKey std_groth16.VerifyingKey[G1El, G2El, GtEl]
	RightWitness      std_groth16.Witness[FR] `gnark:",public"`
}

func (c *RecursionAggregate[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := std_groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.LeftVerifyingKey, c.LeftProof, c.LeftWitness)
	if err != nil {
		return err
	}
	err = verifier.AssertProof(c.RightVerifyingKey, c.RightProof, c.RightWitness)
	if err != nil {
		return err
	}
	return nil
}

func RecursionAggregateProof(leftIndex, rightIndex, depth int) {
	curve := ecc.BN254
	field := curve.ScalarField()
	newDepth := depth + 1
	var parentCCS constraint.ConstraintSystem
	var parentPK groth16.ProvingKey
	var parentVK groth16.VerifyingKey
	if !utils.CheckFileExists(fmt.Sprintf("output/layer_%d_vk", newDepth)) {
		logger.Info("parent layer_%d_vk not exists, compile and setup first", newDepth)
		childCCS := ReadCCS(curve, fmt.Sprintf("output/layer_%d_ccs", depth))
		ac := &RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			LeftWitness:       std_groth16.PlaceholderWitness[sw_bn254.ScalarField](childCCS),
			RightWitness:      std_groth16.PlaceholderWitness[sw_bn254.ScalarField](childCCS),
			LeftVerifyingKey:  std_groth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](childCCS),
			RightVerifyingKey: std_groth16.PlaceholderVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](childCCS),
		}
		parentCCS, _ = frontend.Compile(field, r1cs.NewBuilder, ac)
		WriteCCS(parentCCS, fmt.Sprintf("output/layer_%d_ccs", newDepth))
		parentPK, parentVK, _ = groth16.Setup(parentCCS)
		WritePK(parentPK, fmt.Sprintf("output/layer_%d_pk", newDepth))
		WriteVK(parentVK, fmt.Sprintf("output/layer_%d_vk", newDepth))
	} else {
		parentCCS = ReadCCS(curve, fmt.Sprintf("output/layer_%d_ccs", newDepth))
		parentPK = ReadPK(curve, fmt.Sprintf("output/layer_%d_pk", newDepth))
		parentVK = ReadVK(curve, fmt.Sprintf("output/layer_%d_vk", newDepth))
	}
	childVK := ReadVK(curve, fmt.Sprintf("output/layer_%d_vk", depth))
	leftChildProof := ReadProof(curve, fmt.Sprintf("output/layer_%d_proof_%d", depth, leftIndex))
	rightChildProof := ReadProof(curve, fmt.Sprintf("output/layer_%d_proof_%d", depth, rightIndex))
	leftChildWitness := ReadWitness(curve, fmt.Sprintf("output/layer_%d_witness_%d", depth, leftIndex))
	rightChildWitness := ReadWitness(curve, fmt.Sprintf("output/layer_%d_witness_%d", depth, rightIndex))

	circuitChildVK, _ := std_groth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](childVK)
	circuitLeftChildProof, _ := std_groth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leftChildProof)
	circuitRightChildProof, _ := std_groth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](rightChildProof)
	circuitLeftChildWitness, _ := std_groth16.ValueOfWitness[sw_bn254.ScalarField](leftChildWitness)
	circuitRightChildWitness, _ := std_groth16.ValueOfWitness[sw_bn254.ScalarField](rightChildWitness)

	acAssign := &RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		LeftProof:         circuitLeftChildProof,
		LeftVerifyingKey:  circuitChildVK,
		LeftWitness:       circuitLeftChildWitness,
		RightProof:        circuitRightChildProof,
		RightVerifyingKey: circuitChildVK,
		RightWitness:      circuitRightChildWitness,
	}
	aggregateWitness, _ := frontend.NewWitness(acAssign, field)
	aggregateProof, _ := groth16.Prove(parentCCS, parentPK, aggregateWitness)
	aggregatePubWitness, _ := aggregateWitness.Public()
	_ = groth16.Verify(aggregateProof, parentVK, aggregatePubWitness)
	WriteProof(aggregateProof, fmt.Sprintf("output/layer_%d_proof_%d", newDepth, leftIndex))
	WriteWitness(aggregatePubWitness, fmt.Sprintf("output/layer_%d_witness_%d", newDepth, leftIndex))
}

func RecursionAggregateLeafProofs(indexList []int, depth int) {
	for i := 0; i < len(indexList); i += 2 {
		RecursionAggregateProof(indexList[i], indexList[i+1], depth)
	}
}
