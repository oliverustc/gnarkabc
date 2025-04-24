package main

import (
	"strconv"

	"gnarkabc/circuits"
	"gnarkabc/logger"
	"gnarkabc/utils"
	"gnarkabc/wrapper/groth16wrapper"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type DummyAggregate struct {
	Proofs       [5]stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	PublicInputs [5]stdgroth16.Witness[sw_bn254.ScalarField]
	verifyingKey stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	PublicHash   frontend.Variable                                                            `gnark:",public"`
}

func (c *DummyAggregate) Define(api frontend.API) error {
	hashFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hashFunc.Reset()
	for i := range 5 {
		for _, input := range c.PublicInputs[i].Public {
			hashFunc.Write(input.Limbs...)
		}
	}
	api.AssertIsEqual(c.PublicHash, hashFunc.Sum())
	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return err
	}
	for i := range 5 {
		verifier.AssertProof(c.verifyingKey, c.Proofs[i], c.PublicInputs[i])
	}
	return nil
}

func GenerateGroth16InnerProofs() {
	curve := utils.CurveMap["BN254"]
	var circuit circuits.Product
	circuit.PreCompile(nil)
	g := groth16wrapper.NewWrapper(&circuit, curve)
	g.Compile()
	g.Setup()
	g.WriteCCS("output/groth16_ccs")
	g.WritePK("output/groth16_pk")
	g.WriteVK("output/groth16_vk")
	for i := 0; i < 5; i++ {
		p := utils.RandInt(0, 100)
		q := utils.RandInt(0, 100)
		circuit.Assign([]interface{}{p, q})
		g.SetAssignment(&circuit)
		g.Prove()
		g.Verify()
		g.WriteProof("output/groth16_proof_" + strconv.Itoa(i))
		g.WriteWitness("output/groth16_witness_"+strconv.Itoa(i), false)
	}
}

func (c *DummyAggregate) PreCompile(params interface{}) {
	curve := utils.CurveMap["BN254"]
	var circuit circuits.Product
	circuit.PreCompile(nil)
	g := groth16wrapper.NewWrapper(&circuit, curve)
	g.ReadCCS("output/groth16_ccs")
	g.ReadPK("output/groth16_pk")
	g.ReadVK("output/groth16_vk")
	g.ReadProof("output/groth16_proof_0")
	g.ReadWitness("output/groth16_witness_0", false)

	circuitVK, err := stdgroth16.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](g.VK)
	if err != nil {
		logger.Info("failed to during ValueofVerifyingKey, %v", err)
	}
	c.verifyingKey = circuitVK
	witnessPlaceholder := stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](g.CCS)
	proofPlaceholder := stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](g.CCS)
	for i := 0; i < 5; i++ {
		c.Proofs[i] = proofPlaceholder
		c.PublicInputs[i] = witnessPlaceholder
	}
}

func (c *DummyAggregate) Assign(params interface{}) {
	curve := utils.CurveMap["BN254"]
	var circuit circuits.Product
	circuit.PreCompile(nil)
	g := groth16wrapper.NewWrapper(&circuit, curve)
	g.ReadCCS("output/groth16_ccs")
	g.ReadPK("output/groth16_pk")
	g.ReadVK("output/groth16_vk")

	for i := 0; i < 5; i++ {
		g.ReadProof("output/groth16_proof_" + strconv.Itoa(i))
		g.ReadWitness("output/groth16_witness_"+strconv.Itoa(i), false)

		circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](g.WitnessFull)
		if err != nil {
			logger.Info("failed to during ValueofWitness, %v", err)
		}
		circuitProof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](g.Proof)
		if err != nil {
			logger.Info("failed to during ValueofProof, %v", err)
		}
		c.PublicInputs[i] = circuitWitness
		c.Proofs[i] = circuitProof
	}
}

func main() {
	if !utils.CheckFileExists("output/groth16_proof_4") {
		GenerateGroth16InnerProofs()
	}
	var g *groth16wrapper.Groth16Wrapper
	if !utils.CheckFileExists("output/aggregate_ccs") {
		var circuit DummyAggregate
		circuit.PreCompile(nil)
		g = groth16wrapper.NewWrapper(&circuit, utils.CurveMap["BN254"])
		g.Compile()
		g.WriteCCS("output/aggregate_ccs")
	} else {
		var circuit DummyAggregate
		circuit.PreCompile(nil)
		g = groth16wrapper.NewWrapper(&circuit, utils.CurveMap["BN254"])
		g.ReadCCS("output/aggregate_ccs")
	}

	if !utils.CheckFileExists("output/aggregate_pk") {
		g.Setup()
		g.WritePK("output/aggregate_pk")
		g.WriteVK("output/aggregate_vk")
	} else {
		g.ReadPK("output/aggregate_pk")
		g.ReadVK("output/aggregate_vk")
	}

	var circuit DummyAggregate
	circuit.PreCompile(nil)
	g.SetAssignment(&circuit)
	g.Prove()
	g.Verify()

}
