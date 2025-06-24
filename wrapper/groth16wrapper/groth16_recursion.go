package groth16wrapper

import (
	"fmt"
	"gnarkabc/logger"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	recursion_groth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        recursion_groth16.Proof[G1El, G2El]
	VerifyingKey recursion_groth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness recursion_groth16.Witness[FR]
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := recursion_groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}
	return verifier.AssertProof(oc.VerifyingKey, oc.Proof, oc.InnerWitness)
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) PreCompile(params any) {
	innerCCS := params.([]any)[0].(constraint.ConstraintSystem)
	oc.Proof = recursion_groth16.PlaceholderProof[G1El, G2El](innerCCS)
	oc.VerifyingKey = recursion_groth16.PlaceholderVerifyingKey[G1El, G2El, GtEl](innerCCS)
	oc.InnerWitness = recursion_groth16.PlaceholderWitness[FR](innerCCS)
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) Assign(params any) {
	// 将params转换为切片以处理多个参数
	args := params.([]any)
	if len(args) != 3 {
		panic("Assign params must be []any with length 3")
	}

	innerVK := args[0].(groth16.VerifyingKey)
	innerWitness := args[1].(witness.Witness)
	innerProof := args[2].(groth16.Proof)

	circuitVK, err := recursion_groth16.ValueOfVerifyingKey[G1El, G2El, GtEl](innerVK)
	if err != nil {
		logger.Fatal("failed to convert verifying key: %v", err)
	}
	circuitWitness, err := recursion_groth16.ValueOfWitness[FR](innerWitness)
	if err != nil {
		logger.Fatal("failed to convert witness: %v", err)
	}
	circuitProof, err := recursion_groth16.ValueOfProof[G1El, G2El](innerProof)
	if err != nil {
		logger.Fatal("failed to convert proof: %v", err)
	}

	oc.VerifyingKey = circuitVK
	oc.InnerWitness = circuitWitness
	oc.Proof = circuitProof
}

type OuterCircuitConstant[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        recursion_groth16.Proof[G1El, G2El]
	vk           recursion_groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness recursion_groth16.Witness[FR]
}

func (oc *OuterCircuitConstant[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := recursion_groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}
	return verifier.AssertProof(oc.vk, oc.Proof, oc.InnerWitness)
}

func (oc *OuterCircuitConstant[FR, G1El, G2El, GtEl]) PreCompile(params any) {
	innerCCS := params.([]any)[0].(constraint.ConstraintSystem)
	oc.InnerWitness = recursion_groth16.PlaceholderWitness[FR](innerCCS)
	innerVK := params.([]any)[1].(groth16.VerifyingKey)
	circuitVK, err := recursion_groth16.ValueOfVerifyingKeyFixed[G1El, G2El, GtEl](innerVK)
	if err != nil {
		logger.Fatal("failed to convert verifying key: %v", err)
	}
	oc.vk = circuitVK
}

func (oc *OuterCircuitConstant[FR, G1El, G2El, GtEl]) Assign(params any) {
	innerWitnes := params.([]any)[0].(witness.Witness)
	innerProof := params.([]any)[1].(groth16.Proof)
	circuitWitness, err := recursion_groth16.ValueOfWitness[FR](innerWitnes)
	if err != nil {
		logger.Fatal("failed to convert witness: %v", err)
	}
	circuitProof, err := recursion_groth16.ValueOfProof[G1El, G2El](innerProof)
	if err != nil {
		logger.Fatal("failed to convert proof: %v", err)
	}
	oc.InnerWitness = circuitWitness
	oc.Proof = circuitProof
}
