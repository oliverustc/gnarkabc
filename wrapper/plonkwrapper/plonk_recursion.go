package plonkwrapper

import (
	"fmt"
	"gnarkabc/logger"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	recursion_plonk "github.com/consensys/gnark/std/recursion/plonk"
)

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        recursion_plonk.Proof[FR, G1El, G2El]
	VerifyingKey recursion_plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitness recursion_plonk.Witness[FR]                  `gnark:",public"`
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := recursion_plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	err = verifier.AssertProof(oc.VerifyingKey, oc.Proof, oc.InnerWitness, recursion_plonk.WithCompleteArithmetic())
	return err
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) PreCompile(params any) {
	innerCCS := params.([]any)[0].(constraint.ConstraintSystem)
	oc.Proof = recursion_plonk.PlaceholderProof[FR, G1El, G2El](innerCCS)
	oc.InnerWitness = recursion_plonk.PlaceholderWitness[FR](innerCCS)
	innerVK := params.([]any)[1].(plonk.VerifyingKey)
	circuitVK, err := recursion_plonk.ValueOfVerifyingKey[FR, G1El, G2El](innerVK)
	if err != nil {
		logger.Fatal("failed to convert verifying key: %v", err)
	}
	oc.VerifyingKey = circuitVK
}

func (oc *OuterCircuit[FR, G1El, G2El, GtEl]) Assign(params any) {
	innerWitness := params.([]any)[0].(witness.Witness)
	innerProof := params.([]any)[1].(plonk.Proof)

	circuitWitness, err := recursion_plonk.ValueOfWitness[FR](innerWitness)
	if err != nil {
		logger.Fatal("failed to convert witness: %v", err)
	}
	circuitProof, err := recursion_plonk.ValueOfProof[FR, G1El, G2El](innerProof)
	if err != nil {
		logger.Fatal("failed to convert proof: %v", err)
	}
	oc.InnerWitness = circuitWitness
	oc.Proof = circuitProof
}
