package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

// InnerCircuitNative is the definition of the inner circuit we want to
// recursively verify inside an outer circuit. The circuit proves the knowledge
// of a factorisation of a semiprime.
type InnerCircuitNative struct {
	P, Q frontend.Variable
	N    frontend.Variable `gnark:",public"`
}

func (c *InnerCircuitNative) Define(api frontend.API) error {
	// prove that P*Q == N
	res := api.Mul(c.P, c.Q)
	api.AssertIsEqual(res, c.N)
	// we must also enforce that P != 1 and Q != 1
	api.AssertIsDifferent(c.P, 1)
	api.AssertIsDifferent(c.Q, 1)
	return nil
}

// computeInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the PLONK keys are generated on the fly, but
// in practice should be generated once and using MPC.
func computeInnerProof(field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitNative{})
	if err != nil {
		panic(err)
	}
	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	// inner proof
	innerAssignment := &InnerCircuitNative{
		P: 3,
		Q: 5,
		N: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		panic(err)
	}
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outer, field))
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, plonk.GetNativeVerifierOptions(outer, field))
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof
}

type RecursionAggregate[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof        plonk.Proof[FR, G1El, G2El]
	PreviousVerifyingKey plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	PreviousWitness      plonk.Witness[FR]                  `gnark:",public"`
	Proof                plonk.Proof[FR, G1El, G2El]
	VerifyingKey         plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	Witness              plonk.Witness[FR]                  `gnark:",public"`
}

func (c *RecursionAggregate[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.PreviousVerifyingKey, c.PreviousProof, c.PreviousWitness)
	if err != nil {
		return err
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.Witness)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	// compute the proof which we want to verify recursively
	innerCcs0, innerVK0, innerWitness0, innerProof0 := computeInnerProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
	innerCcs1, innerVK1, innerWitness1, innerProof1 := computeInnerProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
	// initialize the witness elements
	circuitVk0, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK0)
	if err != nil {
		panic(err)
	}
	circuitVk1, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerVK1)
	if err != nil {
		panic(err)
	}

	ra := RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreviousVerifyingKey: circuitVk0,
		PreviousProof:        plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs0),
		PreviousWitness:      plonk.PlaceholderWitness[sw_bn254.ScalarField](innerCcs0),
		VerifyingKey:         circuitVk1,
		Witness:              plonk.PlaceholderWitness[sw_bn254.ScalarField](innerCcs1),
		Proof:                plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs1),
	}

	circuitWitness0, err := plonk.ValueOfWitness[sw_bn254.ScalarField](innerWitness0)
	if err != nil {
		panic(err)
	}
	circuitProof0, err := plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof0)
	if err != nil {
		panic(err)
	}
	circuitWitness1, err := plonk.ValueOfWitness[sw_bn254.ScalarField](innerWitness1)
	if err != nil {
		panic(err)
	}
	circuitProof1, err := plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](innerProof1)
	if err != nil {
		panic(err)
	}

	raAssign := RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
		PreviousProof:   circuitProof0,
		PreviousWitness: circuitWitness0,
		Witness:         circuitWitness1,
		Proof:           circuitProof1,
	}

	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &ra)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(&raAssign, ecc.BN254.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	recursionCircuitVK, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	if err != nil {
		panic(err)
	}
	recursionCircuitProof, err := plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](outerProof)
	if err != nil {
		panic(err)
	}
	recursionCircuitWitness, err := plonk.ValueOfWitness[sw_bn254.ScalarField](publicWitness)
	if err != nil {
		panic(err)
	}

	for range 3 {
		newCcs, newVK, newWitness, newProof := computeInnerProof(ecc.BN254.ScalarField(), ecc.BN254.ScalarField())
		circuitNewVK, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](newVK)
		if err != nil {
			panic(err)
		}
		newRA := RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			PreviousVerifyingKey: recursionCircuitVK,
			VerifyingKey:         circuitNewVK,
			PreviousProof:        plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
			PreviousWitness:      plonk.PlaceholderWitness[sw_bn254.ScalarField](ccs),
			Witness:              plonk.PlaceholderWitness[sw_bn254.ScalarField](newCcs),
			Proof:                plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](newCcs),
		}
		newCircuitWitness, err := plonk.ValueOfWitness[sw_bn254.ScalarField](newWitness)
		if err != nil {
			panic(err)
		}
		newCircuitProof, err := plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](newProof)
		if err != nil {
			panic(err)
		}

		newRAAssign := RecursionAggregate[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{
			PreviousProof:   recursionCircuitProof,
			PreviousWitness: recursionCircuitWitness,
			Witness:         newCircuitWitness,
			Proof:           newCircuitProof,
		}

		newRecursionCCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &newRA)
		if err != nil {
			panic(err)
		}
		newRecursionSRS, newRecursionSRSLagrange, err := unsafekzg.NewSRS(newRecursionCCS)
		if err != nil {
			panic(err)
		}

		newRecursionPK, newRecursionVK, err := native_plonk.Setup(newRecursionCCS, newRecursionSRS, newRecursionSRSLagrange)
		if err != nil {
			panic(err)
		}

		newRecursionWitness, err := frontend.NewWitness(&newRAAssign, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}
		newRecursionPubWitness, err := newRecursionWitness.Public()
		if err != nil {
			panic(err)
		}
		newRecursionProof, err := native_plonk.Prove(newRecursionCCS, newRecursionPK, newRecursionWitness, plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		if err != nil {
			panic(err)
		}
		err = native_plonk.Verify(newRecursionProof, newRecursionVK, newRecursionPubWitness, plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
		if err != nil {
			panic(err)
		}
		// 进入下一轮循环，更新相关参数
		recursionCircuitVK, err = plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](newRecursionVK)
		if err != nil {
			panic(err)
		}
		recursionCircuitProof, err = plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](newRecursionProof)
		if err != nil {
			panic(err)
		}
		recursionCircuitWitness, err = plonk.ValueOfWitness[sw_bn254.ScalarField](newRecursionWitness)
		if err != nil {
			panic(err)
		}
		ccs = newRecursionCCS
	}
}
