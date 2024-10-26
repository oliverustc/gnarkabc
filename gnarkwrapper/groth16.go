package gnarkwrapper

import (
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"gnarkabc/logger"
)

type Groth16 struct {
	Circuit       frontend.Circuit
	Curve         ecc.ID
	Field         *big.Int
	Assignment    frontend.Circuit
	WitnessFull   witness.Witness
	WitnessPublic witness.Witness
	CCS           constraint.ConstraintSystem
	PK            groth16.ProvingKey
	VK            groth16.VerifyingKey
	Proof         groth16.Proof

	CompileTime time.Duration
	SetupTime   time.Duration
	ProveTime   time.Duration
	VerifyTime  time.Duration
}

func NewGroth16(circuit frontend.Circuit, curve ecc.ID) *Groth16 {
	return &Groth16{
		Circuit: circuit,
		Curve:   curve,
		Field:   curve.ScalarField(),
	}
}

func (g *Groth16) Compile() error {
	logger.Debug("compiling circuit ...")
	var err error
	start := time.Now()
	g.CCS, err = frontend.Compile(g.Field, r1cs.NewBuilder, g.Circuit)
	if err != nil {
		logger.Error("compile circuit failed. " + err.Error())
		return err
	}
	g.CompileTime = time.Since(start)
	logger.Debug("circuit compiled, took: " + g.CompileTime.String())
	return nil
}

func (g *Groth16) Setup() error {
	logger.Debug("setting up circuit ...")
	var err error
	start := time.Now()
	g.PK, g.VK, err = groth16.Setup(g.CCS)
	if err != nil {
		logger.Error("setup circuit failed. " + err.Error())
		return err
	}
	g.SetupTime = time.Since(start)
	logger.Debug("circuit setup, took: " + g.SetupTime.String())
	return nil
}

func (g *Groth16) generateWitness(publicOnly bool) (witness.Witness, error) {
	var opts []frontend.WitnessOption
	if publicOnly {
		opts = append(opts, frontend.PublicOnly())
	}
	return frontend.NewWitness(g.Assignment, g.Field, opts...)
}

func (g *Groth16) Prove() error {
	logger.Debug("proving ...")
	var err error
	start := time.Now()
	g.WitnessFull, err = g.generateWitness(false)
	if err != nil {
		logger.Error("generate witness failed. " + err.Error())
		return err
	}
	g.Proof, err = groth16.Prove(g.CCS, g.PK, g.WitnessFull)
	if err != nil {
		logger.Error("prove failed. " + err.Error())
		return err
	}
	g.ProveTime = time.Since(start)
	logger.Debug("circuit proved, took: " + g.ProveTime.String())
	return nil
}

func (g *Groth16) Verify() {
	logger.Debug("verifying ...")
	var err error
	start := time.Now()
	g.WitnessPublic, err = g.generateWitness(true)
	if err != nil {
		logger.Fatal("generate public witness failed. " + err.Error())
	}
	err = groth16.Verify(g.Proof, g.VK, g.WitnessPublic)
	if err != nil {
		logger.Fatal("verify proof failed.")
	} else {
		logger.Debug("circuit verified")
	}
	g.VerifyTime = time.Since(start)
	logger.Debug("circuit verified, took: " + g.VerifyTime.String())
}

func (g *Groth16) BenchmarkCompile(iterations int) {
	logger.Debug("benchmarking compiling circuit ...")
	var compileTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Compile()
		compileTime += g.CompileTime
	}
	g.CompileTime = compileTime / time.Duration(iterations)
}

func (g *Groth16) BenchmarkSetup(iterations int) {
	logger.Debug("benchmarking setup circuit ...")
	var setupTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Setup()
		setupTime += g.SetupTime
	}
	g.SetupTime = setupTime / time.Duration(iterations)
}

func (g *Groth16) BenchmarkProve(iterations int) {
	logger.Debug("benchmarking proving circuit ...")
	var proveTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Prove()
		proveTime += g.ProveTime
	}
	g.ProveTime = proveTime / time.Duration(iterations)
}

func (g *Groth16) BenchmarkVerify(iterations int) {
	logger.Debug("benchmarking verifying circuit ...")
	var verifyTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Verify()
		verifyTime += g.VerifyTime
	}
	g.VerifyTime = verifyTime / time.Duration(iterations)
}
