package gnarkwrapper

import (
	"gnarkabc/logger"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	bls12_377cs "github.com/consensys/gnark/constraint/bls12-377"
	bls12_381cs "github.com/consensys/gnark/constraint/bls12-381"
	bls24_315cs "github.com/consensys/gnark/constraint/bls24-315"
	bls24_317cs "github.com/consensys/gnark/constraint/bls24-317"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	bw6_633cs "github.com/consensys/gnark/constraint/bw6-633"
	bw6_761cs "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

type Plonk struct {
	Circuit       frontend.Circuit
	Curve         ecc.ID
	Field         *big.Int
	Assignment    frontend.Circuit
	WitnessFull   witness.Witness
	WitnessPublic witness.Witness
	CCS           constraint.ConstraintSystem
	PK            plonk.ProvingKey
	VK            plonk.VerifyingKey
	Proof         plonk.Proof

	CompileTime time.Duration
	SetupTime   time.Duration
	ProveTime   time.Duration
	VerifyTime  time.Duration
}

func NewPlonk(circuit frontend.Circuit, curve ecc.ID) *Plonk {
	return &Plonk{
		Circuit: circuit,
		Curve:   curve,
		Field:   curve.ScalarField(),
	}
}

func (p *Plonk) Compile() {
	logger.Debug("compiling circuit ...")
	var err error
	start := time.Now()
	p.CCS, err = frontend.Compile(p.Field, scs.NewBuilder, p.Circuit)
	if err != nil {
		logger.Fatal("compile circuit failed. " + err.Error())
	}
	p.CompileTime = time.Since(start)
	logger.Debug("circuit compiled, took: " + p.CompileTime.String())
}

func (p *Plonk) Setup2() {
	logger.Debug("setting up circuit ...")
	start := time.Now()
	scs := p.CCS.(*bls12_377cs.SparseR1CS)

	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	if err != nil {
		logger.Fatal("create SRS failed. " + err.Error())
	}
	pk, vk, err := plonk.Setup(p.CCS, srs, srsLagrange)
	if err != nil {
		logger.Fatal("setup circuit failed. " + err.Error())
	}
	p.SetupTime = time.Since(start)
	logger.Debug("circuit setup, took: " + p.SetupTime.String())
	p.PK = pk
	p.VK = vk
}

func (p *Plonk) Setup() {
	logger.Debug("setting up circuit ...")
	var srs, srsLagrange kzg.SRS
	var err error
	start := time.Now()
	switch p.Curve {
	case ecc.BN254:
		scs := p.CCS.(*bn254cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BLS12_377:
		scs := p.CCS.(*bls12_377cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BLS12_381:
		scs := p.CCS.(*bls12_381cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BW6_761:
		scs := p.CCS.(*bw6_761cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BLS24_315:
		scs := p.CCS.(*bls24_315cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BW6_633:
		scs := p.CCS.(*bw6_633cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	case ecc.BLS24_317:
		scs := p.CCS.(*bls24_317cs.SparseR1CS)
		srs, srsLagrange, err = unsafekzg.NewSRS(scs)
	}
	if err != nil {
		logger.Fatal("create SRS failed. " + err.Error())
	}
	p.PK, p.VK, err = plonk.Setup(p.CCS, srs, srsLagrange)
	if err != nil {
		logger.Fatal("setup circuit failed. " + err.Error())
	}
	p.SetupTime = time.Since(start)
	logger.Debug("circuit setup, took: " + p.SetupTime.String())
}

func (p *Plonk) Prove() {
	logger.Debug("proving circuit ...")
	var err error
	start := time.Now()
	p.WitnessFull, err = frontend.NewWitness(p.Assignment, p.Field)
	if err != nil {
		logger.Fatal("generate witness failed. " + err.Error())
	}
	p.Proof, err = plonk.Prove(p.CCS, p.PK, p.WitnessFull)
	if err != nil {
		logger.Fatal("prove circuit failed. " + err.Error())
	}
	p.ProveTime = time.Since(start)
	logger.Debug("circuit proved, took: " + p.ProveTime.String())
}

func (p *Plonk) Verify() {
	logger.Debug("verifying circuit ...")
	var err error
	start := time.Now()
	p.WitnessPublic, err = frontend.NewWitness(p.Assignment, p.Field, frontend.PublicOnly())
	if err != nil {
		logger.Fatal("generate public witness failed. " + err.Error())
	}
	err = plonk.Verify(p.Proof, p.VK, p.WitnessPublic)
	if err != nil {
		logger.Fatal("verify circuit failed. " + err.Error())
	}
	p.VerifyTime = time.Since(start)
	logger.Debug("circuit verified, took: " + p.VerifyTime.String())
}

func (p *Plonk) BenchmarkProve(n int) {
	logger.Debug("benchmarking proving circuit ...")
	var proveTime time.Duration
	for i := 0; i < n; i++ {
		p.Prove()
		proveTime += p.ProveTime
	}
	p.ProveTime = proveTime / time.Duration(n)
	logger.Debug("proving circuit benchmarked, took: " + p.ProveTime.String())
}

func (p *Plonk) BenchmarkVerify(n int) {
	logger.Debug("benchmarking verifying circuit ...")
	var verifyTime time.Duration
	for i := 0; i < n; i++ {
		p.Verify()
		verifyTime += p.VerifyTime
	}
	p.VerifyTime = verifyTime / time.Duration(n)
	logger.Debug("verifying circuit benchmarked, took: " + p.VerifyTime.String())
}
