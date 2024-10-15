package gnarkwrapper

import (
	"testing"

	"github.com/consensys/gnark/frontend"
)

type TestCircuit struct {
	P frontend.Variable
	Q frontend.Variable
	N frontend.Variable `gnark:",public"`
}

func (tc *TestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(tc.N, api.Mul(tc.P, tc.Q))
	return nil
}

func TestGroth16(t *testing.T) {
	for curveName, curve := range CurveMap {
		t.Logf("\ntesting groth16 zk-SNARK on curve %s", curveName)

		zk := NewGroth16(&TestCircuit{}, curve)
		zk.Compile()
		zk.Setup()
		circuit := &TestCircuit{
			P: 13,
			Q: 17,
			N: 221,
		}
		zk.Assignment = circuit
		zk.Prove()
		zk.Verify()

		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)
	}
}
