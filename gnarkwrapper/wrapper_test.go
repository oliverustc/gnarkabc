package gnarkwrapper

import (
	"gnarkabc/logger"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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

func (tc *TestCircuit) PreCompile(args ...interface{}) {

}

func (tc *TestCircuit) Assign(curveName string, args ...interface{}) {
	p := args[0].(int)
	q := args[1].(int)
	tc.P = p
	tc.Q = q
	tc.N = p * q
}

func TestZKP(t *testing.T) {
	curveName := "BN254"
	var circuit CircuitWrapper = &TestCircuit{}
	circuit.PreCompile()
	var assign CircuitWrapper = &TestCircuit{}
	assign.Assign(curveName, 13, 17)
	ZKP("groth16", ecc.BN254, circuit, assign)
}

func TestWrapper(t *testing.T) {
	schemeList := []string{"groth16", "plonk"}
	for _, scheme := range schemeList {
		for curveName, curve := range CurveMap {
			logger.Info("testing %s zk-SNARK on curve %s", scheme, curveName)
			zk := NewGnarkWrapper(scheme, &TestCircuit{}, curve)
			zk.Compile()
			zk.Setup()
			circuit := &TestCircuit{
				P: 13,
				Q: 17,
				N: 221,
			}
			zk.SetAssignment(circuit)
			zk.Prove()
			zk.Verify()

			witnessJson := zk.GetWitnessJson(false)
			logger.Info("witnessJson: %s", witnessJson)
			publicWitnessJson := zk.GetWitnessJson(true)
			logger.Info("publicWitnessJson: %s", publicWitnessJson)
		}
	}
}

func TestGroth16(t *testing.T) {
	// 支持所有曲线
	curveNameList := []string{"BN254", "BLS12-377", "BLS12-381", "BW6-761", "BLS24-315", "BW6-633", "BLS24-317"}
	for _, curveName := range curveNameList {
		curve := CurveMap[curveName]
		logger.Info("testing groth16 zk-SNARK on curve %s", curveName)
		zk := NewGroth16(&TestCircuit{}, curve)
		zk.Compile()
		zk.Setup()
		circuit := &TestCircuit{
			P: 13,
			Q: 17,
			N: 221,
		}
		zk.SetAssignment(circuit)
		zk.Prove()
		zk.Verify()

		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)
	}
}

func TestPlonk(t *testing.T) {
	// 支持所有曲线
	curveNameList := []string{"BN254", "BLS12-377", "BLS12-381", "BW6-761", "BLS24-315", "BW6-633", "BLS24-317"}
	for _, curveName := range curveNameList {
		curve := CurveMap[curveName]
		logger.Info("testing plonk zk-SNARK on curve %s", curveName)

		zk := NewPlonk(&TestCircuit{}, curve)
		zk.Compile()
		zk.Setup()
		circuit := &TestCircuit{
			P: 13,
			Q: 17,
			N: 221,
		}
		zk.SetAssignment(circuit)
		zk.Prove()
		zk.Verify()

		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)
	}
}
