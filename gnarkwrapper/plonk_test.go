package gnarkwrapper

import "testing"

func TestPlonk(t *testing.T) {
	// 支持所有曲线
	curveNameList := []string{"BN254", "BLS12_377", "BLS12-381", "BW6_761", "BLS24_315", "BW6_633", "BLS24_317"}
	for _, curveName := range curveNameList {
		curve := CurveMap[curveName]
		t.Logf("\ntesting plonk zk-SNARK on curve %s", curveName)
		// field := curve.ScalarField()

		zk := NewPlonk(&TestCircuit{}, curve)
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
