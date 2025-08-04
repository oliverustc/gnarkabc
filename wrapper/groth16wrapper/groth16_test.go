package groth16wrapper

import (
	"testing"

	"github.com/oliverustc/gnarkabc/circuits"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"
)

func TestGroth16(t *testing.T) {
	var circuit circuits.Product
	circuit.PreCompile(nil)
	for _, curveName := range utils.CurveNameList {
		curve := utils.CurveMap[curveName]
		zk := NewWrapper(&circuit, curve)
		zk.Compile()
		zk.Setup()
		compileTime := zk.BenchmarkCompile(10)
		setupTime := zk.BenchmarkSetup(10)

		p := utils.RandInt(0, 1000)
		q := utils.RandInt(0, 1000)
		assignParams := []any{p, q}
		circuit.Assign(assignParams)
		zk.SetAssignment(&circuit)
		zk.Prove()
		zk.Verify()
		logger.Info("groth16 on curve [ %s ] success", curveName)

		proveTime := zk.BenchmarkProve(10)
		verifyTime := zk.BenchmarkVerify(10)

		logger.Info("benchmark on compile : %s", compileTime.String())
		logger.Info("benchmark on setup : %s", setupTime.String())
		logger.Info("benchmark on prove : %s", proveTime.String())
		logger.Info("benchmark on verify : %s", verifyTime.String())
	}
}
