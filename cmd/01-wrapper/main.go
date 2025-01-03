package main

import (
	"gnarkabc/gnarkwrapper"
	"gnarkabc/logger"

	"github.com/consensys/gnark/frontend"
)

// 定义一个简单的电路结构
type SimpleCircuit struct {
	X frontend.Variable `gnark:"x"`       // 输入变量 X
	Y frontend.Variable `gnark:",public"` // 公共输出变量 Y
}

// 定义电路的逻辑：Y = X^3 + X + 5
func (sc *SimpleCircuit) Define(api frontend.API) error {
	// 计算 X 的立方
	x3 := api.Mul(sc.X, sc.X, sc.X)
	// 计算 Y 的值
	res := api.Add(x3, sc.X, 5)
	// 断言 Y 等于计算结果
	api.AssertIsEqual(sc.Y, res)
	return nil
}

func (sc *SimpleCircuit) PreCompile(params ...interface{}) {
	// 留空
}

func (sc *SimpleCircuit) Assign(curveName string, params ...interface{}) {
	x := params[0].(int)
	y := x*x*x + x + 5
	sc.X = x
	sc.Y = y
}

func main() {
	var sc SimpleCircuit
	sc.PreCompile()
	var scAssign SimpleCircuit
	scAssign.Assign("BN254", 128)
	curve := gnarkwrapper.CurveMap["BN254"]
	proveTimeGroth16, constraintNumGroth16, verifyTimeGroth16 := gnarkwrapper.ZKP("groth16", curve, &sc, &scAssign)

	proveTimePlonk, constraintNumPlonk, verifyTimePlonk := gnarkwrapper.ZKP("plonk", curve, &sc, &scAssign)
	logger.Info("ProveTime on groth16: %v ms", proveTimeGroth16)
	logger.Info("ProveTime on plonk: %v ms", proveTimePlonk)
	logger.Info("ConstraintNum on groth16: %v", constraintNumGroth16)
	logger.Info("ConstraintNum on plonk: %v", constraintNumPlonk)
	logger.Info("VerifyTime on groth16: %v ms", verifyTimeGroth16)
	logger.Info("VerifyTime on plonk: %v ms", verifyTimePlonk)
}
