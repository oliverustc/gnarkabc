package main

import (
	"gnarkabc/logger"
	"gnarkabc/utils"
	"gnarkabc/wrapper/groth16wrapper"
	"gnarkabc/wrapper/plonkwrapper"

	"github.com/consensys/gnark/frontend"
)

// 定义一个简单的电路结构
type Product struct {
	X frontend.Variable `gnark:"x"`       // 输入变量 X
	Y frontend.Variable `gnark:",public"` // 公共输出变量 Y
}

// 定义电路的逻辑：Y = X^3 + X + 5
func (sc *Product) Define(api frontend.API) error {
	// 计算 X 的立方
	x3 := api.Mul(sc.X, sc.X, sc.X)
	// 计算 Y 的值
	res := api.Add(x3, sc.X, 5)
	// 断言 Y 等于计算结果
	api.AssertIsEqual(sc.Y, res)
	return nil
}

func (sc *Product) PreCompile(params ...interface{}) {
	// 留空
}

func (sc *Product) Assign(params ...interface{}) {
	x := params[0].(int)
	y := x*x*x + x + 5
	sc.X = x
	sc.Y = y
}

func main() {
	curveName := "BN254"
	curve := utils.CurveMap[curveName]
	var sc Product
	sc.PreCompile()
	var scAssign Product
	scAssign.Assign(128)
	groth16 := groth16wrapper.NewWrapper(&sc, curve)
	groth16.Compile()
	groth16.Setup()
	groth16.SetAssignment(&scAssign)
	groth16.Prove()
	groth16.Verify()

	logger.Info("groth16 compile time: %s", groth16.CompileTime.String())
	logger.Info("groth16 setup time: %s", groth16.SetupTime.String())
	logger.Info("groth16 prove time: %s", groth16.ProveTime.String())
	logger.Info("groth16 verify time: %s", groth16.VerifyTime.String())

	plonk := plonkwrapper.NewWrapper(&sc, curve)
	plonk.Compile()
	plonk.Setup()
	plonk.SetAssignment(&scAssign)
	plonk.Prove()
	plonk.Verify()

	logger.Info("plonk compile time: %s", plonk.CompileTime.String())
	logger.Info("plonk setup time: %s", plonk.SetupTime.String())
	logger.Info("plonk prove time: %s", plonk.ProveTime.String())
	logger.Info("plonk verify time: %s", plonk.VerifyTime.String())
}
