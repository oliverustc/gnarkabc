package wrapper

import (
	"gnarkabc/utils"
	"gnarkabc/wrapper/groth16wrapper"
	"gnarkabc/wrapper/plonkwrapper"

	"github.com/consensys/gnark/frontend"
)

type CircuitWrapper interface {
	frontend.Circuit
	PreCompile(params interface{})
	Assign(params interface{})
}

func Groth16ZKP(cw CircuitWrapper, curveName string, compileParams interface{}, assignParams interface{}) *groth16wrapper.Groth16Wrapper {
	curve := utils.CurveMap[curveName]
	g := groth16wrapper.NewWrapper(cw, curve)
	cw.PreCompile(compileParams)
	g.Compile()
	g.Setup()
	cw.Assign(assignParams)
	g.SetAssignment(cw)
	g.Prove()
	g.Verify()
	return g
}

func PlonkZKP(cw CircuitWrapper, curveName string, compileParams interface{}, assignParams interface{}) *plonkwrapper.PlonkWrapper {
	curve := utils.CurveMap[curveName]
	p := plonkwrapper.NewWrapper(cw, curve)
	cw.PreCompile(compileParams)
	p.Compile()
	p.Setup()
	cw.Assign(assignParams)
	p.SetAssignment(cw)
	p.Prove()
	p.Verify()
	return p
}
