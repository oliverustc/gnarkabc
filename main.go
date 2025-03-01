package main

import (
	"github.com/oliverustc/gnarkabc/gnarkwrapper"
	"github.com/oliverustc/gnarkabc/logger"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type SimpleCircuit struct {
	P frontend.Variable
	Q frontend.Variable

	N frontend.Variable `gnark:",public"`
}

func (circuit *SimpleCircuit) Define(api frontend.API) error {
	n := api.Mul(circuit.P, circuit.Q)
	api.AssertIsEqual(n, circuit.N)
	return nil
}

func (circuit *SimpleCircuit) PreCompile(params ...interface{}) {

}
func (circuit *SimpleCircuit) Assign(curveName string, params ...interface{}) {
	P := params[0].(int)
	Q := params[1].(int)
	N := P * Q
	circuit.P = P
	circuit.Q = Q
	circuit.N = N
}

func main() {
	var circuit gnarkwrapper.CircuitWrapper = &SimpleCircuit{}
	var assign gnarkwrapper.CircuitWrapper = &SimpleCircuit{}
	circuit.PreCompile()
	assign.Assign("BN254", 2, 3)
	proveTime, constraintNum, verifyTime := gnarkwrapper.ZKP("groth16", ecc.BN254, circuit, assign)
	logger.Info("proveTime: %v", proveTime)
	logger.Info("constraintNum: %v", constraintNum)
	logger.Info("verifyTime: %v", verifyTime)

}
