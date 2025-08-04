package main

import (
	"os"

	"github.com/oliverustc/gnarkabc/circuits"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"
	"github.com/oliverustc/gnarkabc/wrapper/groth16wrapper"
)

func generateProductGroth16InnerProofs() {
	var innerCircuit circuits.Product
	innerCircuit.PreCompile(nil)
	for _, curveName := range utils.Groth16RecursionCurveList {
		curve := utils.CurveMap[curveName]
		zk := groth16wrapper.NewWrapper(&innerCircuit, curve)
		zk.Compile()
		zk.Setup()
		p := utils.RandInt(0, 1000)
		q := utils.RandInt(0, 1000)
		assignParams := []any{p, q}
		innerCircuit.Assign(assignParams)
		zk.SetAssignment(&innerCircuit)
		zk.Prove()
		zk.Verify()

		zk.WriteCCS("output/inner_groth16_product_" + curveName + ".ccs")
		zk.WriteVK("output/inner_groth16_product_" + curveName + ".vk")
		zk.WriteProof("output/inner_groth16_product_" + curveName + ".proof")
		zk.WriteWitness("output/inner_groth16_product_"+curveName+".wit", false)
	}
}

func generateMimcHashGroth16InnerProofs() {
	var innerCircuit circuits.MimcHash
	innerCircuit.PreCompile(nil)
	for _, curveName := range utils.Groth16RecursionCurveList {
		curve := utils.CurveMap[curveName]
		zk := groth16wrapper.NewWrapper(&innerCircuit, curve)
		zk.Compile()
		zk.Setup()
		p := utils.RandInt(0, 1000)
		assignParams := []any{p}
		innerCircuit.Assign(assignParams)
		zk.SetAssignment(&innerCircuit)
		zk.Prove()
		zk.Verify()
		zk.WriteCCS("output/inner_groth16_mimc_" + curveName + ".ccs")
		zk.WriteVK("output/inner_groth16_mimc_" + curveName + ".vk")
		zk.WriteProof("output/inner_groth16_mimc_" + curveName + ".proof")
	}
}

const HelpMessage = `
	Usage: genInner, recursive
		- genInner: generate inner proofs for product and mimc hash circuits
		- recursive: generate recursive proofs for product and mimc hash circuits
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		logger.Info("%v", HelpMessage)
	}
	generateProductGroth16InnerProofs()
}
