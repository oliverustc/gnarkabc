package plonkwrapper

import (
	"testing"

	"gnarkabc/circuits"
	"gnarkabc/logger"
	"gnarkabc/utils"
)

func TestPlonkWrite(t *testing.T) {
	utils.RemoveDir("output")
	var circuit circuits.Product
	circuit.PreCompile(nil)
	for _, curveName := range utils.CurveNameList {
		curve := utils.CurveMap[curveName]
		p := NewWrapper(&circuit, curve)
		p.Compile()
		p.Setup()
		assignParams := []interface{}{13, 17}
		circuit.Assign(assignParams)
		p.SetAssignment(&circuit)
		p.Prove()
		p.Verify()
		logger.Info("plonk on curve [ %s ] success", curveName)
		p.WriteCCS("output/ccs_" + curveName)
		p.WritePK("output/pk_" + curveName)
		p.WriteVK("output/vk_" + curveName)
		p.WriteWitness("output/witness_"+curveName, false)
		p.WriteWitness("output/public_witness_"+curveName, true)
		p.WriteProof("output/proof_" + curveName)
		logger.Info("write params success on [ %s ]", curveName)
	}
}

func TestPlonkRead(t *testing.T) {
	for _, curveName := range utils.CurveNameList {
		var circuit circuits.Product
		circuit.PreCompile(nil)
		curve := utils.CurveMap[curveName]

		p := NewWrapper(&circuit, curve)
		p.ReadCCS("output/ccs_" + curveName)
		p.ReadPK("output/pk_" + curveName)
		p.ReadVK("output/vk_" + curveName)
		p.ReadWitness("output/witness_"+curveName, false)
		// 首先基于已有参数自行prove和verify
		p.Prove()
		p.ReadWitness("output/public_witness_"+curveName, true)
		p.Verify()
		// 然后读取已有的proof仅进行验证
		p.ReadProof("output/proof_" + curveName)
		p.Verify()
		logger.Info("prove and verify success on [ %s ] after read params", curveName)
	}
}
