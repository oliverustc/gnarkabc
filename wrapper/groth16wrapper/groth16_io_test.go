package groth16wrapper

import (
	"testing"

	"github.com/oliverustc/gnarkabc/circuits"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"
)

func TestGroth16Write(t *testing.T) {
	utils.RemoveDir("output")
	for _, curveName := range utils.CurveNameList {
		curve := utils.CurveMap[curveName]
		var circuit circuits.Product
		circuit.PreCompile(nil)
		zk := NewWrapper(&circuit, curve)
		zk.Compile()
		zk.Setup()
		assignParams := []any{13, 17}
		circuit.Assign(assignParams)
		zk.SetAssignment(&circuit)
		zk.Prove()
		zk.Verify()
		zk.WriteCCS("output/ccs_" + curveName)
		zk.WritePK("output/pk_" + curveName)
		zk.WriteVK("output/vk_" + curveName)
		zk.WriteWitness("output/witness_"+curveName, false)
		zk.WriteWitness("output/public_witness_"+curveName, true)
		zk.WriteProof("output/proof_" + curveName)
		logger.Info("write params success on [ %s ]", curveName)
	}
}

func TestGroth16Read(t *testing.T) {
	for _, curveName := range utils.CurveNameList {
		curve := utils.CurveMap[curveName]
		var circuit circuits.Product
		circuit.PreCompile(nil)
		zk := NewWrapper(&circuit, curve)
		zk.ReadCCS("output/ccs_" + curveName)
		zk.ReadPK("output/pk_" + curveName)
		zk.ReadVK("output/vk_" + curveName)
		zk.ReadWitness("output/witness_"+curveName, false)
		// 首先基于已有参数自行prove和verify
		zk.Prove()
		zk.ReadWitness("output/public_witness_"+curveName, true)
		zk.Verify()
		// 然后读取已有的proof仅进行验证
		zk.ReadProof("output/proof_" + curveName)
		zk.Verify()
		logger.Info("prove and verify success on [ %s ] after read params", curveName)
	}
}
