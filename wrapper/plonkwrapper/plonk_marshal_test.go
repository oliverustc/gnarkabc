package plonkwrapper

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/oliverustc/gnarkabc/circuits"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"
)

type PlonkParams struct {
	CCS           string `json:"ccs"`
	PK            string `json:"pk"`
	VK            string `json:"vk"`
	Proof         string `json:"proof"`
	Witness       string `json:"witness"`
	WitnessPublic string `json:"witness_public"`
}

func TestPlonkMarshal(t *testing.T) {
	for _, curveName := range utils.CurveNameList {
		logger.Info("marshal params on curve: %s", curveName)
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

		ccsStr, _ := zk.MarshalCCSToStr()
		pkStr, _ := zk.MarshalPKToStr()
		vkStr, _ := zk.MarshalVKToStr()
		witnessStr, _ := zk.MarshalWitnessToStr(false)
		witnessPublicStr, _ := zk.MarshalWitnessToStr(true)
		proofStr, _ := zk.MarshalProofToStr()
		// write str to a json file
		jsonFile, _ := os.Create("output/plonk_params_" + curveName + ".json")
		plonkParams := PlonkParams{
			CCS:           ccsStr,
			PK:            pkStr,
			VK:            vkStr,
			Witness:       witnessStr,
			WitnessPublic: witnessPublicStr,
			Proof:         proofStr,
		}
		json.NewEncoder(jsonFile).Encode(plonkParams)
		jsonFile.Close()
		logger.Info("marshal params success on curve: %s", curveName)
	}
}

func TestPlonkUnmarshal(t *testing.T) {
	for _, curveName := range utils.CurveNameList {
		logger.Info("unmarshal params on curve: %s", curveName)
		curve := utils.CurveMap[curveName]
		var circuit circuits.Product
		circuit.PreCompile(nil)
		zk := NewWrapper(&circuit, curve)
		jsonData, err := os.ReadFile("output/plonk_params_" + curveName + ".json")
		if err != nil {
			logger.Error("failed to read file: %s", err.Error())
			return
		}
		var plonkParams PlonkParams
		err = json.Unmarshal(jsonData, &plonkParams)
		if err != nil {
			logger.Error("failed to unmarshal json: %s", err.Error())
			return
		}
		zk.UnmarshalCCSFromStr(plonkParams.CCS)
		zk.UnmarshalPKFromStr(plonkParams.PK)
		zk.UnmarshalVKFromStr(plonkParams.VK)
		zk.UnmarshalWitnessFromStr(plonkParams.Witness, false)
		zk.UnmarshalWitnessFromStr(plonkParams.WitnessPublic, true)
		zk.UnmarshalProofFromStr(plonkParams.Proof)
		zk.Verify()
		logger.Info("verify success on curve: %s", curveName)
	}
}
