package groth16wrapper

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/oliverustc/gnarkabc/circuits"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"
)

type Groth16Params struct {
	CCS           string `json:"ccs"`
	PK            string `json:"pk"`
	VK            string `json:"vk"`
	Witness       string `json:"witness"`
	WitnessPublic string `json:"witness_public"`
	Proof         string `json:"proof"`
}

func TestGroth16Marshal(t *testing.T) {
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
		jsonFile, _ := os.Create("output/groth16_params_" + curveName + ".json")
		groth16Params := Groth16Params{
			CCS:           ccsStr,
			PK:            pkStr,
			VK:            vkStr,
			Witness:       witnessStr,
			WitnessPublic: witnessPublicStr,
			Proof:         proofStr,
		}
		json.NewEncoder(jsonFile).Encode(groth16Params)
		jsonFile.Close()
		logger.Info("marshal params success on curve: %s", curveName)
	}
}

func TestGroth16Unmarshal(t *testing.T) {
	for _, curveName := range utils.CurveNameList {
		logger.Info("unmarshal params on curve: %s", curveName)
		curve := utils.CurveMap[curveName]
		var circuit circuits.Product
		circuit.PreCompile(nil)
		zk := NewWrapper(&circuit, curve)
		jsonData, err := os.ReadFile("output/groth16_params_" + curveName + ".json")
		if err != nil {
			logger.Error("failed to read file: %s", err.Error())
			return
		}
		var groth16Params Groth16Params
		err = json.Unmarshal(jsonData, &groth16Params)
		if err != nil {
			logger.Error("failed to unmarshal json: %s", err.Error())
			return
		}
		zk.UnmarshalCCSFromStr(groth16Params.CCS)
		zk.UnmarshalPKFromStr(groth16Params.PK)
		zk.UnmarshalVKFromStr(groth16Params.VK)
		zk.UnmarshalWitnessFromStr(groth16Params.Witness, false)
		zk.UnmarshalWitnessFromStr(groth16Params.WitnessPublic, true)
		zk.UnmarshalProofFromStr(groth16Params.Proof)
		zk.Verify()
		logger.Info("verify success on curve: %s", curveName)
	}
}
