package main

import (
	"encoding/json"
	"os"

	"github.com/oliverustc/gnarkabc/gnarkwrapper"
	"github.com/oliverustc/gnarkabc/hash/mimchash"
	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MimcCircuit struct {
	PreImage []frontend.Variable `gnark:"secret"`
	Hash     frontend.Variable   `gnark:",public"`
}

func (mc *MimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(mc.PreImage[:]...)
	result := mimc.Sum()
	api.AssertIsEqual(result, mc.Hash)
	return nil
}

func (mc *MimcCircuit) PreCompile(params ...interface{}) {
	preImageLen := params[0].(int)
	length := (preImageLen + 31) / 32
	mc.PreImage = make([]frontend.Variable, length)
}

func (mc *MimcCircuit) Assign(curveName string, params ...interface{}) {
	preImage := params[0].(string)

	var preImageByteArr [][]byte
	if len(preImage)%32 != 0 {
		padding := 32 - (len(preImage) % 32)
		logger.Debug("padding: %d chars", padding)
		preImage += string(make([]byte, padding)) // 填充空字节
	}
	field := mimchash.MiMCCaseMap[curveName].Curve.ScalarField()
	for i := 0; i < len(preImage); i += 32 {
		end := i + 32
		if end > len(preImage) {
			end = len(preImage)
		}
		preImageStr := preImage[i:end]
		preImageByteArr = append(preImageByteArr, mimchash.Convert2Byte(preImageStr, field))
		logger.Debug("preImageStr: %s", preImageStr)
	}
	hashFunc := mimchash.MiMCCaseMap[curveName].Hash
	hashFunc.Reset()
	mc.PreImage = make([]frontend.Variable, len(preImageByteArr))
	for i, p := range preImageByteArr {
		mc.PreImage[i] = p
		hashFunc.Write(p)
	}
	mc.Hash = hashFunc.Sum(nil)

}

func MiMCZKP(scheme string, curveName string, preImage string) (proveTime int64, constraintNum int, verifyTime int64) {
	curve := mimchash.MiMCCaseMap[curveName].Curve
	var circuit MimcCircuit
	circuit.PreCompile(len(preImage))
	var assign MimcCircuit
	assign.Assign(curveName, preImage)
	proveTime, constraintNum, verifyTime = gnarkwrapper.ZKP(scheme, curve, &circuit, &assign)
	return
}

type Performance struct {
	Scheme        string `json:"scheme"`
	Curve         string `json:"curve"`
	PreImage      string `json:"pre_image"`
	ProveTime     int64  `json:"prove_time"`
	VerifyTime    int64  `json:"verify_time"`
	ConstraintNum int    `json:"constraint_num"`
}

func main() {
	var performanceList []Performance
	preImage := utils.RandStr(10)
	for _, scheme := range []string{"groth16", "plonk"} {
		for _, curveName := range []string{"BN254", "BLS12-377", "BLS12-381", "BLS24-315", "BLS24-317"} {

			proveTime, constraintNum, verifyTime := MiMCZKP(scheme, curveName, preImage)
			performanceList = append(performanceList, Performance{Scheme: scheme, Curve: curveName, PreImage: preImage, ProveTime: proveTime, VerifyTime: verifyTime, ConstraintNum: constraintNum})
		}
	}

	// write to json file
	jsonData, err := json.Marshal(performanceList)
	if err != nil {
		logger.Error("failed to marshal json: %v", err)
		return
	}
	os.WriteFile("mimc_performance.json", jsonData, 0644)
}
