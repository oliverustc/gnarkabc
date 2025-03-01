package main

import (
	"encoding/json"
	"os"

	"github.com/oliverustc/gnarkabc/logger"
)

type Performance struct {
	Scheme        string `json:"scheme"`
	HashAlg       string `json:"hash_alg"`
	Curve         string `json:"curve"`
	PreImage      string `json:"pre_image"`
	ProveTime     int64  `json:"prove_time"`
	VerifyTime    int64  `json:"verify_time"`
	ConstraintNum int    `json:"constraint_num"`
}

func performance() {
	var performanceList []Performance
	for _, scheme := range []string{"groth16", "plonk"} {
		for _, curve := range []string{"BN254", "BLS12-377", "BLS12-381", "BLS24-315", "BLS24-317"} {
			performanceList = append(performanceList, Sha256ZKP(scheme, curve, "hello"))
			for _, hashAlg := range []string{"SHA3-256", "SHA3-384", "SHA3-512", "Keccak-256", "Keccak-512"} {
				performanceList = append(performanceList, Sha3ZKP(scheme, curve, "hello", hashAlg))
			}
		}
	}
	for _, performance := range performanceList {
		logger.Info("Scheme: %s, HashAlg: %s, Curve: %s, PreImage: %s, ProveTime: %v ms, VerifyTime: %v ms, ConstraintNum: %v", performance.Scheme, performance.HashAlg, performance.Curve, performance.PreImage, performance.ProveTime, performance.VerifyTime, performance.ConstraintNum)
	}
	// write to json file
	jsonData, err := json.Marshal(performanceList)
	if err != nil {
		logger.Error("Failed to marshal performance list to JSON: %v", err)
	}
	os.WriteFile("performance.json", jsonData, 0644)
}

func main() {
	performance()
}
