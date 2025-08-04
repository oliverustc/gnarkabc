package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

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

var sha256CurveList = []string{"BN254", "BLS12-377", "BLS12-381", "BLS24-315"}

func performance() []Performance {
	var p []Performance
	for _, scheme := range []string{"groth16", "plonk"} {
		for _, curve := range sha256CurveList {
			logger.Info("Sha256ZKP on curve [%s] scheme [%s]", curve, scheme)
			p = append(p, Sha256ZKP(scheme, curve, "z"))
			// for hashName := range shahash.HashCaseMap {
			// 	logger.Info("Sha3ZKP on curve [%s] scheme [%s] hash [%s]", curve, scheme, hashName)
			// 	p = append(p, Sha3ZKP(scheme, curve, "z", hashName))
			// }
		}
	}
	return p
}

func main() {
	// 读取系统参数，如果为空，则仅执行sha256zkp
	// 若为performance， 则测试所有hash算法
	args := os.Args[1:]
	if len(args) == 0 {
		logger.Info("Sha256ZKP on curve [BN254] scheme [groth16]")
		Sha256ZKP("groth16", "BN254", "z")
		return
	}
	if args[0] == "performance" {
		// 添加一步用户确认
		logger.Info("这将需要较长时间，确定要继续吗？(yes/[no])")
		// 读取用户输入
		var confirm string
		_, err := fmt.Scanln(&confirm)
		// 如果有错误（比如用户直接按回车）或者输入不是"yes"，则取消操作
		if err != nil || confirm != "yes" {
			logger.Info("操作已取消")
			return
		}

		logger.Info("Gathering performance data...")
		pList := performance()
		// 将pList写入json文件
		jsonData, err := json.Marshal(pList)
		if err != nil {
			panic(err)
		}
		fileName := fmt.Sprintf("performance_%s.json", time.Now().Format("20060102150405"))
		err = os.WriteFile(fileName, jsonData, 0644)
		if err != nil {
			logger.Error("Failed to write performance data to file: %s", err)
			return
		}
		logger.Info("Performance data saved to %s", fileName)
		return
	}
}
