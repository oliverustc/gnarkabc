package main

import (
	"crypto/sha256"
	"fmt"
	"gnarkabc/gnarkwrapper"
	"gnarkabc/logger"
	"gnarkabc/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// Sha256Circuit 定义了SHA256电路的结构
type Sha256Circuit struct {
	PreImage []uints.U8   `gnark:"preimage"` // 原像，私有输入
	Hash     [32]uints.U8 `gnark:",public"`  // 哈希值，公开输入
}

// Define 实现了电路的逻辑
func (sc *Sha256Circuit) Define(api frontend.API) error {
	// 初始化SHA256哈希函数
	h, err := sha2.New(api)
	if err != nil {
		return err
	}

	// 初始化uint API
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// 计算哈希值
	h.Write(sc.PreImage)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("hash is not 32 bytes")
	}

	// 验证计算的哈希值与输入的哈希值相等
	for i := range sc.Hash {
		uapi.ByteAssertEq(sc.Hash[i], res[i])
	}
	return nil
}

func (sc *Sha256Circuit) GenerateValidAssignment(preImage string) {
	preImageBytes := []byte(preImage)
	preImageU8 := uints.NewU8Array(preImageBytes)
	hash := sha256.Sum256(preImageBytes)
	hashU8 := uints.NewU8Array(hash[:])
	hashU8Arr := [32]uints.U8(hashU8)
	sc.PreImage = preImageU8
	sc.Hash = hashU8Arr
}

func Sha256Groth16ZK() []utils.ZkDuration {
	preImage := "!"
	var durations []utils.ZkDuration
	var curveNameList = []string{"BN254", "BLS12-377", "BLS12-381", "BW6-633", "BW6-761", "BLS24-315", "BLS24-317"}
	for _, curveName := range curveNameList {
		logger.Info("testing groth16 zk-snark on curve %s", curveName)
		curve := gnarkwrapper.CurveMap[curveName]
		var sc Sha256Circuit
		sc.PreImage = make([]uints.U8, len(preImage))
		zk := gnarkwrapper.NewGroth16(&sc, curve)
		zk.Compile()
		zk.Setup()

		var assign Sha256Circuit
		assign.GenerateValidAssignment(preImage)
		zk.Assignment = &assign
		zk.Prove()
		zk.Verify()
		zk.BenchmarkCompile(10)
		zk.BenchmarkSetup(10)
		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)
		durations = append(durations, utils.ZkDuration{
			CurveName:   curveName,
			CompileTime: zk.CompileTime.Microseconds(),
			SetupTime:   zk.SetupTime.Microseconds(),
			ProveTime:   zk.ProveTime.Microseconds(),
			VerifyTime:  zk.VerifyTime.Microseconds(),
		})
	}
	return durations
}
