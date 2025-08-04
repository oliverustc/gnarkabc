package main

import (
	"fmt"

	"github.com/oliverustc/gnarkabc/hash/shahash"
	"github.com/oliverustc/gnarkabc/wrapper"

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

func (sc *Sha256Circuit) PreCompile(params any) {
	preImageLen := params.([]interface{})[0].(int)
	sc.PreImage = make([]uints.U8, preImageLen)
}

func (sc *Sha256Circuit) Assign(params any) {
	args := params.([]interface{})
	preImage := args[0].(string)
	preImageU8, hashU8Arr := shahash.CalcSha256(preImage)
	sc.PreImage = preImageU8
	sc.Hash = hashU8Arr
}

func Sha256ZKP(scheme string, curveName string, preImage string) Performance {
	var sc Sha256Circuit
	preCompileParams := []any{len(preImage)}

	assignParams := []any{preImage}
	switch scheme {
	case "groth16":
		gw := wrapper.Groth16ZKP(&sc, curveName, preCompileParams, assignParams)
		return Performance{
			Scheme:        scheme,
			HashAlg:       "SHA256",
			Curve:         curveName,
			PreImage:      preImage,
			ProveTime:     gw.BenchmarkProve(10).Milliseconds(),
			VerifyTime:    gw.BenchmarkVerify(10).Milliseconds(),
			ConstraintNum: gw.ConstraintNum,
		}
	case "plonk":
		pw := wrapper.PlonkZKP(&sc, curveName, preCompileParams, assignParams)
		return Performance{
			Scheme:        scheme,
			HashAlg:       "SHA256",
			Curve:         curveName,
			PreImage:      preImage,
			ProveTime:     pw.BenchmarkProve(10).Milliseconds(),
			VerifyTime:    pw.BenchmarkVerify(10).Milliseconds(),
			ConstraintNum: pw.ConstraintNum,
		}
	default:
		return Performance{}
	}
}
