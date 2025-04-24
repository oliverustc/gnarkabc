package main

import (
	"fmt"

	"gnarkabc/hash/shahash"
	"gnarkabc/wrapper"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Sha3Circuit struct {
	PreImage []uints.U8 `gnark:"secret"`  // 原像，私有输入
	Hash     []uints.U8 `gnark:",public"` // 哈希值，公开输入
	Hasher   string
}

func (sc *Sha3Circuit) Define(api frontend.API) error {
	newHasher, ok := shahash.HashCaseMap[sc.Hasher]
	if !ok {
		return fmt.Errorf("invalid hasher: %s", sc.Hasher)
	}
	h, err := newHasher.ZK(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	h.Write(sc.PreImage)
	res := h.Sum()
	for i := range sc.Hash {
		uapi.ByteAssertEq(res[i], sc.Hash[i])
	}
	return nil
}

func (sc *Sha3Circuit) PreCompile(params interface{}) {
	args := params.([]interface{})
	preImageLen := args[0].(int)
	sc.PreImage = make([]uints.U8, preImageLen)
	zkSha3Name := args[1].(string)
	hashLen := shahash.HashCaseMap[zkSha3Name].Native().Size()
	sc.Hash = make([]uints.U8, hashLen)
	sc.Hasher = zkSha3Name
}

func (sc *Sha3Circuit) Assign(params interface{}) {
	args := params.([]interface{})
	preImage := args[0].(string)
	zkSha3Name := args[1].(string)
	preImageU8, HashU8 := shahash.CalcSha3(preImage, zkSha3Name)
	sc.PreImage = preImageU8
	sc.Hash = HashU8
	sc.Hasher = zkSha3Name
}

func Sha3ZKP(scheme string, curveName string, preImage string, zkSha3Name string) Performance {
	var sc Sha3Circuit
	preCompileParams := []interface{}{len(preImage), zkSha3Name}
	assignParams := []interface{}{preImage, zkSha3Name}
	switch scheme {
	case "groth16":
		gw := wrapper.Groth16ZKP(&sc, curveName, preCompileParams, assignParams)
		return Performance{
			Scheme:        scheme,
			HashAlg:       zkSha3Name,
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
			HashAlg:       zkSha3Name,
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
