package main

import (
	"fmt"
	"gnarkabc/gnarkwrapper"
	"gnarkabc/hash/sha"
	"gnarkabc/logger"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Sha3Circuit struct {
	PreImage []uints.U8 `gnark:"secret"`  // 原像，私有输入
	Hash     []uints.U8 `gnark:",public"` // 哈希值，公开输入
	Hasher   string
}

func (sc *Sha3Circuit) Define(api frontend.API) error {
	newHasher, ok := sha.HashCaseMap[sc.Hasher]
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

func (sc *Sha3Circuit) PreCompile(params ...interface{}) {
	preImageLen := params[0].(int)
	sc.PreImage = make([]uints.U8, preImageLen)
	zkSha3Name := params[1].(string)
	hashLen := sha.HashCaseMap[zkSha3Name].Native().Size()
	sc.Hash = make([]uints.U8, hashLen)
	sc.Hasher = zkSha3Name
}

func (sc *Sha3Circuit) Assign(curveName string, params ...interface{}) {
	preImage := params[0].(string)
	zkSha3Name := params[1].(string)
	preImageU8, HashU8 := sha.CalcSha3(preImage, zkSha3Name)
	sc.PreImage = preImageU8
	sc.Hash = HashU8
	sc.Hasher = zkSha3Name
}

func Sha3ZKP(scheme string, curveName string, preImage string, zkSha3Name string) Performance {
	curve := gnarkwrapper.CurveMap[curveName]

	var sc Sha3Circuit
	sc.PreCompile(len(preImage), zkSha3Name)
	var scAssign Sha3Circuit
	scAssign.Assign(curveName, preImage, zkSha3Name)

	ProveTime, ConstraintNum, VerifyTime := gnarkwrapper.ZKP(scheme, curve, &sc, &scAssign)
	logger.Info("[%s] hash proof with [%s] scheme on curve [%s]", zkSha3Name, scheme, curveName)
	logger.Info("ProveTime: %v ms", ProveTime)
	logger.Info("ConstraintNum: %v", ConstraintNum)
	logger.Info("VerifyTime: %v ms", VerifyTime)

	return Performance{
		Scheme:        scheme,
		HashAlg:       zkSha3Name,
		Curve:         curveName,
		PreImage:      preImage,
		ProveTime:     ProveTime,
		VerifyTime:    VerifyTime,
		ConstraintNum: ConstraintNum,
	}
}
