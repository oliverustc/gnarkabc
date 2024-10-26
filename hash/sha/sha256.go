package sha

import (
	"crypto/sha256"
	"fmt"

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
