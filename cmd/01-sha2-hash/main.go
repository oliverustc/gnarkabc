package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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

func main() {
	const preImage = "hello world !"
	var sha2Circuit Sha256Circuit
	sha2Circuit.PreImage = make([]uints.U8, len(preImage))

	// 编译电路
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &sha2Circuit)
	if err != nil {
		fmt.Println("Compile error:", err)
		return
	}

	// 生成证明密钥和验证密钥
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println("Setup error:", err)
		return
	}

	// 准备输入数据
	preImageBytes := []byte(preImage)
	preImageU8 := uints.NewU8Array(preImageBytes)

	hash := sha256.Sum256(preImageBytes)
	hashU8 := uints.NewU8Array(hash[:])
	hashU8Arr := [32]uints.U8(hashU8)

	// 创建有效的电路实例
	validCircuit := &Sha256Circuit{
		PreImage: preImageU8,
		Hash:     hashU8Arr,
	}

	// 创建witness
	witness, err := frontend.NewWitness(validCircuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println("NewWitness error:", err)
		return
	}

	// 生成证明
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println("Prove error:", err)
		return
	}

	// 创建公开电路实例
	publicCircuit := &Sha256Circuit{
		Hash: hashU8Arr,
	}

	// 创建公开witness
	publicWitness, err := frontend.NewWitness(publicCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println("NewWitness (public) error:", err)
		return
	}

	// 验证证明
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Verify error:", err)
	} else {
		fmt.Println("Verification successful")
	}
}
