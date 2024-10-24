package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// 定义一个简单的电路结构
type SimpleCircuit struct {
	X frontend.Variable `gnark:"x"`       // 输入变量 X
	Y frontend.Variable `gnark:",public"` // 公共输出变量 Y
}

// 定义电路的逻辑：Y = X^3 + X + 5
func (sc *SimpleCircuit) Define(api frontend.API) error {
	// 计算 X 的立方
	x3 := api.Mul(sc.X, sc.X, sc.X)
	// 计算 Y 的值
	res := api.Add(x3, sc.X, 5)
	// 断言 Y 等于计算结果
	api.AssertIsEqual(sc.Y, res)
	return nil
}

func main() {
	// 创建一个 SimpleCircuit 实例
	var myCircuit SimpleCircuit

	// 编译电路，生成 R1CS
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 设置证明密钥和验证密钥
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建一个有效的电路实例
	validCircuit := &SimpleCircuit{
		X: 1, // 输入 X 的值
		Y: 7, // 预期输出 Y 的值
	}

	// 创建Witness
	witness, err := frontend.NewWitness(validCircuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		return
	}

	// 生成证明
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建一个公共电路实例
	publicCircuit := &SimpleCircuit{
		Y: 7, // 公共输出 Y 的值
	}

	// 创建公共见证
	publicWitness, err := frontend.NewWitness(publicCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return
	}

	// 验证证明
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	} else {
		// 验证成功
		fmt.Printf("Verify success !")
	}
}