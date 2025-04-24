package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// 定义一个简单的电路结构
type Product struct {
	X frontend.Variable `gnark:"x"`       // 输入变量 X
	Y frontend.Variable `gnark:",public"` // 公共输出变量 Y
}

// 定义电路的逻辑：Y = X^3 + X + 5
func (sc *Product) Define(api frontend.API) error {
	// 计算 X 的立方
	x3 := api.Mul(sc.X, sc.X, sc.X)
	// 计算 Y 的值
	res := api.Add(x3, sc.X, 5)
	// 断言 Y 等于计算结果
	api.AssertIsEqual(sc.Y, res)
	return nil
}

func Groth16() {
	// 创建一个 Product 实例
	var myCircuit Product

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
	validCircuit := &Product{
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

	// 创建公共见证
	publicWitness, err := witness.Public()
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
		fmt.Printf("Verify success ! \n")
	}
}

func Plonk() {
	var myCircuit Product
	// 编译电路，生成 PLONK
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &myCircuit)
	if err != nil {
		fmt.Println(err)
		return
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		fmt.Println(err)
		return
	}

	validAssign := &Product{
		X: 1,
		Y: 7,
	}

	witness, err := frontend.NewWitness(validAssign, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
		return
	}

	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println(err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println(err)
		return
	}

	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Verify success !\n")
	}
}

func main() {
	fmt.Println("Groth16:")
	Groth16()
	fmt.Println("Plonk:")
	Plonk()
}
