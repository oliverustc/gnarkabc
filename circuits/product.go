package circuits

import "github.com/consensys/gnark/frontend"

// Product 是一个简单且运行高效的电路，用于内部测试
type Product struct {
	P frontend.Variable
	Q frontend.Variable
	N frontend.Variable `gnark:",public"`
}

// Define 实现了电路的约束逻辑
func (tc *Product) Define(api frontend.API) error {
	api.AssertIsEqual(tc.N, api.Mul(tc.P, tc.Q))
	return nil
}

func (tc *Product) PreCompile(params interface{}) {
	// 预编译逻辑为空
	// 对于Product，PreCompile不需要任何参数
}

func (tc *Product) Assign(params interface{}) {
	// 将params转换为切片以处理多个参数
	args := params.([]interface{})
	if len(args) != 2 {
		panic("Assign params must be []interface{} with length 2")
	}

	p := args[0].(int)
	q := args[1].(int)
	tc.P = p
	tc.Q = q
	tc.N = p * q
}
