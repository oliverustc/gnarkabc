package wrapper

import (
	"testing"

	"gnarkabc/circuits"
)

func TestZKP(t *testing.T) {
	// 使用指针类型的Product
	var cw CircuitWrapper = &circuits.Product{}

	// 对于Product，PreCompile不需要参数，所以传nil
	// 对于Assign，需要两个整数参数，这里通过[]interface{}传递
	assignParams := []any{3, 4} // 这将使 P=3, Q=4, N=12
	_ = Groth16ZKP(cw, "BN254", nil, assignParams)
	_ = PlonkZKP(cw, "BN254", nil, assignParams)
}
