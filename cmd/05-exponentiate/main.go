package main

import (
	"github.com/oliverustc/gnarkabc/gnarkwrapper"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type Circuit struct {
	// proving Y = X^E
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {

	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := frontend.Variable(1)
	bits := bits.ToBinary(api, circuit.E, bits.WithNbDigits(bitSize))
	api.Println("bits", bits)
	api.Println("len(bits)", len(bits))

	for i := 0; i < len(bits); i++ {
		api.Println("i", i)
		if i != 0 {
			output = api.Mul(output, output)
			api.Println("after output * output, output =", output)
		}
		multiply := api.Mul(output, circuit.X)
		api.Println("after multiply, multiply =", multiply)
		output = api.Select(bits[len(bits)-1-i], multiply, output)
		api.Println("bits[len(bits)-1-i]", bits[len(bits)-1-i])
		api.Println("after select, output =", output)
	}

	api.AssertIsEqual(circuit.Y, output)

	return nil
}

func (c *Circuit) PreCompile(params ...interface{}) {

}

func (c *Circuit) Assign(curveName string, params ...interface{}) {
	x := params[0].(int)
	y := params[1].(int)
	e := params[2].(int)
	c.X = x
	c.Y = y
	c.E = e
}

func main() {
	var circuit Circuit

	var assign Circuit
	assign.Assign("BN254", 2, 256, 8)

	zkp := gnarkwrapper.NewGnarkWrapper("groth16", &circuit, ecc.BN254)
	circuit.PreCompile()
	zkp.Compile()
	zkp.Setup()

	zkp.SetAssignment(&assign)
	zkp.Prove()
	zkp.Verify()
}
