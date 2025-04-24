package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

type Poseidon2Hash struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (c *Poseidon2Hash) Define(api frontend.API) error {
	poseidonHash, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}
	poseidonHash.Reset()
	poseidonHash.Write(c.PreImage)
	h := poseidonHash.Sum()
	api.AssertIsEqual(c.Hash, h)
	return nil
}

func (c *Poseidon2Hash) PreCompile(params interface{}) {
}

func (c *Poseidon2Hash) Assign(params interface{}) {
	args := params.([]interface{})
	preImage := args[0].([][]byte)
	hash := args[1].([]byte)
	c.PreImage = preImage[0]
	c.Hash = hash
}
