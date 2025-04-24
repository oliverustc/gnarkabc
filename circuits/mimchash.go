package circuits

import (
	"gnarkabc/logger"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MimcHash struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (m *MimcHash) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Reset()
	mimc.Write(m.PreImage)
	h := mimc.Sum()
	api.AssertIsEqual(m.Hash, h)
	return nil
}

func (m *MimcHash) PreCompile(params interface{}) {
	// 留空
}

func (m *MimcHash) Assign(params interface{}) {
	args := params.([]interface{})
	preImage := args[0].([][]byte)
	hash := args[1].([]byte)
	m.PreImage = preImage[0]
	m.Hash = hash
	logger.Info("Assigning MimcHash circuit with preImage %v and hash %v", preImage, hash)
}
