package groth16wrapper

import (
	"bytes"
	"encoding/base64"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/oliverustc/gnarkabc/logger"
)

func (g *Groth16Wrapper) MarshalCCS() ([]byte, error) {
	var buf bytes.Buffer
	size, err := g.CCS.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write ccs to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote ccs to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (g *Groth16Wrapper) MarshalCCSToStr() (string, error) {
	data, err := g.MarshalCCS()
	if err != nil {
		logger.Error("failed to marshal ccs to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (g *Groth16Wrapper) UnmarshalCCS(data []byte) error {
	g.CCS = groth16.NewCS(g.Curve)
	size, err := g.CCS.ReadFrom(bytes.NewReader(data))
	logger.Debug("read ccs from buffer, size= %d", size)
	return err
}

func (g *Groth16Wrapper) UnmarshalCCSFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode ccs from string: %s", err.Error())
		return err
	}
	return g.UnmarshalCCS(data)
}

func (g *Groth16Wrapper) MarshalPK() ([]byte, error) {
	var buf bytes.Buffer
	size, err := g.PK.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write pk to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote pk to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (g *Groth16Wrapper) MarshalPKToStr() (string, error) {
	data, err := g.MarshalPK()
	if err != nil {
		logger.Error("failed to marshal pk to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (g *Groth16Wrapper) UnmarshalPK(data []byte) error {
	g.PK = groth16.NewProvingKey(g.Curve)
	size, err := g.PK.ReadFrom(bytes.NewReader(data))
	logger.Debug("read pk from buffer, size= %d", size)
	return err
}

func (g *Groth16Wrapper) UnmarshalPKFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode pk from string: %s", err.Error())
		return err
	}
	return g.UnmarshalPK(data)
}

func (g *Groth16Wrapper) MarshalVK() ([]byte, error) {
	var buf bytes.Buffer
	size, err := g.VK.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write vk to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote vk to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (g *Groth16Wrapper) MarshalVKToStr() (string, error) {
	data, err := g.MarshalVK()
	if err != nil {
		logger.Error("failed to marshal vk to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (g *Groth16Wrapper) UnmarshalVK(data []byte) error {
	g.VK = groth16.NewVerifyingKey(g.Curve)
	size, err := g.VK.ReadFrom(bytes.NewReader(data))
	logger.Debug("read vk from buffer, size= %d", size)
	return err
}

func (g *Groth16Wrapper) UnmarshalVKFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode vk from string: %s", err.Error())
		return err
	}
	return g.UnmarshalVK(data)
}

func (g *Groth16Wrapper) MarshalWitness(public bool) ([]byte, error) {
	var buf bytes.Buffer
	if public {
		size, err := g.WitnessPublic.WriteTo(&buf)
		if err != nil {
			logger.Error("failed to write public witness to buffer: %s", err.Error())
			return nil, err
		}
		logger.Debug("wrote public witness to buffer, size= %d", size)
		return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
	}
	size, err := g.WitnessFull.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write witness to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote witness to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (g *Groth16Wrapper) MarshalWitnessToStr(public bool) (string, error) {
	data, err := g.MarshalWitness(public)
	if err != nil {
		logger.Error("failed to marshal witness to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (g *Groth16Wrapper) UnmarshalWitness(data []byte, public bool) error {
	var err error
	if public {
		g.WitnessPublic, err = witness.New(g.Field)
		if err != nil {
			logger.Error("failed to create public witness: %s", err.Error())
			return err
		}
		size, err := g.WitnessPublic.ReadFrom(bytes.NewReader(data))
		logger.Debug("read public witness from buffer, size= %d", size)
		return err
	}
	g.WitnessFull, err = witness.New(g.Field)
	if err != nil {
		logger.Error("failed to create witness: %s", err.Error())
		return err
	}
	size, err := g.WitnessFull.ReadFrom(bytes.NewReader(data))
	logger.Debug("read witness from buffer, size= %d", size)
	return err
}

func (g *Groth16Wrapper) UnmarshalWitnessFromStr(str string, public bool) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode witness from string: %s", err.Error())
		return err
	}
	return g.UnmarshalWitness(data, public)
}

func (g *Groth16Wrapper) MarshalProof() ([]byte, error) {
	var buf bytes.Buffer
	size, err := g.Proof.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write proof to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote proof to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (g *Groth16Wrapper) MarshalProofToStr() (string, error) {
	data, err := g.MarshalProof()
	if err != nil {
		logger.Error("failed to marshal proof to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (g *Groth16Wrapper) UnmarshalProof(data []byte) error {
	g.Proof = groth16.NewProof(g.Curve)
	size, err := g.Proof.ReadFrom(bytes.NewReader(data))
	logger.Debug("read proof from buffer, size= %d", size)
	return err
}

func (g *Groth16Wrapper) UnmarshalProofFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode proof from string: %s", err.Error())
		return err
	}
	return g.UnmarshalProof(data)
}
