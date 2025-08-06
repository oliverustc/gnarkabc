package plonkwrapper

import (
	"bytes"
	"encoding/base64"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/oliverustc/gnarkabc/logger"
)

func (p *PlonkWrapper) MarshalCCS() ([]byte, error) {
	var buf bytes.Buffer
	size, err := p.CCS.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write ccs to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote ccs to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (p *PlonkWrapper) MarshalCCSToStr() (string, error) {
	data, err := p.MarshalCCS()
	if err != nil {
		logger.Error("failed to marshal ccs to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (p *PlonkWrapper) UnmarshalCCS(data []byte) error {
	p.CCS = plonk.NewCS(p.Curve)
	size, err := p.CCS.ReadFrom(bytes.NewReader(data))
	logger.Debug("read ccs from buffer, size= %d", size)
	return err
}

func (p *PlonkWrapper) UnmarshalCCSFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode ccs from string: %s", err.Error())
		return err
	}
	return p.UnmarshalCCS(data)
}

func (p *PlonkWrapper) MarshalPK() ([]byte, error) {
	var buf bytes.Buffer
	size, err := p.PK.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write pk to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote pk to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (p *PlonkWrapper) MarshalPKToStr() (string, error) {
	data, err := p.MarshalPK()
	if err != nil {
		logger.Error("failed to marshal pk to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (p *PlonkWrapper) UnmarshalPK(data []byte) error {
	p.PK = plonk.NewProvingKey(p.Curve)
	size, err := p.PK.ReadFrom(bytes.NewReader(data))
	logger.Debug("read pk from buffer, size= %d", size)
	return err
}

func (p *PlonkWrapper) UnmarshalPKFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode pk from string: %s", err.Error())
		return err
	}
	return p.UnmarshalPK(data)
}

func (p *PlonkWrapper) MarshalVK() ([]byte, error) {
	var buf bytes.Buffer
	size, err := p.VK.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write vk to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote vk to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (p *PlonkWrapper) MarshalVKToStr() (string, error) {
	data, err := p.MarshalVK()
	if err != nil {
		logger.Error("failed to marshal vk to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (p *PlonkWrapper) UnmarshalVK(data []byte) error {
	p.VK = plonk.NewVerifyingKey(p.Curve)
	size, err := p.VK.ReadFrom(bytes.NewReader(data))
	logger.Debug("read vk from buffer, size= %d", size)
	return err
}

func (p *PlonkWrapper) UnmarshalVKFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode vk from string: %s", err.Error())
		return err
	}
	return p.UnmarshalVK(data)
}

func (p *PlonkWrapper) MarshalProof() ([]byte, error) {
	var buf bytes.Buffer
	size, err := p.Proof.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write proof to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote proof to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (p *PlonkWrapper) MarshalProofToStr() (string, error) {
	data, err := p.MarshalProof()
	if err != nil {
		logger.Error("failed to marshal proof to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (p *PlonkWrapper) UnmarshalProof(data []byte) error {
	p.Proof = plonk.NewProof(p.Curve)
	size, err := p.Proof.ReadFrom(bytes.NewReader(data))
	logger.Debug("read proof from buffer, size= %d", size)
	return err
}

func (p *PlonkWrapper) UnmarshalProofFromStr(str string) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode proof from string: %s", err.Error())
		return err
	}
	return p.UnmarshalProof(data)
}

func (p *PlonkWrapper) MarshalWitness(public bool) ([]byte, error) {
	var buf bytes.Buffer
	if public {
		size, err := p.WitnessPublic.WriteTo(&buf)
		if err != nil {
			logger.Error("failed to write public witness to buffer: %s", err.Error())
			return nil, err
		}
		logger.Debug("wrote public witness to buffer, size= %d", size)
		return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
	}
	size, err := p.WitnessFull.WriteTo(&buf)
	if err != nil {
		logger.Error("failed to write witness to buffer: %s", err.Error())
		return nil, err
	}
	logger.Debug("wrote witness to buffer, size= %d", size)
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}

func (p *PlonkWrapper) MarshalWitnessToStr(public bool) (string, error) {
	data, err := p.MarshalWitness(public)
	if err != nil {
		logger.Error("failed to marshal witness to string: %s", err.Error())
		return "", err
	}
	return string(data), nil
}

func (p *PlonkWrapper) UnmarshalWitness(data []byte, public bool) error {
	var err error
	if public {
		p.WitnessPublic, err = witness.New(p.Field)
		if err != nil {
			logger.Error("failed to create public witness: %s", err.Error())
			return err
		}
		size, err := p.WitnessPublic.ReadFrom(bytes.NewReader(data))
		logger.Debug("read public witness from buffer, size= %d", size)
		return err
	}
	p.WitnessFull, err = witness.New(p.Field)
	if err != nil {
		logger.Error("failed to create witness: %s", err.Error())
		return err
	}
	size, err := p.WitnessFull.ReadFrom(bytes.NewReader(data))
	logger.Debug("read witness from buffer, size= %d", size)
	return err
}

func (p *PlonkWrapper) UnmarshalWitnessFromStr(str string, public bool) error {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		logger.Error("failed to decode witness from string: %s", err.Error())
		return err
	}
	return p.UnmarshalWitness(data, public)
}
