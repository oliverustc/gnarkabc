package main

import (
	"os"
	"strings"

	"gnarkabc/logger"
	"gnarkabc/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func WriteCCS(ccs constraint.ConstraintSystem, filePath string) {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	utils.EnsureDirExists(folderName)
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("failed to create file: %s", err.Error())
	}
	defer file.Close()
	size, err := ccs.WriteTo(file)
	if err != nil {
		logger.Error("failed to write ccs to file: %s", err.Error())
	}
	logger.Debug("write ccs to %s, size= %d", filePath, size)
}

func ReadCCS(curve ecc.ID, filePath string) constraint.ConstraintSystem {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	if !utils.CheckDirExists(folderName) {
		logger.Fatal("directory %s does not exist", folderName)
	}
	file, err := os.Open(filePath)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer file.Close()
	ccs := groth16.NewCS(curve)
	size, err := ccs.ReadFrom(file)
	if err != nil {
		logger.Error("failed to read ccs from file: %s", err.Error())
	}
	logger.Debug("read ccs from %s, size= %d", filePath, size)
	return ccs
}

func WritePK(pk groth16.ProvingKey, filePath string) {
	// 从filePath中读取文件夹名称
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	utils.EnsureDirExists(folderName)
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("failed to create file: %s", err.Error())
	}
	defer file.Close()
	size, err := pk.WriteTo(file)
	if err != nil {
		logger.Error("failed to write pk to file: %s", err.Error())
	}
	logger.Debug("write pk to %s, size= %d", filePath, size)
}

func ReadPK(curve ecc.ID, filePath string) groth16.ProvingKey {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	if !utils.CheckDirExists(folderName) {
		logger.Fatal("directory %s does not exist", folderName)
	}
	file, err := os.Open(filePath)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer file.Close()
	pk := groth16.NewProvingKey(curve)
	size, err := pk.ReadFrom(file)
	if err != nil {
		logger.Error("failed to read pk from file: %s", err.Error())
	}
	logger.Debug("read pk from %s, size= %d", filePath, size)
	return pk
}

func WriteVK(vk groth16.VerifyingKey, filePath string) {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	utils.EnsureDirExists(folderName)
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("failed to create file: %s", err.Error())
	}
	defer file.Close()
	size, err := vk.WriteTo(file)
	if err != nil {
		logger.Error("failed to write vk to file: %s", err.Error())
	}
	logger.Debug("write vk to %s, size= %d", filePath, size)
}

func ReadVK(curve ecc.ID, filePath string) groth16.VerifyingKey {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	if !utils.CheckDirExists(folderName) {
		logger.Fatal("directory %s does not exist", folderName)
	}
	file, err := os.Open(filePath)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer file.Close()
	vk := groth16.NewVerifyingKey(curve)
	size, err := vk.ReadFrom(file)
	if err != nil {
		logger.Error("failed to read vk from file: %s", err.Error())
	}
	logger.Debug("read vk from %s, size= %d", filePath, size)
	return vk
}

func WriteProof(proof groth16.Proof, filePath string) {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	utils.EnsureDirExists(folderName)
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("failed to create file: %s", err.Error())
	}
	defer file.Close()
	size, err := proof.WriteTo(file)
	if err != nil {
		logger.Error("failed to write proof to file: %s", err.Error())
	}
	logger.Debug("write proof to %s, size= %d", filePath, size)
}

func ReadProof(curve ecc.ID, filePath string) groth16.Proof {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	if !utils.CheckDirExists(folderName) {
		logger.Fatal("directory %s does not exist", folderName)
	}
	file, err := os.Open(filePath)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer file.Close()
	proof := groth16.NewProof(curve)
	size, err := proof.ReadFrom(file)
	if err != nil {
		logger.Error("failed to read proof from file: %s", err.Error())
	}
	logger.Debug("read proof from %s, size= %d", filePath, size)
	return proof
}

func WriteWitness(witness witness.Witness, filePath string) {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	utils.EnsureDirExists(folderName)
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("failed to create file: %s", err.Error())
	}
	defer file.Close()
	size, err := witness.WriteTo(file)
	if err != nil {
		logger.Error("failed to write witness to file: %s", err.Error())
	}
	logger.Debug("write witness to %s, size= %d", filePath, size)
}

func ReadWitness(curve ecc.ID, filePath string) witness.Witness {
	folderName := filePath[:strings.LastIndex(filePath, "/")]
	if !utils.CheckDirExists(folderName) {
		logger.Fatal("directory %s does not exist", folderName)
	}
	file, err := os.Open(filePath)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer file.Close()
	witness, err := witness.New(curve.ScalarField())
	if err != nil {
		logger.Fatal("failed to create witness: %s", err.Error())
	}
	size, err := witness.ReadFrom(file)
	if err != nil {
		logger.Error("failed to read witness from file: %s", err.Error())
	}
	logger.Debug("read witness from %s, size= %d", filePath, size)
	return witness
}
