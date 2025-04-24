package groth16wrapper

const FpSize = 4 * 8

// 相比于gnark-solidity-checker, 将decrapated 接口更新为新接口
// 以及添加打印compressedProof功能
const Groth16Template = `package main

import (
	"encoding/hex"
	"math/big"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	proofHex = "{{ .Proof }}"
	inputHex = "{{ .PublicInputs }}"
	nbPublicInputs = {{ .NbPublicInputs }}
	fpSize = 4 * 8
)

func main() {
	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	checkErr(err, "init keyed transactor")

	genesis := map[common.Address]types.Account{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	}
	backend := simulated.NewBackend(genesis)
	client := backend.Client()

	// deploy verifier contract
	_, _, verifierContract, err := DeployVerifier(auth, client)
	checkErr(err, "deploy verifier contract failed")
	backend.Commit()


	proofBytes, err := hex.DecodeString(proofHex)
	checkErr(err, "decode proof hex failed")

	{{ if eq .NbCommitments 0 }}
	if len(proofBytes) != fpSize*8 {
		panic("proofBytes != fpSize*8")
	}
	{{ end }}

	inputBytes, err := hex.DecodeString(inputHex)
	checkErr(err, "decode input hex failed")

	if len(inputBytes)%fr.Bytes != 0 {
		panic("inputBytes mod fr.Bytes !=0")
	}

	// convert public inputs
	nbInputs := len(inputBytes) / fr.Bytes
	if nbInputs != nbPublicInputs {
		panic("nbInputs != nbPublicInputs")
	}
	var input [nbPublicInputs]*big.Int
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}

	// solidity contract inputs
	var proof [8]*big.Int

	// proof.Ar, proof.Bs, proof.Krs
	for i := 0; i < 8; i++ {
		proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}

	{{ if eq .NbCommitments 0 }}
	// call the contract
	err = verifierContract.VerifyProof(&bind.CallOpts{}, proof, input)
	checkErr(err, "calling verifier on chain gave error")
	if err == nil {
		fmt.Println("proof is valid")
	}

	// compress proof
	proofCompressed, err := verifierContract.CompressProof(&bind.CallOpts{}, proof)
	checkErr(err, "compressing proof gave error")
	compressedProofStr := "["
	for i := range proofCompressed {
		compressedProofStr += proofCompressed[i].String() + ","
	}
	compressedProofStr = compressedProofStr[:len(compressedProofStr)-1]
	compressedProofStr += "]"
	inputStr := "["
	for i := range input {
		inputStr += input[i].String() + ","
	}
	inputStr = inputStr[:len(inputStr)-1]
	inputStr += "]"
	compressedProofStr += ","
	compressedProofStr += inputStr
	fmt.Println("compressed proof:\n", compressedProofStr)

	// verify compressed proof
	err = verifierContract.VerifyCompressedProof(&bind.CallOpts{}, proofCompressed, input)
	checkErr(err, "calling verifier with compressed proof on chain gave error")
	{{ else }}
	// prepare commitments for calling
	c := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(c.Int64())

	if commitmentCount != {{ .NbCommitments }} {
		panic("commitmentCount != .NbCommitments")
	}

	var commitments [{{mul 2 .NbCommitments}}]*big.Int
	var commitmentPok [2]*big.Int

	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize])
	}

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])

	// call the contract
	err = verifierContract.VerifyProof(&bind.CallOpts{}, proof, commitments, commitmentPok, input)
	checkErr(err, "calling verifier on chain gave error")

	// compress proof
	compressed, err := verifierContract.CompressProof(&bind.CallOpts{}, proof, commitments, commitmentPok)
	checkErr(err, "compressing proof gave error")

	// verify compressed proof
	err = verifierContract.VerifyCompressedProof(&bind.CallOpts{}, compressed.Compressed, compressed.CompressedCommitments, compressed.CompressedCommitmentPok, input)
	checkErr(err, "calling verifier with compressed proof on chain gave error")
	if err == nil {
		fmt.Println("compressedproof is valid")
	} else {
		fmt.Printf("compressedproof is invalid, error: %s\n", err.Error())
	}
	{{ end }}
}

func checkErr(err error, ctx string) {
	if err != nil {
		panic(ctx + " " + err.Error())
	}
}

`
const GoModTemplate = `module tmpsolidity

go 1.23

require (
	github.com/consensys/gnark master
	github.com/consensys/gnark-crypto v0.13.1-0.20240827160944-8031ce47e83b
	github.com/ethereum/go-ethereum v0.0.0
)

replace github.com/ethereum/go-ethereum => github.com/gbotrel/go-ethereum v1.8.14-0.20240827161042-51b21f369b78

`
