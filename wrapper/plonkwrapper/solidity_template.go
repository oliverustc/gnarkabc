package plonkwrapper

// 相比于gnark-solidity-checker, 将decrapated 接口更新为新接口
const PlonkTemplate = `package main


import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	proofHex = "{{ .Proof }}"
	inputHex = "{{ .PublicInputs }}"
	nbPublicInputs = {{ .NbPublicInputs }}
	fpSize = 4 * 8
)

func main() {
	const gasLimit uint64 = 4712388

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	checkErr(err, "init keyed transactor")

	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	}
	backend := backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, verifierContract, err := DeployPlonkVerifier(auth, backend)
	checkErr(err, "deploy verifier contract failed")
	backend.Commit()


	proofBytes, err := hex.DecodeString(proofHex)
	checkErr(err, "decode proof hex failed")


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


	// call the contract
	res, err := verifierContract.Verify(&bind.CallOpts{}, proofBytes[:], input[:])
	checkErr(err, "calling verifier on chain gave error")
	if res {
		fmt.Println("proof is valid")
	} else {
		fmt.Println("proof is invalid")
		os.Exit(42)
	}
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
