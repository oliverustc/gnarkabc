package main

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
	proofHex       = "d07b56baa53e9b6206e1ee27762f1a92780cef473ba379e66feea16bd8d6c56e8f9b0f759f1e2bf845e217f4c20bf28077dcd20ee0296af02812e18d855590142331666b83bd71bacef291f0ce2544e800aeeee4f5b651c8011fa685db047da08a940609a56cdecf920fa4a197a50a45b9a52f5831f945172d5b48c8eeb9d564000000004000000000000000000000000000000000000000000000000000000000000000"
	inputHex       = "0000000100000000000000010000000000000000000000000000000000000000000000000000000000000020"
	nbPublicInputs = 1
	fpSize         = 4 * 8
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
