#!/bin/bash


echo "clean files "

pushd solidity 

rm combined.json gnark_solidity.go proof Verifier.sol  main.go publicWitness

popd 

echo "run main.go"

go run main.go

pushd solidity 


echo "=======generate ========"

./gnark-solidity-checker generate --solidity ./Verifier.sol --dir .  

echo "=======verify ========"

# 读取文件并转换为十六进制
PROOF_HEX=$(xxd -p proof | tr -d '\n')
RAW_PROOF_HEX=$(xxd -p rawProof | tr -d '\n')
PUBLIC_INPUTS_HEX=$(xxd -p publicWitness | tr -d '\n')

# 使用十六进制内容进行验证
./gnark-solidity-checker verify --dir . -n 1 --plonk \
    --proof "$PROOF_HEX" \
    --public-inputs "$PUBLIC_INPUTS_HEX"

# echo "try raw proof"

# ./gnark-solidity-checker verify --dir . -n 1 --plonk \
#     --proof "$RAW_PROOF_HEX" \
#     --public-inputs "$PUBLIC_INPUTS_HEX"

popd

