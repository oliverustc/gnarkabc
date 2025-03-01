package gnarkwrapper

import (
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"

	"github.com/consensys/gnark-crypto/ecc"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	bls12_377cs "github.com/consensys/gnark/constraint/bls12-377"
	bls12_381cs "github.com/consensys/gnark/constraint/bls12-381"
	bls24_315cs "github.com/consensys/gnark/constraint/bls24-315"
	bls24_317cs "github.com/consensys/gnark/constraint/bls24-317"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	bw6_633cs "github.com/consensys/gnark/constraint/bw6-633"
	bw6_761cs "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// PlonkWrapper PLONK证明系统的包装器
type PlonkWrapper struct {
	BaseWrapper
	PK    plonk.ProvingKey   // 证明密钥/
	VK    plonk.VerifyingKey // 验证密钥
	Proof plonk.Proof        // 生成的证明
}

// NewPlonk 创建新的PLONK包装器实例
func NewPlonk(circuit frontend.Circuit, curve ecc.ID) *PlonkWrapper {
	return &PlonkWrapper{
		BaseWrapper: BaseWrapper{
			Circuit: circuit,
			Curve:   curve,
			Field:   curve.ScalarField(),
		},
	}
}

// Compile 编译电路
func (p *PlonkWrapper) Compile() {
	logger.Debug("compiling circuit ...")
	var err error
	start := time.Now()
	p.CCS, err = frontend.Compile(p.Field, scs.NewBuilder, p.Circuit)
	if err != nil {
		logger.Fatal("compile circuit failed. " + err.Error())
	}
	p.CompileTime = time.Since(start)
	logger.Debug("circuit compiled, took: " + p.CompileTime.String())
	if p.ConstraintNum == 0 {
		p.ConstraintNum = p.CCS.GetNbConstraints()
		logger.Debug("constraint number: %d", p.ConstraintNum)
	}
}

// Setup 设置电路的证明系统
func (p *PlonkWrapper) Setup() {
	logger.Debug("setting up circuit ...")
	var srs, srsLagrange kzg.SRS
	var err error
	start := time.Now()

	// 提取 SRS 创建逻辑，避免代码重复
	srs, srsLagrange, err = p.createSRS(p.CCS)
	if err != nil {
		logger.Fatal("create SRS failed. " + err.Error())
	}

	p.PK, p.VK, err = plonk.Setup(p.CCS, srs, srsLagrange)
	if err != nil {
		logger.Fatal("setup circuit failed. " + err.Error())
	}

	p.SetupTime = time.Since(start)
	logger.Debug("circuit setup, took: " + p.SetupTime.String())
}

// createSRS 创建结构化参考字符串(SRS)
func (p *PlonkWrapper) createSRS(scs constraint.ConstraintSystem) (kzg.SRS, kzg.SRS, error) {
	switch p.Curve {
	case ecc.BN254:
		return unsafekzg.NewSRS(scs.(*bn254cs.SparseR1CS))
	case ecc.BLS12_377:
		return unsafekzg.NewSRS(scs.(*bls12_377cs.SparseR1CS))
	case ecc.BLS12_381:
		return unsafekzg.NewSRS(scs.(*bls12_381cs.SparseR1CS))
	case ecc.BW6_761:
		return unsafekzg.NewSRS(scs.(*bw6_761cs.SparseR1CS))
	case ecc.BLS24_315:
		return unsafekzg.NewSRS(scs.(*bls24_315cs.SparseR1CS))
	case ecc.BW6_633:
		return unsafekzg.NewSRS(scs.(*bw6_633cs.SparseR1CS))
	case ecc.BLS24_317:
		return unsafekzg.NewSRS(scs.(*bls24_317cs.SparseR1CS))
	}
	return nil, nil, errors.New("invalid curve ID")
}

// SetAssignment 设置电路的赋值
func (p *PlonkWrapper) SetAssignment(assignment frontend.Circuit) {
	p.Assignment = assignment
}

// Prove 生成零知识证明
func (p *PlonkWrapper) Prove() {
	logger.Debug("proving circuit ...")
	var err error
	start := time.Now()
	p.WitnessFull, err = frontend.NewWitness(p.Assignment, p.Field)
	if err != nil {
		logger.Fatal("generate witness failed. " + err.Error())
	}
	p.Proof, err = plonk.Prove(p.CCS, p.PK, p.WitnessFull)
	if err != nil {
		logger.Fatal("prove circuit failed. " + err.Error())
	}
	p.ProveTime = time.Since(start)
	logger.Debug("circuit proved, took: " + p.ProveTime.String())
}

// Verify 验证零知识证明
func (p *PlonkWrapper) Verify() {
	logger.Debug("verifying circuit ...")
	var err error
	start := time.Now()
	p.WitnessPublic, err = frontend.NewWitness(p.Assignment, p.Field, frontend.PublicOnly())
	if err != nil {
		logger.Fatal("generate public witness failed. " + err.Error())
	}
	err = plonk.Verify(p.Proof, p.VK, p.WitnessPublic)
	if err != nil {
		logger.Fatal("verify circuit failed. " + err.Error())
	}
	p.VerifyTime = time.Since(start)
	logger.Debug("circuit verified, took: " + p.VerifyTime.String())
}

// BenchmarkCompile 对编译过程进行基准测试
func (p *PlonkWrapper) BenchmarkCompile(iterations int) time.Duration {
	logger.Debug("benchmarking compile circuit ...")
	var compileTime time.Duration
	for i := 0; i < iterations; i++ {
		p.Compile()
		compileTime += p.CompileTime
	}
	p.CompileTime = compileTime / time.Duration(iterations)
	logger.Debug("after %d iterations, compile time: %s", iterations, p.CompileTime.String())
	return p.CompileTime
}

// BenchmarkSetup 对设置过程进行基准测试
func (p *PlonkWrapper) BenchmarkSetup(iterations int) time.Duration {
	logger.Debug("benchmarking setup ")
	var setupTime time.Duration
	for i := 0; i < iterations; i++ {
		p.Setup()
		setupTime += p.SetupTime
	}
	p.SetupTime = setupTime / time.Duration(iterations)
	logger.Debug("after %d iterations, setup time: %s", iterations, p.SetupTime.String())
	return p.SetupTime
}

// BenchmarkProve 对证明生成过程进行基准测试
func (p *PlonkWrapper) BenchmarkProve(iterations int) time.Duration {
	logger.Debug("benchmarking proving circuit ...")
	var proveTime time.Duration
	for i := 0; i < iterations; i++ {
		p.Prove()
		proveTime += p.ProveTime
	}
	p.ProveTime = proveTime / time.Duration(iterations)
	logger.Debug("after %d iterations, prove time: %s", iterations, p.ProveTime.String())
	return p.ProveTime
}

// BenchmarkVerify 对验证过程进行基准测试
func (p *PlonkWrapper) BenchmarkVerify(iterations int) time.Duration {
	logger.Debug("benchmarking verifying circuit ...")
	var verifyTime time.Duration
	for i := 0; i < iterations; i++ {
		p.Verify()
		verifyTime += p.VerifyTime
	}
	p.VerifyTime = verifyTime / time.Duration(iterations)
	logger.Debug("after %d iterations, verify time: %s", iterations, p.VerifyTime.String())
	return p.VerifyTime
}

func (p *PlonkWrapper) GetConstraintNum() int {
	return p.CCS.GetNbConstraints()
}

func (p *PlonkWrapper) GetWitness() witness.Witness {
	return p.WitnessFull
}

func (p *PlonkWrapper) GetWitnessJson(public bool) []byte {
	schama, err := frontend.NewSchema(p.Assignment)
	if err != nil {
		logger.Fatal("get schema failed: %v", err)
	}
	if public {
		witness, err := p.WitnessFull.Public()
		if err != nil {
			logger.Fatal("get public witness failed: %v", err)
		}
		witnessJson, err := witness.ToJSON(schama)
		if err != nil {
			logger.Fatal("get public witness json failed: %v", err)
		}
		return witnessJson
	} else {
		witnessJson, err := p.WitnessFull.ToJSON(schama)
		if err != nil {
			logger.Fatal("get witness json failed: %v", err)
		}
		return witnessJson
	}
}

func (p *PlonkWrapper) ExportSolidity(filePath string) {
	if filePath == "" {
		logger.Info("filePath is empty, using default path: output/PlonkVerifier.sol")
		filePath = "output/PlonkVerifier.sol"
	}
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	utils.EnsureDirExists("output")
	solFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer solFile.Close()
	p.VK.ExportSolidity(solFile)
	logger.Info("export solidity to %s", filePath)
}

func (p *PlonkWrapper) ProofMarshall() (proofStr string) {
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}

	_proof, ok := p.Proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		logger.Fatal("marshal proof failed")
	}
	proofStr = hex.EncodeToString(_proof.MarshalSolidity())
	return
}

func (p *PlonkWrapper) PublicWitnessMarshall() (publicWitnessStr string) {
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	bPublicWitness, err := p.WitnessPublic.MarshalBinary()
	if err != nil {
		logger.Fatal("marshal public witness failed: %v", err)
	}
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr = hex.EncodeToString(bPublicWitness)
	return
}

func (p *PlonkWrapper) GetPublicInputNum() string {
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	return strconv.Itoa(len(p.WitnessPublic.Vector().(fr_bn254.Vector)))
}

func (p *PlonkWrapper) GenSolProofParams() (proofStr string) {
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}

	_proof, ok := p.Proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		logger.Fatal("marshal proof failed")
	}
	proofStr = hex.EncodeToString(_proof.MarshalSolidity())
	proofStr = "0x" + proofStr
	return
}

func (p *PlonkWrapper) GenSolInputParams() (inputStr string) {
	if p.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	bPublicWitness, err := p.WitnessPublic.MarshalBinary()
	if err != nil {
		logger.Fatal("marshal public witness failed: %v", err)
	}
	bPublicWitness = bPublicWitness[12:]
	nbInputs := len(bPublicWitness) / 32
	var input []*big.Int
	input = make([]*big.Int, nbInputs)
	for i := range input {
		var e fr_bn254.Element
		e.SetBytes(bPublicWitness[fr_bn254.Bytes*i : fr_bn254.Bytes*(i+1)])
		input[i] = new(big.Int)
		e.BigInt(input[i])
	}
	inputStr = "["
	for i := range input {
		inputStr += input[i].String() + ","
	}
	inputStr = inputStr[:len(inputStr)-1]
	inputStr += "]"
	return
}

// 编译和ABI生成
// groth16和plonk在这部分除solidity路径外，没有任何不同，但为了方便后续调用，分别在两个文件中添加了此函数
func (p *PlonkWrapper) SolCompileAndABIgen(solPath string) {
	if solPath == "" {
		logger.Info("solPath is empty, use default path: output/PlonkVerifier.sol")
		solPath = "output/PlonkVerifier.sol"
	}
	compileCmd := exec.Command("solc", "--evm-version", "paris", "--combined-json", "abi,bin", solPath, "-o", "output", "--overwrite")
	logger.Debug("compile command: %v", compileCmd.String())
	if out, err := compileCmd.CombinedOutput(); err != nil {
		logger.Error("failed to compile: " + err.Error())
		logger.Error("output : " + string(out))
	} else {
		logger.Debug("compile success: " + string(out))
	}
	abiGenCmd := exec.Command("abigen", "--combined-json", filepath.Join("output", "combined.json"), "--pkg", "main", "--out", filepath.Join("output", "gnark_solidity.go"))
	logger.Debug("abiGen command: %v", abiGenCmd.String())
	if out, err := abiGenCmd.CombinedOutput(); err != nil {
		logger.Error("failed to generate abi: " + err.Error())
		logger.Error("output : " + string(out))
	} else {
		logger.Debug("abiGen success: " + string(out))
	}
}

func (p *PlonkWrapper) SolGenMain() {
	helpers := template.FuncMap{
		"mul": func(a, b int) int {
			return a * b
		},
	}
	tmpl, err := template.New("").Funcs(helpers).Parse(PlonkTemplate)
	if err != nil {
		logger.Error("failed to parse template: " + err.Error())
	}
	prootStr := p.ProofMarshall()
	inputStr := p.PublicWitnessMarshall()

	data := struct {
		Proof          string
		PublicInputs   string
		NbPublicInputs int
		NbCommitments  int
	}{
		Proof:          prootStr,
		PublicInputs:   inputStr,
		NbPublicInputs: len(p.WitnessPublic.Vector().(fr_bn254.Vector)),
		// 暂时不懂怎么获取commitments的数量，所以先设置为0
		NbCommitments: 0,
	}
	file, err := os.Create("output/main.go")
	if err != nil {
		logger.Error("failed to create file: " + err.Error())
	}
	defer file.Close()
	tmpl.Execute(file, data)
}

func (p *PlonkWrapper) SolGenGoMod() {
	file, err := os.Create("output/go.mod")
	if err != nil {
		logger.Error("failed to create file: " + err.Error())
	}
	defer file.Close()
	tmpl, err := template.New("").Parse(GoModTemplate)
	if err != nil {
		logger.Error("failed to parse template: " + err.Error())
	}
	tmpl.Execute(file, nil)
}

func (p *PlonkWrapper) SolVerify() {
	cmdGoModTidy := exec.Command("sh", "-c", "cd output && go mod tidy")
	logger.Info("running go mod tidy" + cmdGoModTidy.String())
	if out, err := cmdGoModTidy.CombinedOutput(); err != nil {
		logger.Error("failed to run go mod tidy: " + err.Error())
		logger.Error("output : " + string(out))
	} else {
		logger.Info("go mod tidy success: " + string(out))
	}

	cmdGoRun := exec.Command("sh", "-c", "cd output && go run main.go gnark_solidity.go")
	logger.Info("running go run main.go gnark_solidity.go" + cmdGoRun.String())
	if out, err := cmdGoRun.CombinedOutput(); err != nil {
		logger.Error("failed to run go run main.go gnark_solidity.go: " + err.Error())
		logger.Error("output : " + string(out))
	} else {
		logger.Info("go run main.go gnark_solidity.go success: " + string(out))
	}
}
