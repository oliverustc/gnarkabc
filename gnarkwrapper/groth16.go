package gnarkwrapper

import (
	"encoding/hex"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"text/template"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/oliverustc/gnarkabc/logger"
	"github.com/oliverustc/gnarkabc/utils"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Groth16Wrapper Groth16证明系统的包装器
type Groth16Wrapper struct {
	BaseWrapper
	PK    groth16.ProvingKey   // 证明密钥
	VK    groth16.VerifyingKey // 验证密钥
	Proof groth16.Proof        // 生成的证明
}

// NewGroth16 创建新的Groth16包装器实例
func NewGroth16(circuit frontend.Circuit, curve ecc.ID) *Groth16Wrapper {
	return &Groth16Wrapper{
		BaseWrapper: BaseWrapper{
			Circuit: circuit,
			Curve:   curve,
			Field:   curve.ScalarField(),
		},
	}
}

// Compile 编译电路
func (g *Groth16Wrapper) Compile() {
	logger.Debug("compiling circuit ...")
	var err error
	start := time.Now()
	g.CCS, err = frontend.Compile(g.Field, r1cs.NewBuilder, g.Circuit)
	if err != nil {
		logger.Fatal("compile circuit failed. " + err.Error())
	}
	g.CompileTime = time.Since(start)
	logger.Debug("circuit compiled, took: " + g.CompileTime.String())
	if g.ConstraintNum == 0 {
		g.ConstraintNum = g.CCS.GetNbConstraints()
		logger.Debug("constraint number: %d", g.ConstraintNum)
	}
}

// Setup 设置电路的证明系统
func (g *Groth16Wrapper) Setup() {
	logger.Debug("setting up circuit ...")
	var err error
	start := time.Now()
	g.PK, g.VK, err = groth16.Setup(g.CCS)
	if err != nil {
		logger.Fatal("setup circuit failed. " + err.Error())
	}
	g.SetupTime = time.Since(start)
	logger.Debug("circuit setup, took: " + g.SetupTime.String())
}

// generateWitness 生成见证者数据
// publicOnly: 是否只生成公开输入的见证者
func (g *Groth16Wrapper) generateWitness(publicOnly bool) (witness.Witness, error) {
	var opts []frontend.WitnessOption
	if publicOnly {
		opts = append(opts, frontend.PublicOnly())
	}
	return frontend.NewWitness(g.Assignment, g.Field, opts...)
}

// SetAssignment 设置电路的赋值
func (g *Groth16Wrapper) SetAssignment(assignment frontend.Circuit) {
	g.Assignment = assignment
}

// Prove 生成零知识证明
func (g *Groth16Wrapper) Prove() {
	logger.Debug("proving ...")
	var err error
	start := time.Now()
	g.WitnessFull, err = g.generateWitness(false)
	if err != nil {
		logger.Fatal("generate witness failed. " + err.Error())
	}
	g.Proof, err = groth16.Prove(g.CCS, g.PK, g.WitnessFull)
	if err != nil {
		logger.Fatal("prove failed. " + err.Error())
	}
	g.ProveTime = time.Since(start)
	logger.Debug("circuit proved, took: " + g.ProveTime.String())
}

// Verify 验证零知识证明
func (g *Groth16Wrapper) Verify() {
	logger.Debug("verifying ...")
	var err error
	start := time.Now()
	g.WitnessPublic, err = g.generateWitness(true)
	if err != nil {
		logger.Fatal("generate public witness failed. " + err.Error())
	}
	err = groth16.Verify(g.Proof, g.VK, g.WitnessPublic)
	if err != nil {
		logger.Fatal("verify proof failed.")
	} else {
		logger.Debug("circuit verified")
	}
	g.VerifyTime = time.Since(start)
	logger.Debug("circuit verified, took: " + g.VerifyTime.String())
}

// BenchmarkCompile 对编译过程进行基准测试
func (g *Groth16Wrapper) BenchmarkCompile(iterations int) time.Duration {
	logger.Debug("benchmarking compiling circuit ...")
	var compileTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Compile()
		compileTime += g.CompileTime
	}
	g.CompileTime = compileTime / time.Duration(iterations)
	logger.Debug("after %d iterations, compile time: %s", iterations, g.CompileTime.String())
	return g.CompileTime
}

// BenchmarkSetup 对设置过程进行基准测试
func (g *Groth16Wrapper) BenchmarkSetup(iterations int) time.Duration {
	logger.Debug("benchmarking setup circuit ...")
	var setupTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Setup()
		setupTime += g.SetupTime
	}
	g.SetupTime = setupTime / time.Duration(iterations)
	logger.Debug("after %d iterations, setup time: %s", iterations, g.SetupTime.String())
	return g.SetupTime
}

// BenchmarkProve 对证明生成过程进行基准测试
func (g *Groth16Wrapper) BenchmarkProve(iterations int) time.Duration {
	logger.Debug("benchmarking proving circuit ...")
	var proveTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Prove()
		proveTime += g.ProveTime
	}
	g.ProveTime = proveTime / time.Duration(iterations)
	logger.Debug("after %d iterations, prove time: %s", iterations, g.ProveTime.String())
	return g.ProveTime
}

// BenchmarkVerify 对验证过程进行基准测试
func (g *Groth16Wrapper) BenchmarkVerify(iterations int) time.Duration {
	logger.Debug("benchmarking verifying circuit ...")
	var verifyTime time.Duration
	for i := 0; i < iterations; i++ {
		g.Verify()
		verifyTime += g.VerifyTime
	}
	g.VerifyTime = verifyTime / time.Duration(iterations)
	logger.Debug("after %d iterations, verify time: %s", iterations, g.VerifyTime.String())
	return g.VerifyTime
}

// 获取电路中约束数量
func (g *Groth16Wrapper) GetConstraintNum() int {
	return g.CCS.GetNbConstraints()
}

// 获取Witness
func (g *Groth16Wrapper) GetWitness() witness.Witness {
	return g.WitnessFull
}

// 获取json格式witness
func (g *Groth16Wrapper) GetWitnessJson(public bool) []byte {
	schama, err := frontend.NewSchema(g.Assignment)
	if err != nil {
		logger.Fatal("get schema failed: %v", err)
	}
	if public {
		witness, err := g.WitnessFull.Public()
		if err != nil {
			logger.Fatal("get public witness failed: %v", err)
		}
		witnessJson, err := witness.ToJSON(schama)
		if err != nil {
			logger.Fatal("get public witness json failed: %v", err)
		}
		return witnessJson
	} else {
		witnessJson, err := g.WitnessFull.ToJSON(schama)
		if err != nil {
			logger.Fatal("get witness json failed: %v", err)
		}
		return witnessJson
	}
}

func (g *Groth16Wrapper) ExportSolidity(filePath string) {
	if filePath == "" {
		logger.Info("filePath is empty, using default path: output/Groth16Verifier.sol")
		filePath = "output/Groth16Verifier.sol"
	}
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	utils.EnsureDirExists("output")
	solFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logger.Fatal("open file failed: %v", err)
	}
	defer solFile.Close()
	g.VK.ExportSolidity(solFile)
	logger.Info("export solidity to %s", filePath)
}

// 参与gnark-solidity-checker验证流程的准备工作，将proof序列化
func (g *Groth16Wrapper) ProofMarshall() (proofStr string) {
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}

	_proof, ok := g.Proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		logger.Fatal("marshal proof failed")
	}
	proofStr = hex.EncodeToString(_proof.MarshalSolidity())
	return
}

// 参与gnark-solidity-checker验证流程的准备工作，将public witness序列化
func (g *Groth16Wrapper) PublicWitnessMarshall() (publicWitnessStr string) {
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	bPublicWitness, err := g.WitnessPublic.MarshalBinary()
	if err != nil {
		logger.Fatal("marshal public witness failed: %v", err)
	}
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr = hex.EncodeToString(bPublicWitness)
	return
}

// 参与gnark-solidity-checker验证流程的准备工作，获取public input的长度
func (g *Groth16Wrapper) GetPublicInputNum() string {
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	return strconv.Itoa(len(g.WitnessPublic.Vector().(fr_bn254.Vector)))
}

// 阅读gnark-solidity-checker的源码，简化下的proof的处理流程
func (g *Groth16Wrapper) GenSolProofParams() string {
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}

	_proof, ok := g.Proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		logger.Fatal("marshal proof failed")
	}
	proofBytes := _proof.MarshalSolidity()
	var proof [8]*big.Int
	for i := range 8 {
		proof[i] = new(big.Int).SetBytes(proofBytes[FpSize*i : FpSize*(i+1)])
	}
	proofStr := "["
	for i := range proof {
		proofStr += proof[i].String() + ","
	}
	proofStr = proofStr[:len(proofStr)-1]
	proofStr += "]"
	return proofStr
}

// 阅读gnark-solidity-checker的源码，简化下的input的处理流程
func (g *Groth16Wrapper) GenSolInputParams() string {
	if g.Curve != ecc.BN254 {
		logger.Fatal("only BN254 curve is supported")
	}
	bPublicWitness, err := g.WitnessPublic.MarshalBinary()
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
	inputStr := "["
	for i := range input {
		inputStr += input[i].String() + ","
	}
	inputStr = inputStr[:len(inputStr)-1]
	inputStr += "]"
	return inputStr
}

// 编译和ABI生成
// groth16和plonk在这部分除solidity路径外，没有任何不同，但为了方便后续调用，分别在两个文件中添加了此函数
func (g *Groth16Wrapper) SolCompileAndABIgen(solPath string) {
	if solPath == "" {
		logger.Info("solPath is empty, use default path: output/Groth16Verifier.sol")
		solPath = "output/Groth16Verifier.sol"
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

func (g *Groth16Wrapper) SolGenMain() {
	helpers := template.FuncMap{
		"mul": func(a, b int) int {
			return a * b
		},
	}
	tmpl, err := template.New("").Funcs(helpers).Parse(Groth16Template)
	if err != nil {
		logger.Error("failed to parse template: " + err.Error())
	}
	prootStr := g.ProofMarshall()
	inputStr := g.PublicWitnessMarshall()

	data := struct {
		Proof          string
		PublicInputs   string
		NbPublicInputs int
		NbCommitments  int
	}{
		Proof:          prootStr,
		PublicInputs:   inputStr,
		NbPublicInputs: len(g.WitnessPublic.Vector().(fr_bn254.Vector)),
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

func (g *Groth16Wrapper) SolGenGoMod() {
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

func (g *Groth16Wrapper) SolVerify() {
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
