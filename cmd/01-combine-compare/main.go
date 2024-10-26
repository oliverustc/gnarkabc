package main

import (
	"gnarkabc/gnarkwrapper"
	"gnarkabc/logger"
	"os"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// 定义一个简单的电路结构
type SimpleCircuit struct {
	X frontend.Variable `gnark:"x"`       // 输入变量 X
	Y frontend.Variable `gnark:",public"` // 公共输出变量 Y
}

// 定义电路的逻辑：Y = X^3 + X + 5
func (sc *SimpleCircuit) Define(api frontend.API) error {
	// 计算 X 的立方
	x3 := api.Mul(sc.X, sc.X, sc.X)
	// 计算 Y 的值
	res := api.Add(x3, sc.X, 5)
	// 断言 Y 等于计算结果
	api.AssertIsEqual(sc.Y, res)
	return nil
}

type ZkDuration struct {
	CurveName   string
	CompileTime int64
	SetupTime   int64
	ProveTime   int64
	VerifyTime  int64
}

func Groth16ZK() []ZkDuration {
	var durations []ZkDuration
	var curveNameList = []string{"BN254", "BLS12-377", "BLS12-381", "BW6-633", "BW6-761", "BLS24-315", "BLS24-317"}
	for _, curveName := range curveNameList {
		logger.Info("testing groth16 zk-snark on curve %s", curveName)
		curve := gnarkwrapper.CurveMap[curveName]
		var sc SimpleCircuit
		zk := gnarkwrapper.NewGroth16(&sc, curve)
		zk.Compile()
		zk.Setup()
		x := 133
		y := x*x*x + x + 5
		validAssignment := &SimpleCircuit{
			X: x,
			Y: y,
		}
		zk.Assignment = validAssignment
		zk.Prove()
		zk.Verify()
		zk.BenchmarkCompile(10)
		zk.BenchmarkSetup(10)
		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)

		durations = append(durations, ZkDuration{
			CurveName:   curveName,
			CompileTime: zk.CompileTime.Microseconds(),
			SetupTime:   zk.SetupTime.Microseconds(),
			ProveTime:   zk.ProveTime.Microseconds(),
			VerifyTime:  zk.VerifyTime.Microseconds(),
		})
	}
	return durations
}

func PlonkZk() []ZkDuration {
	var durations []ZkDuration
	var curveNameList = []string{"BN254", "BLS12-377", "BLS12-381", "BW6-633", "BW6-761", "BLS24-315", "BLS24-317"}
	for _, curveName := range curveNameList {
		logger.Info("testing plonk zk-snark on curve %s", curveName)
		curve := gnarkwrapper.CurveMap[curveName]
		var sc SimpleCircuit
		zk := gnarkwrapper.NewPlonk(&sc, curve)
		zk.Compile()
		zk.Setup()
		x := 133
		y := x*x*x + x + 5
		validAssignment := &SimpleCircuit{
			X: x,
			Y: y,
		}
		zk.Assignment = validAssignment
		zk.Prove()
		zk.Verify()
		zk.BenchmarkCompile(10)
		zk.BenchmarkSetup(10)
		zk.BenchmarkProve(10)
		zk.BenchmarkVerify(10)

		durations = append(durations, ZkDuration{
			CurveName:   curveName,
			CompileTime: zk.CompileTime.Microseconds(),
			SetupTime:   zk.SetupTime.Microseconds(),
			ProveTime:   zk.ProveTime.Microseconds(),
			VerifyTime:  zk.VerifyTime.Microseconds(),
		})
	}
	return durations
}

// 转换 int64 切片为 opts.BarData 切片
func ConvertToBarData(times []int64) []opts.BarData {
	var barData []opts.BarData
	for _, time := range times {
		barData = append(barData, opts.BarData{Value: time})
	}
	return barData
}

func DrawCharts(groth16, plonk []ZkDuration) {
	// 创建图表
	barCompile := charts.NewBar()
	barSetup := charts.NewBar()
	barProve := charts.NewBar()
	barVerify := charts.NewBar()

	// 设置全局选项
	for _, bar := range []*charts.Bar{barCompile, barSetup, barProve, barVerify} {
		bar.SetGlobalOptions(
			charts.WithTitleOpts(opts.Title{
				Title:    "ZK-SNARK Performance Comparison",
				Subtitle: "Performance metrics for different curves",
			}),
			charts.WithLegendOpts(opts.Legend{
				Orient: "vertical",
				Left:   "right",
			}),
			charts.WithGridOpts(opts.Grid{
				Top: "20%",
			}),
			charts.WithYAxisOpts(opts.YAxis{
				Name: "时间 (微秒)",
			}),
		)
	}
	var (
		curveNames         []string
		groth16CompileTime []int64
		plonkCompileTime   []int64
		groth16SetupTime   []int64
		plonkSetupTime     []int64
		groth16ProveTime   []int64
		plonkProveTime     []int64
		groth16VerifyTime  []int64
		plonkVerifyTime    []int64
	)

	for _, dur := range groth16 {
		curveNames = append(curveNames, dur.CurveName)
		groth16CompileTime = append(groth16CompileTime, dur.CompileTime)
		groth16SetupTime = append(groth16SetupTime, dur.SetupTime)
		groth16ProveTime = append(groth16ProveTime, dur.ProveTime)
		groth16VerifyTime = append(groth16VerifyTime, dur.VerifyTime)
	}
	for _, dur := range plonk {
		plonkCompileTime = append(plonkCompileTime, dur.CompileTime)
		plonkSetupTime = append(plonkSetupTime, dur.SetupTime)
		plonkProveTime = append(plonkProveTime, dur.ProveTime)
		plonkVerifyTime = append(plonkVerifyTime, dur.VerifyTime)
	}

	barCompile.SetXAxis(curveNames).
		AddSeries("Groth16 Compile Time", ConvertToBarData(groth16CompileTime)).
		AddSeries("Plonk Compile Time", ConvertToBarData(plonkCompileTime))

	barSetup.SetXAxis(curveNames).
		AddSeries("Groth16 Setup Time", ConvertToBarData(groth16SetupTime)).
		AddSeries("Plonk Setup Time", ConvertToBarData(plonkSetupTime))

	barProve.SetXAxis(curveNames).
		AddSeries("Groth16 Prove Time", ConvertToBarData(groth16ProveTime)).
		AddSeries("Plonk Prove Time", ConvertToBarData(plonkProveTime))

	barVerify.SetXAxis(curveNames).
		AddSeries("Groth16 Verify Time", ConvertToBarData(groth16VerifyTime)).
		AddSeries("Plonk Verify Time", ConvertToBarData(plonkVerifyTime))

	// 渲染到 HTML 文件
	date := time.Now().Format("2006-01-02_15-04-05")
	f, err := os.Create("performance_" + date + ".html")
	if err != nil {
		logger.Fatal("create file failed: " + err.Error())
	}
	defer f.Close()
	// 渲染每个图表
	barCompile.Render(f)
	barSetup.Render(f)
	barProve.Render(f)
	barVerify.Render(f)
}

func main() {
	groth16Duration := Groth16ZK()
	plonkDuration := PlonkZk()
	DrawCharts(groth16Duration, plonkDuration)
}
