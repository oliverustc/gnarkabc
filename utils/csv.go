package utils

import (
	"encoding/csv"
	"fmt"
	"gnarkabc/logger"
	"os"
	"time"
)

// CSVWriter 结构体用于处理 CSV 文件的读写操作
// 提供了按行、按列写入数据的功能，支持文件和目录的自动创建
type CSVWriter struct {
	Folder       string   // CSV 文件的根目录路径
	FileName     string   // CSV 文件名（不含路径）
	Path         string   // CSV 文件的完整路径
	ColumnLabels []string // CSV 文件的列标签集合
	RowLabels    []string // CSV 文件的行标签集合
}

func NewCSVWriter(fileName string) *CSVWriter {
	cw := &CSVWriter{
		FileName: fileName,
	}
	return cw
}

func (cw *CSVWriter) Init(folder ...string) {
	defaultFolder := "data"
	// 如果传入folder，则使用传入的folder
	if len(folder) > 0 {
		defaultFolder = folder[0]
		cw.Folder = defaultFolder
		cw.Path = defaultFolder + "/" + cw.FileName
	} else {
		// 否则使用当前日期和时间作为文件夹名
		dataStr := time.Now().Format("2006-01-02")
		timeStr := time.Now().Format("15-04-05")
		cw.Folder = defaultFolder + "/" + dataStr
		cw.Path = defaultFolder + "/" + dataStr + "/" + timeStr + "_" + cw.FileName
	}
	cw.ensureFolderExists()
	cw.ensureFileExists()
}

// ensureFolderExists 确保存储 CSV 文件的文件夹存在
// 如果文件夹不存在，则创建它
func (cw *CSVWriter) ensureFolderExists() {
	_, err := os.Stat(cw.Folder)
	if os.IsNotExist(err) {
		logger.Debug("Folder:%s Not Exist, Create it", cw.Folder)
		err = os.MkdirAll(cw.Folder, os.ModePerm)
		if err != nil {
			logger.Fatal("Create folder:%s Failed, %v", cw.Folder, err)
		}
	}
}

func (cw *CSVWriter) ensureFileExists() {
	_, err := os.Stat(cw.Path)
	if os.IsNotExist(err) {
		logger.Debug("File:%s Not Exist, Create it", cw.Path)
		file, err := os.OpenFile(cw.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			logger.Fatal("Open file:%s Failed, %v", cw.Path, err)
		}
		defer file.Close()
	}
}

func (cw *CSVWriter) WriteRow(row []string) {
	cw.ensureFileExists()
	file, err := os.OpenFile(cw.Path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		logger.Fatal("Open file:%s Failed, %v", cw.Path, err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	err = writer.Write(row)
	if err != nil {
		logger.Fatal("Write to csv Failed, %v", err)
	}
	writer.Flush()
}

// WriteCol 将数据按列写入 CSV 文件
// 如果文件不存在则创建，如果文件存在则追加新列
// 参数:
//   - col: 要写入的列数据切片
func (cw *CSVWriter) WriteCol(col []string) {
	cw.ensureFileExists()

	// 以读写模式打开文件
	file, err := os.OpenFile(cw.Path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		logger.Fatal("打开文件失败:%s, %v", cw.Path, err)
	}
	defer file.Close()
	logger.Debug("open and write permission check ok")

	// 读取现有数据
	reader := csv.NewReader(file)
	data, err := reader.ReadAll()
	if err != nil {
		logger.Fatal("读取文件失败:%s, %v", cw.Path, err)
	}
	logger.Debug("data: %v", data)
	// 更新数据
	data = cw.updateDataWithNewCol(data, col)

	// // 回到文件开始处
	// file.Seek(0, 0)
	// file.Truncate(0)

	file, err = os.OpenFile(cw.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		logger.Fatal("Open file:%s Failed, %v", cw.Path, err)
	}
	writer := csv.NewWriter(file)
	err = writer.WriteAll(data)
	if err != nil {
		logger.Fatal("Write File:%s Failed, %v", cw.Path, err)
	}
	writer.Flush()
}

// updateDataWithNewCol 将新列数据整合到现有的 CSV 数据中
// 参数:
//   - data: 现有的 CSV 数据矩阵
//   - col: 要添加的新列数据
//
// 返回值:
//   - [][]string: 更新后的数据矩阵
func (cw *CSVWriter) updateDataWithNewCol(data [][]string, col []string) [][]string {
	if len(data) == 0 {
		data = make([][]string, len(col))
		for i := range data {
			data[i] = make([]string, 1)
			data[i][0] = col[i]
		}
		logger.Debug("data is empty, create new data: %v", data)
	} else {
		for i, value := range col {
			if i < len(data) {
				data[i] = append(data[i], value)
			} else {
				logger.Error("col: %v", col)
				logger.Error("data: %v", data)
				logger.Fatal("Length of col:%d and data:%d not match !", len(col), len(data[0]))
			}
		}
		logger.Debug("update data with new col: %v", data)
	}
	return data
}

func (cw *CSVWriter) InitColLabels(colLabels []string) {
	cw.ColumnLabels = colLabels
	logger.Debug("colLabels: %v", colLabels)
	cw.WriteCol(colLabels)
}

// RecordCol 记录一列时间数据到 CSV 文件
// 参数:
//   - colLabel: 列标签
//   - timeDuration: 要记录的时间数据切片
func (cw *CSVWriter) RecordCol(colLabel string, colData []string) {
	newCol := append([]string{colLabel}, colData...)
	logger.Debug("new Col: %v", newCol)
	cw.WriteCol(newCol)
}

// AverageByRow 计算二维时间切片的行平均值
// 参数:
//   - durations: 二维时间切片
//
// 返回值:
//   - []time.Duration: 每行的平均时间值
func AverageByRow(durations [][]time.Duration) []time.Duration {
	rowAverages := make([]time.Duration, len(durations))
	logger.Debug("Durations: %v", durations)
	for i, row := range durations {
		var rowTotal time.Duration
		for _, d := range row {
			rowTotal += d
		}
		rowAverages[i] = rowTotal / time.Duration(len(row))
	}
	logger.Debug("Row Averages: %v", rowAverages)
	return rowAverages
}

// AverageByCol 计算二维时间切片的列平均值
// 参数:
//   - durations: 二维时间切片
//
// 返回值:
//   - []time.Duration: 每列的平均时间值
func AverageByCol(durations [][]time.Duration) []time.Duration {
	if len(durations) == 0 {
		return nil
	}

	// Assuming all inner slices have the same length
	numCols := len(durations[0])
	sums := make([]time.Duration, numCols)
	counts := make([]int, numCols)

	for _, row := range durations {
		for j, duration := range row {
			sums[j] += duration
			counts[j]++
		}
	}

	averages := make([]time.Duration, numCols)
	for i := range averages {
		averages[i] = sums[i] / time.Duration(counts[i])
	}

	return averages
}

// ConvertMilliSec 将时间间隔转换为毫秒为单位的字符串表示
// 参数:
//   - timeDuration: 要转换的时间间隔
//
// 返回值:
//   - string: 保留三位小数的毫秒值字符串
func ConvertMilliSec(timeDuration time.Duration) string {
	timeFloat := float64(timeDuration.Nanoseconds()) / 1e6
	return fmt.Sprintf("%.3f", timeFloat)
}

func (cw *CSVWriter) InitRowLabels(rowLabels []string) {
	cw.RowLabels = rowLabels
	cw.WriteRow(rowLabels)
}

// RecordRow 记录一行数据和对应的时间数据到 CSV 文件
// 参数:
//   - row: 基础数据行
//   - timeDurationList: 要记录的时间数据切片
func (cw *CSVWriter) RecordRow(rowData []string) {
	cw.WriteRow(rowData)
}
