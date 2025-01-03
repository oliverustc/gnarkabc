package utils

import "github.com/go-echarts/go-echarts/v2/opts"

// 转换 int64 切片为 opts.BarData 切片
func ConvertToBarData(times []int64) []opts.BarData {
	var barData []opts.BarData
	for _, time := range times {
		barData = append(barData, opts.BarData{Value: time})
	}
	return barData
}
