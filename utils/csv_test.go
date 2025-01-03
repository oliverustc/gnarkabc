package utils

import (
	"testing"
)

func TestCsvWriter(t *testing.T) {
	cw := NewCSVWriter("test_write_row_col.csv")
	cw.WriteRow([]string{"1", "2", "3"})
	cw.WriteRow([]string{"1", "2", "3"})
	cw.WriteRow([]string{"1", "2", "3"})
	cw.WriteCol([]string{"4", "5", "6"})
	cw.WriteCol([]string{"4", "5", "6"})
	cw.WriteCol([]string{"7", "8", "9"})
}

// func TestCSVRecordRow(t *testing.T) {
// 	cw := NewCSVWriter("test_record_row.csv")
// 	cw.InitRowLabels([]string{"Time", "time1", "time2", "time3"})
// 	cw.RecordRow([]string{"para1"}, []time.Duration{time.Second, time.Second * 2, time.Second * 3})
// 	cw.RecordRow([]string{"para2"}, []time.Duration{time.Second * 4, time.Second * 5, time.Second * 6})
// 	cw.RecordRow([]string{"para3"}, []time.Duration{time.Second * 7, time.Second * 8, time.Second * 9})
// 	cw.RecordRow([]string{"para4"}, []time.Duration{time.Second * 10, time.Second * 11, time.Second * 12})
// }

func TestCSVRecordCol(t *testing.T) {
	cw := NewCSVWriter("test_record_col.csv")
	// cw.Init()
	cw.Init("example")
	cw.InitColLabels([]string{"Time", "time1", "time2", "time3"})
	cw.RecordCol("para1", []string{"1", "2", "3"})
	cw.RecordCol("para2", []string{"4", "5", "6"})
	cw.RecordCol("para3", []string{"7", "8", "9"})
	cw.RecordCol("para4", []string{"10", "11", "12"})
}
