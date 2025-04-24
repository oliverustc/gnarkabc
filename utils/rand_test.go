package utils

import (
	"testing"

	"gnarkabc/logger"
)

func TestRandStr(t *testing.T) {
	for i := 0; i < 10; i++ {
		randStr := RandStr(32)
		logger.Info("randStr: %s", randStr)
	}
}

func TestRandInt(t *testing.T) {
	for i := 0; i < 10; i++ {
		randInt := RandInt(1, 100)
		logger.Info("randInt: %d", randInt)
	}
}

func TestRandItem(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	for i := 0; i < 10; i++ {
		randItem := RandItem(items)
		logger.Info("randItem: %s", randItem)
	}
}
