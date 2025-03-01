package sha

import (
	"testing"

	"github.com/oliverustc/gnarkabc/logger"
)

func TestCalcSha256(t *testing.T) {
	preImage := "hello"
	preImageU8, hashU8 := CalcSha256(preImage)
	logger.Info("preImageU8: %v", preImageU8)
	logger.Info("hashU8: %v", hashU8)
}
