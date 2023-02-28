package processing

import (
	"GoBrrp/helper"

	"github.com/sirupsen/logrus"
)

func Inner(input []byte) []byte {
	//input
	logrus.Info("INCOMING INPUT:", helper.PrintByteArray(input))
	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i]
	}
	logrus.Debugln("New result: ", helper.PrintByteArray(result))
	return result
}

func Outer(input []byte) []byte {
	logrus.Error("OUTGOING INPUT:", helper.PrintByteArray(input))
	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = input[i]
	}
	return result
}
