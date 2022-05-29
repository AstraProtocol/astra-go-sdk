package common

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestECBEncrypt(t *testing.T) {
	data := "property cactus cannon talent priority silk ice nurse such arctic dove wonder blue stumble chalk engine start know unable tool arctic tone sugar grass"
	result, err := ECBEncrypt([]byte(data), []byte("WA5Nyx4ODj1Y%9j3"))
	if err != nil {
		panic(err)
	}

	fmt.Println(result)

	result1, err := ECBDecrypt(result, []byte("WA5Nyx4ODj1Y%9j3"))

	if err != nil {
		panic(err)
	}

	fmt.Println(result1)
	assert.Equal(t, data, result1)
}

func TestVerifySignature(t *testing.T) {
	publicKey := "A/tdneaDL83fm2BNjYRKacJvRo81iDaYSiybfaDUSM3I"
	publicKey = "A/tdneaDL83fm2BNjYRKacJvRo81iDaYSiybfaDUSM3I\n"
	signature := "MEQCIFKsQUbx0dzVLSqtfz8CGKGeY0/p9xEwED/76X1EdznaAiBk2XZTkOEi\nJpBoiKXbw3bQklw+8M3AffqGwBNJlj+xYQ=="
	msg := "ECDSA is cool."

	isValid, err := VerifySignature(publicKey, signature, msg)
	if err != nil {
		panic(err)
	}

	fmt.Println(isValid)
}