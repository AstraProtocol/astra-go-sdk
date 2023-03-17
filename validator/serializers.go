package validator

import (
	"math/big"
)

type DelegateRequest struct {
	PrivateKey    string
	DelegateAddr  string
	ValidatorAddr string
	Amount        *big.Int
	GasLimit      uint64
	GasPrice      string
}

type ReDelegateRequest struct {
	PrivateKey        string
	DelegateAddr      string
	FromValidatorAddr string
	ToValidatorAddr   string
	Amount            *big.Int
	GasLimit          uint64
	GasPrice          string
}
