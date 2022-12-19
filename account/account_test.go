package account

import (
	"fmt"
	"testing"
)

func TestCreateAccount(t *testing.T) {
	n := NewAccount(60)
	key, err := n.CreateAccount()
	if err != nil {
		panic(err)
	}
	fmt.Println("key type 60")
	fmt.Println(key.String())

	n1 := NewAccount(118)
	key1, err := n1.CreateAccount()
	if err != nil {
		panic(err)
	}

	fmt.Println("key type 118")
	fmt.Println(key1.String())
}

func TestCreateMulAccount(t *testing.T) {
	n := NewAccount(60)
	key, addr, pubKey, err := n.CreateMulSignAccount(3, 2)
	if err != nil {
		panic(err)
	}

	fmt.Println("key type 60")
	fmt.Println("addr", addr)
	fmt.Println("pucKey", pubKey)
	fmt.Println("list key")
	for i, serialized := range key {
		fmt.Println("index", i)
		fmt.Println(serialized.String())
	}
}

func TestCreateMulAccountFromAccount(t *testing.T) {
	n := NewAccount(60)
	account1, _ := n.CreateAccount()
	account2, _ := n.CreateAccount()
	addr, pubKey, err := n.CreateMulSignAccountFromTwoAccount(account1.PublicKey(), account2.PublicKey(), 2)
	if err != nil {
		panic(err)
	}

	fmt.Println("key type 60")
	fmt.Println("addr", addr)
	fmt.Println("pucKey", pubKey)
}

func TestImportPrivateKey(t *testing.T) {
	n := NewAccount(60)
	key, err := n.ImportPrivateKey("c6849b352fb9027e0a4592c52226de2f37747192412f50f8daeac6c5a6f5e9de")
	if err != nil {
		panic(err)
	}

	fmt.Println("key type 60")
	fmt.Println(key.String())
}
