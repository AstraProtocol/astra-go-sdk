---
Description: Tutorial on key types in Astra Protocol.
---

## Keys

The followings are all types of keys a user might possess.

* `mnemonic`: A Seed phrases are part of the BIP39 standard, a seed is usually created from a 12- or 24-word mnemonic. This is a set of rules that simplify managing private keys
  via seed phrases. An example of a mnemonic is  
 `they coffee chapter remain rebel usual one wife between clarify island fee glide van hair trouble rose decade coast smart win pause train what`
  


* `privateKey`: A private key is simply a number, picked randomly. The private key which is used to sign transactions.
  An example of a private key is  
  `e5a27287b69f0c550e944d4e947fa605218e38a64b44997ff0c4dc0a3865c6fc`


* `PaymentAddress`: this is the address to receive funds of a user. An example of a payment address
  is `astra1du8a7n6exmrsn8c6hvyz8rf2x4rg3s7q7cujv5`


* `ValidatorAddress`: this is the key used to stake nodes. An example of a payment address
  is `astravaloper1du8a7n6exmrsn8c6hvyz8rf2x4rg3s7qmparh6`


* `PublicKey`: this is the public key corresponding to generate payment address. An example of a public key
  is `{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"AxluJNomWZ+SWvOMwyeilyIln7WkafIVCR6cZYLYCrwR\"}`
  

*Note: Astra SDK used Hierarchical Deterministic (HD) Wallet to store the digital keys*

Digital key schemes for creating digital signatures is `eth_secp256k1` Curve

To generate an account on Incognito using this SDK.

```go
keyWallet := astraClient.NewAccountClient()
acc, err := keyWallet.CreateAccount()
if err != nil {
    panic(err)
}

data, _ := acc.String()
```

To generate a multisign account on Incognito using this SDK.

```go
acc, addr, pubKey, err := astraClient.CreateMulSignAccount(3, 2)
if err != nil {
    panic(err)
}

fmt.Println("addr", addr)
fmt.Println("pucKey", pubKey)
fmt.Println("list key")

for i, item := range acc {
    fmt.Println("index", i)
    fmt.Println(item.String())
}
```

## Example

[keys.go](./../example/keys.go)

```go
package main

import (
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/client"
	"github.com/AstraProtocol/astra-go-sdk/config"
)

func main() {
	cfg := &config.Config{
		ChainId:       "chain-id",
		Endpoint:      "http://localhost:26657",
		PrefixAddress: "astra",
		TokenSymbol:   "aastra",
	}

	astraClient := client.NewClient(cfg)

	keyWallet := astraClient.NewAccountClient()
	acc, err := keyWallet.CreateAccount()
	if err != nil {
		panic(err)
	}

	data, _ := acc.String()
	fmt.Println(data)
}
```

---
Return to [the table of contents](./readme.md).