---
Description: Tutorial on how to restore accounts from a mnemonic string.
---

# Restore Accounts from a Mnemonic String

Suppose that you have created your accounts from somewhere else (e.g., Incognito Wallet) and you want to restore all of
them using this `go-sdk`. This time, we use the function [`ImportAccount`](../../../incclient/account.go) in
the [`incclient`](../../../incclient) package.

```go
wallets, err := astraClient.ImportAccount(mnemonic)
if err != nil {
    log.Fatal(err)
}
```

## Example

[import_keys.go](./../example/keys.go)

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

	mnemonic := "naive journey paper infant arch loyal credit since rebuild crisp coil jelly name kind anchor mixture unique drink fame cherry network quarter step tired"

	keyWallet := astraClient.NewAccountClient()
	acc, err := keyWallet.ImportAccount(mnemonic)
	if err != nil {
		panic(err)
	}

	data, _ := acc.String()
	fmt.Println(data)
}

```

---
Return to [the table of contents](./readme.md).