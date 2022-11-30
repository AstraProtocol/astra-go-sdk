---
Description: Tutorial on how to set up a client to connect to Astra Protocol with Go.
---

## Setting up the Client

The Astra Protocol allows anyone to connect by an RPC client.

To interact with the Incognito network, first import the `incclient` package and initialize an Incognito client by calling `NewMainNetClient` which by default connects to the mainnet end-point above. If you wish to connect to the testnet, try `NewTestNetClient`.


## Examples
[client.go](./../example/client.go)

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

	fmt.Println("Let's get yourself into the Astra Protocol!")
	_ = astraClient
}
```
---
Return to [the table of contents](./readme.md).