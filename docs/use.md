### Initialized Client

```go
import (
    "fmt"
    "github.com/AstraProtocol/astra-go-sdk/client"
)

func main() {
    cfg := &config.Config{
       	ChainId:       "chain-id",
		Endpoint:      "http://localhost:26657",
        PrefixAddress: "astra",
        TokenSymbol:   "aastra",
    }
    
    client := NewClient(cfg)
    
    //todo
}
```

### Create account

```go
    accClient := client.NewAccountClient()
    acc, err := accClient.CreateAccount()
    if err != nil {
        panic(err)
    }
    
    data, _ := acc.String()
```

### Create MultiSign Account

```go
    accClient := client.NewAccountClient()
    acc, addr, pubKey, err := accClient.CreateMulSignAccount(3, 2)
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