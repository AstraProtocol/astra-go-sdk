package client

import (
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/account"
	"github.com/AstraProtocol/astra-go-sdk/bank"
	"github.com/AstraProtocol/astra-go-sdk/config"
	"github.com/AstraProtocol/astra-go-sdk/scan"
	sdkClient "github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/types"
	authTypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/evmos/ethermint/encoding"
	ethermintTypes "github.com/evmos/ethermint/types"
	"github.com/evmos/evmos/v6/app"
)

type Client struct {
	coinType      uint32
	prefixAddress string
	tokenSymbol   string
	rpcClient     sdkClient.Context
}

func (c *Client) RpcClient() sdkClient.Context {
	return c.rpcClient
}

func NewClient(cfg *config.Config) *Client {
	cli := new(Client)
	cli.Init(cfg)
	return cli
}

func (c *Client) Init(cfg *config.Config) {
	c.prefixAddress = cfg.PrefixAddress
	c.tokenSymbol = cfg.TokenSymbol
	c.coinType = ethermintTypes.Bip44CoinType

	sdkConfig := types.GetConfig()
	sdkConfig.SetPurpose(44)
	sdkConfig.SetCoinType(ethermintTypes.Bip44CoinType)

	bech32PrefixAccAddr := fmt.Sprintf("%v", c.prefixAddress)
	bech32PrefixAccPub := fmt.Sprintf("%vpub", c.prefixAddress)
	bech32PrefixValAddr := fmt.Sprintf("%vvaloper", c.prefixAddress)
	bech32PrefixValPub := fmt.Sprintf("%vvaloperpub", c.prefixAddress)
	bech32PrefixConsAddr := fmt.Sprintf("%vvalcons", c.prefixAddress)
	bech32PrefixConsPub := fmt.Sprintf("%vvalconspub", c.prefixAddress)

	sdkConfig.SetBech32PrefixForAccount(bech32PrefixAccAddr, bech32PrefixAccPub)
	sdkConfig.SetBech32PrefixForValidator(bech32PrefixValAddr, bech32PrefixValPub)
	sdkConfig.SetBech32PrefixForConsensusNode(bech32PrefixConsAddr, bech32PrefixConsPub)

	ar := authTypes.AccountRetriever{}

	//github.com/cosmos/cosmos-sdk/simapp/app.go
	//github.com/evmos/ethermint@v0.19.0/app/app.go -> selected
	encodingConfig := encoding.MakeConfig(app.ModuleBasics)
	rpcHttp, err := sdkClient.NewClientFromNode(cfg.Endpoint)
	if err != nil {
		panic(err)
	}

	rpcClient := sdkClient.Context{}
	rpcClient = rpcClient.
		WithClient(rpcHttp).
		//WithNodeURI(c.endpoint).
		WithCodec(encodingConfig.Marshaler).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithAccountRetriever(ar).
		WithChainID(cfg.ChainId).
		WithBroadcastMode(flags.BroadcastSync)

	c.rpcClient = rpcClient
}

func (c *Client) NewAccountClient() *account.Account {
	return account.NewAccount()
}

func (c *Client) NewBankClient() *bank.Bank {
	return bank.NewBank(c.rpcClient, c.tokenSymbol)
}

func (c *Client) NewScanner(bank *bank.Bank) *scan.Scanner {
	return scan.NewScanner(c.rpcClient, bank)
}
