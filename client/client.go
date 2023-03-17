package client

import (
	"context"
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/account"
	"github.com/AstraProtocol/astra-go-sdk/bank"
	"github.com/AstraProtocol/astra-go-sdk/config"
	"github.com/AstraProtocol/astra-go-sdk/scan"
	"github.com/AstraProtocol/astra-go-sdk/validator"
	sdkClient "github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/types"
	authTypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	distributionTypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/evmos/ethermint/encoding"
	ethermintTypes "github.com/evmos/ethermint/types"
	emvTypes "github.com/evmos/ethermint/x/evm/types"
	"github.com/evmos/evmos/v6/app"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
)

type Client struct {
	prefixAddress        string
	tokenSymbol          string
	rpcClient            sdkClient.Context
	ctx                  context.Context
	queryClient          emvTypes.QueryClient
	queryValidatorClient distributionTypes.QueryClient
}

func (c *Client) RpcClient() sdkClient.Context {
	return c.rpcClient
}

func NewClient(cfg *config.Config) *Client {
	cli := new(Client)
	cli.init(cfg)
	return cli
}

func (c *Client) init(cfg *config.Config) {
	c.prefixAddress = cfg.PrefixAddress
	c.tokenSymbol = cfg.TokenSymbol

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
	encodingConfig := encoding.MakeConfig(app.ModuleBasics)

	//github.com/cosmos/cosmos-sdk/simapp/app.go
	//github.com/evmos/ethermint@v0.19.0/app/app.go -> selected
	rpcHttp, err := rpchttp.New(cfg.Endpoint, "/websocket")
	if err != nil {
		fmt.Println("rpc http error ", err.Error())
		panic(err)
	}

	var ctx = context.Background()
	c.ctx = ctx

	rpcClient := sdkClient.Context{}
	rpcClient = rpcClient.
		WithClient(rpcHttp).
		//WithNodeURI(cfg.Endpoint).
		WithCodec(encodingConfig.Marshaler).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithLegacyAmino(encodingConfig.Amino).
		WithAccountRetriever(ar).
		WithChainID(cfg.ChainId).
		WithBroadcastMode(flags.BroadcastSync)

	c.rpcClient = rpcClient
	c.queryClient = emvTypes.NewQueryClient(rpcClient)
	c.queryValidatorClient = distributionTypes.NewQueryClient(rpcClient)
}

func (c *Client) NewAccountClient() *account.Account {
	return account.NewAccount()
}

func (c *Client) NewBankClient() *bank.Bank {
	return bank.NewBank(c.rpcClient, c.tokenSymbol, c.ctx, c.queryClient)
}

func (c *Client) NewScanner(bank *bank.Bank) *scan.Scanner {
	return scan.NewScanner(c.rpcClient, bank, c.ctx)
}

func (c *Client) NewValidator() *validator.Validator {
	return validator.NewValidator(c.ctx, c.rpcClient, c.queryClient, c.queryValidatorClient, c.tokenSymbol)
}
