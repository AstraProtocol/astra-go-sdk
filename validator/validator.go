package validator

import (
	"context"
	"github.com/AstraProtocol/astra-go-sdk/account"
	"github.com/AstraProtocol/astra-go-sdk/common"
	"github.com/cosmos/cosmos-sdk/client"
	sdkTypes "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/staking/types"
	emvTypes "github.com/evmos/ethermint/x/evm/types"
	"github.com/pkg/errors"
)

type Validator struct {
	ctx         context.Context
	rpcClient   client.Context
	queryClient emvTypes.QueryClient
	tokenSymbol string
}

func NewValidator(ctx context.Context, rpcClient client.Context, queryClient emvTypes.QueryClient, tokenSymbol string) *Validator {
	return &Validator{ctx: ctx, rpcClient: rpcClient, queryClient: queryClient, tokenSymbol: tokenSymbol}
}

func (v *Validator) Delegate(param *DelegateRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	acc, err := auth.ImportAccount(param.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	coin := sdkTypes.NewCoin(v.tokenSymbol, sdkTypes.NewIntFromBigInt(param.Amount))
	valAddr, err := sdkTypes.ValAddressFromBech32(param.ValidatorAddr)
	if err != nil {
		return nil, err
	}

	delAddr, err := sdkTypes.AccAddressFromBech32(param.DelegateAddr)
	if err != nil {
		return nil, err
	}

	msg := types.NewMsgDelegate(delAddr, valAddr, coin)

	newTx := common.NewTx(
		v.rpcClient,
		v.ctx,
		v.queryClient,
		acc,
		param.GasLimit,
		param.GasPrice)

	txBuilder, err := newTx.BuildUnsignedTx(msg)
	if err != nil {
		return nil, errors.Wrap(err, "BuildUnsignedTx")
	}

	err = newTx.SignTx(txBuilder)
	if err != nil {
		return nil, errors.Wrap(err, "SignTx")
	}

	return txBuilder, nil
}

func (v *Validator) ReDelegate(param *ReDelegateRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	acc, err := auth.ImportAccount(param.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	coin := sdkTypes.NewCoin(v.tokenSymbol, sdkTypes.NewIntFromBigInt(param.Amount))
	fromValAddr, err := sdkTypes.ValAddressFromBech32(param.FromValidatorAddr)
	if err != nil {
		return nil, err
	}

	toValAddr, err := sdkTypes.ValAddressFromBech32(param.ToValidatorAddr)
	if err != nil {
		return nil, err
	}

	delAddr, err := sdkTypes.AccAddressFromBech32(param.DelegateAddr)
	if err != nil {
		return nil, err
	}

	msg := types.NewMsgBeginRedelegate(delAddr, fromValAddr, toValAddr, coin)

	newTx := common.NewTx(
		v.rpcClient,
		v.ctx,
		v.queryClient,
		acc,
		param.GasLimit,
		param.GasPrice)

	txBuilder, err := newTx.BuildUnsignedTx(msg)
	if err != nil {
		return nil, errors.Wrap(err, "BuildUnsignedTx")
	}

	err = newTx.SignTx(txBuilder)
	if err != nil {
		return nil, errors.Wrap(err, "SignTx")
	}

	return txBuilder, nil
}

func (v *Validator) UnDelegate(param *DelegateRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	acc, err := auth.ImportAccount(param.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	coin := sdkTypes.NewCoin(v.tokenSymbol, sdkTypes.NewIntFromBigInt(param.Amount))
	valAddr, err := sdkTypes.ValAddressFromBech32(param.ValidatorAddr)
	if err != nil {
		return nil, err
	}

	delAddr, err := sdkTypes.AccAddressFromBech32(param.DelegateAddr)
	if err != nil {
		return nil, err
	}

	msg := types.NewMsgUndelegate(delAddr, valAddr, coin)

	newTx := common.NewTx(
		v.rpcClient,
		v.ctx,
		v.queryClient,
		acc,
		param.GasLimit,
		param.GasPrice)

	txBuilder, err := newTx.BuildUnsignedTx(msg)
	if err != nil {
		return nil, errors.Wrap(err, "BuildUnsignedTx")
	}

	err = newTx.SignTx(txBuilder)
	if err != nil {
		return nil, errors.Wrap(err, "SignTx")
	}

	return txBuilder, nil
}
