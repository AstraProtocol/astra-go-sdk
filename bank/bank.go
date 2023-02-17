package bank

import (
	"context"
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/account"
	"github.com/AstraProtocol/astra-go-sdk/common"
	"github.com/AstraProtocol/astra-go-sdk/config"
	"github.com/cosmos/cosmos-sdk/client"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	signingTypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	emvTypes "github.com/evmos/ethermint/x/evm/types"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"math/big"
	"strings"
	"time"
)

type Bank struct {
	rpcClient   client.Context
	tokenSymbol string
}

func NewBank(rpcClient client.Context, tokenSymbol string) *Bank {
	return &Bank{rpcClient: rpcClient, tokenSymbol: tokenSymbol}
}

func (b *Bank) Balance(addr string) (*big.Int, error) {
	var header metadata.MD

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*config.ReqTimeout))
	defer cancel()

	ethAddr, err := common.CosmosAddressToEthAddress(addr)
	if err != nil {
		return nil, errors.Wrap(err, "Balance")
	}

	bankClient := emvTypes.NewQueryClient(b.rpcClient)
	bankRes, err := bankClient.Balance(
		ctx,
		&emvTypes.QueryBalanceRequest{Address: ethAddr},
		grpc.Header(&header),
	)

	if err != nil {
		return nil, errors.Wrap(err, "Balance")
	}

	balance, ok := big.NewInt(0).SetString(bankRes.Balance, 10)
	if !ok {
		return nil, errors.Errorf("balance parser %v error", bankRes.Balance)
	}

	return balance, nil
}

func (b *Bank) AccountRetriever(addr string) (uint64, uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*config.ReqTimeout))
	defer cancel()

	queryClient := emvTypes.NewQueryClient(b.rpcClient)
	cosmosAccount, err := queryClient.CosmosAccount(ctx, &emvTypes.QueryCosmosAccountRequest{Address: addr})
	if err != nil {
		return 0, 0, errors.Wrap(err, "CosmosAccount")
	}

	accNum := cosmosAccount.AccountNumber
	accSeq := cosmosAccount.Sequence

	return accNum, accSeq, nil
}

func (b *Bank) BaseFee() (string, error) {
	queryClient := emvTypes.NewQueryClient(b.rpcClient)

	expRes := &emvTypes.QueryBaseFeeRequest{}
	baseFee, err := queryClient.BaseFee(context.Background(), expRes)
	if err != nil {
		return "0", errors.Wrap(err, "BaseFee")
	}

	return fmt.Sprintf("%v%v", baseFee.BaseFee.String(), common.TokenSymbol), nil
}

func (b *Bank) CheckTx(txHash string) (*types.TxResponse, error) {
	output, err := authtx.QueryTx(b.rpcClient, txHash)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("no transaction found with hash %s. err = %v", txHash, err.Error())
		}

		return nil, err
	}

	if output.Empty() {
		return nil, fmt.Errorf("no transaction found with hash %s", txHash)
	}

	return output, nil
}

func (b *Bank) TransferRawData(param *TransferRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	acc, err := auth.ImportAccount(param.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	receiver, err := types.AccAddressFromBech32(param.Receiver)
	if err != nil {
		return nil, errors.Wrap(err, "AccAddressFromBech32")
	}

	coin := types.NewCoin(b.tokenSymbol, types.NewIntFromBigInt(param.Amount))
	msg := bankTypes.NewMsgSend(
		acc.AccAddress(),
		receiver,
		types.NewCoins(coin),
	)

	/*gasPrice, err := b.BaseFee()
	if err != nil {
		return nil, errors.Wrap(err, "BaseFee")
	}*/

	newTx := common.NewTx(b.rpcClient, acc, param.GasLimit, param.GasPrice)

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

func (b *Bank) TransferRawDataAndEstimateGas(param *TransferRequest) (client.TxBuilder, error) {
	txBuilder, err := b.TransferRawData(param)
	if err != nil {
		return nil, err
	}

	txBytes, err := b.rpcClient.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return nil, err
	}

	txSvcClient := tx.NewServiceClient(b.rpcClient)
	simRes, err := txSvcClient.Simulate(context.Background(), &tx.SimulateRequest{
		TxBytes: txBytes,
	})

	if err != nil {
		return nil, err
	}

	if simRes.GasInfo.GasUsed > 0 {
		param.GasLimit = simRes.GasInfo.GasUsed
	}

	return b.TransferRawData(param)
}

func (b *Bank) TransferRawDataWithPrivateKey(param *TransferRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	acc, err := auth.ImportPrivateKey(param.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	receiver, err := types.AccAddressFromBech32(param.Receiver)
	if err != nil {
		return nil, errors.Wrap(err, "AccAddressFromBech32")
	}

	coin := types.NewCoin(b.tokenSymbol, types.NewIntFromBigInt(param.Amount))
	msg := bankTypes.NewMsgSend(
		acc.AccAddress(),
		receiver,
		types.NewCoins(coin),
	)

	/*gasPrice, err := b.BaseFee()
	if err != nil {
		return nil, errors.Wrap(err, "BaseFee")
	}*/

	newTx := common.NewTx(b.rpcClient, acc, param.GasLimit, param.GasPrice)

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

func (b *Bank) TransferRawDataWithPrivateKeyAndEstimateGas(param *TransferRequest) (client.TxBuilder, error) {
	txBuilder, err := b.TransferRawDataWithPrivateKey(param)
	if err != nil {
		return nil, err
	}

	txBytes, err := b.rpcClient.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return nil, err
	}

	txSvcClient := tx.NewServiceClient(b.rpcClient)
	simRes, err := txSvcClient.Simulate(context.Background(), &tx.SimulateRequest{
		TxBytes: txBytes,
	})

	if err != nil {
		return nil, err
	}

	if simRes.GasInfo.GasUsed > 0 {
		param.GasLimit = simRes.GasInfo.GasUsed
	}

	return b.TransferRawDataWithPrivateKey(param)
}

func (b *Bank) SignTxWithSignerAddress(param *SignTxWithSignerAddressRequest) (client.TxBuilder, error) {
	auth := account.NewAccount()
	privateKey, err := auth.ImportAccount(param.SignerPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "ImportAccount")
	}

	from := types.AccAddress(param.MulSignAccPublicKey.Address())
	receiver, err := types.AccAddressFromBech32(param.Receiver)
	if err != nil {
		return nil, errors.Wrap(err, "AccAddressFromBech32")
	}

	amount := types.NewCoin(b.tokenSymbol, types.NewIntFromBigInt(param.Amount))
	msg := bankTypes.NewMsgSend(
		from,
		receiver,
		types.NewCoins(amount),
	)

	newTx := common.NewTxMulSign(
		b.rpcClient,
		privateKey,
		param.GasLimit,
		param.GasPrice,
		param.SequeNum,
		param.AccNum)

	txBuilder, err := newTx.BuildUnsignedTx(msg)
	if err != nil {
		return nil, errors.Wrap(err, "BuildUnsignedTx")
	}

	err = newTx.SignTxWithSignerAddress(txBuilder, param.MulSignAccPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "SignTxWithSignerAddress")
	}

	return txBuilder, nil
}

func (b *Bank) TransferMultiSignRawData(param *TransferMultiSignRequest) (client.TxBuilder, error) {
	mulSignAccPublicKey := param.MulSignAccPublicKey

	from := types.AccAddress(mulSignAccPublicKey.Address())
	receiver, err := types.AccAddressFromBech32(param.Receiver)
	if err != nil {
		return nil, errors.Wrap(err, "AccAddressFromBech32")
	}

	amount := types.NewCoin(b.tokenSymbol, types.NewIntFromBigInt(param.Amount))
	msg := bankTypes.NewMsgSend(
		from,
		receiver,
		types.NewCoins(amount),
	)

	newTx := common.NewTxMulSign(
		b.rpcClient,
		nil,
		param.GasLimit,
		param.GasPrice,
		param.SequeNum,
		param.AccNum,
	)

	txBuilder, err := newTx.BuildUnsignedTx(msg)
	if err != nil {
		return nil, errors.Wrap(err, "BuildUnsignedTx")
	}

	err = newTx.CreateTxMulSign(txBuilder, mulSignAccPublicKey, param.Sigs)
	if err != nil {
		return nil, errors.Wrap(err, "CreateTxMulSign")
	}

	return txBuilder, nil
}

func (b *Bank) TransferMultiSignEstimateGas(privateKey []string, multiSign cryptoTypes.PubKey, amount *big.Int, gasPrice string, gasLimit uint64) (uint64, error) {
	//todo: account estimate is temp account, note: do not use this account

	masterPk := multiSign
	signList := make([][]signingTypes.SignatureV2, 0)
	for _, s := range privateKey {
		request := &SignTxWithSignerAddressRequest{
			SignerPrivateKey:    s,
			MulSignAccPublicKey: masterPk,
			Receiver:            "astra156dh69y8j39eynue4jahrezg32rgl8eck5rhsl",
			Amount:              amount,
			GasLimit:            gasLimit,
			GasPrice:            gasPrice,
		}

		txBuilder, err := b.SignTxWithSignerAddress(request)
		if err != nil {
			return 0, err
		}

		sign, err := common.TxBuilderSignatureJsonEncoder(b.rpcClient.TxConfig, txBuilder)
		if err != nil {
			return 0, err
		}

		signByte, err := common.TxBuilderSignatureJsonDecoder(b.rpcClient.TxConfig, sign)
		if err != nil {
			return 0, err
		}

		signList = append(signList, signByte)
	}

	request := &TransferMultiSignRequest{
		MulSignAccPublicKey: masterPk,
		Receiver:            "astra156dh69y8j39eynue4jahrezg32rgl8eck5rhsl",
		Amount:              amount,
		GasLimit:            gasLimit,
		GasPrice:            gasPrice,
		Sigs:                signList,
	}

	txBuilder, err := b.TransferMultiSignRawData(request)
	if err != nil {
		return 0, err
	}

	txBytes, err := b.rpcClient.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return 0, err
	}

	txSvcClient := tx.NewServiceClient(b.rpcClient)
	simRes, err := txSvcClient.Simulate(context.Background(), &tx.SimulateRequest{
		TxBytes: txBytes,
	})

	if err != nil {
		return 0, err
	}

	return simRes.GasInfo.GasUsed, nil
}

func (b *Bank) ParserEthMsg(txs *Txs, msgEth *emvTypes.MsgEthereumTx) error {
	ethTx := msgEth.AsTransaction()

	var txDataType string
	switch ethTx.Type() {
	case ethTypes.LegacyTxType:
		txDataType = "legacy_tx_type"
	case ethTypes.AccessListTxType:
		txDataType = "access_list_tx_type"
	case ethTypes.DynamicFeeTxType:
		txDataType = "dynamic_fee_tx_type"
	default:
		return errors.New("type invalid")
	}

	txs.Type = msgEth.Type()
	txs.TxDataType = txDataType
	txs.EthTxHash = ethTx.Hash().String()

	from, err := msgEth.GetSender(ethTx.ChainId())
	if err != nil {
		return errors.Wrap(err, "GetSender")
	}

	sender, err := common.EthAddressToCosmosAddress(from.String())
	if err != nil {
		return errors.Wrap(err, "CosmosAddressToEthAddress")
	}

	txs.Sender = sender
	txs.EthSender = from.String()

	dataExternal := ethTx.Data()
	if dataExternal != nil {
		//todo: can not parser eth data
		txs.IsUnNativeCoin = true
	} else {
		receiver, err := common.EthAddressToCosmosAddress(ethTx.To().String())
		if err != nil {
			return errors.Wrap(err, "EthAddressToCosmosAddress")
		}

		txs.Receiver = receiver
		txs.EthReceiver = ethTx.To().String()
	}

	amount, err := common.ConvertToDecimal(ethTx.Value().String(), 18)
	if err != nil {
		return errors.Wrap(err, "CosmosAddressToEthAddress")
	}

	txs.AmountDecimal = fmt.Sprintf("%v", amount)
	txs.Amount = ethTx.Value().String()

	txs.TokenSymbol = ""

	return nil
}

func (b *Bank) ParserCosmosMsg(txs *Txs, msgSend *bankTypes.MsgSend) error {
	txs.TxDataType = "cosmos"
	txs.Type = msgSend.Type()
	ethSender, err := common.CosmosAddressToEthAddress(msgSend.FromAddress)
	if err != nil {
		return errors.Wrap(err, "CosmosAddressToEthAddress")
	}

	txs.Sender = msgSend.FromAddress
	txs.EthSender = ethSender

	receiver, err := common.CosmosAddressToEthAddress(msgSend.ToAddress)
	if err != nil {
		return errors.Wrap(err, "CosmosAddressToEthAddress")
	}

	txs.Receiver = msgSend.ToAddress
	txs.EthReceiver = receiver

	txs.Amount = msgSend.Amount[0].Amount.String()

	amount, err := common.ConvertToDecimal(msgSend.Amount[0].Amount.String(), 18)
	if err != nil {
		return errors.Wrap(err, "CosmosAddressToEthAddress")
	}

	txs.AmountDecimal = fmt.Sprintf("%v", amount)
	txs.TokenSymbol = msgSend.Amount[0].Denom

	return nil
}

func (b *Bank) TxDetail(txHash string) (*Txs, error) {
	rs, err := b.CheckTx(txHash)
	if err != nil {
		return nil, err
	}

	tx, err := b.rpcClient.TxConfig.TxDecoder()(rs.Tx.GetValue())
	if err != nil {
		return nil, err
	}

	txBytes, err := b.rpcClient.TxConfig.TxJSONEncoder()(tx)
	if err != nil {
		return nil, err
	}

	msg := tx.GetMsgs()[0]
	txs := &Txs{
		Code:        rs.Code,
		IsOk:        common.BlockedStatus(rs.Code),
		Time:        rs.Timestamp,
		BlockHeight: rs.Height,
		TxHash:      rs.TxHash,
		RawData:     string(txBytes),
	}

	msgEth, ok := msg.(*emvTypes.MsgEthereumTx)
	if ok {
		err := b.ParserEthMsg(txs, msgEth)
		if err != nil {
			return nil, err
		}
	}

	msgBankSend, ok := msg.(*bankTypes.MsgSend)
	if ok {
		err := b.ParserCosmosMsg(txs, msgBankSend)
		if err != nil {
			return nil, err
		}
	}

	return txs, nil
}
