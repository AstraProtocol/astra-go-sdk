package scan

import (
	"context"
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/bank"
	"github.com/cosmos/cosmos-sdk/client"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	evmtypes "github.com/evmos/ethermint/x/evm/types"
	"github.com/pkg/errors"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	"github.com/tendermint/tendermint/types"
	"time"
)

type Scanner struct {
	rpcClient client.Context
	bank      *bank.Bank
}

func NewScanner(rpcClient client.Context, bank *bank.Bank) *Scanner {
	return &Scanner{rpcClient: rpcClient, bank: bank}
}

func (b *Scanner) ScanViaWebsocket() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	subscription := b.rpcClient.Client

	err := subscription.Start()
	if err != nil {
		panic(err)
	}
	defer subscription.Stop()

	queryStr := fmt.Sprintf("tm.event='NewBlock' AND block.height='1038312'")
	fmt.Println(queryStr)
	blockHeadersSub, err := subscription.Subscribe(
		ctx,
		"test-client",
		queryStr,
	)

	if err != nil {
		panic(err)
	}

	go func() {
		for e := range blockHeadersSub {
			eventDataHeader := e.Data.(types.EventDataNewBlock)
			height := eventDataHeader.Block.Height
			data := eventDataHeader.Block.Data

			fmt.Println(height)
			for _, rawData := range data.Txs {
				tx, err := b.rpcClient.TxConfig.TxDecoder()(rawData)
				if err != nil {
					panic(err)
				}

				_, err = b.rpcClient.TxConfig.TxJSONEncoder()(tx)
				if err != nil {
					panic(err)
				}

				fmt.Printf("%X\n", rawData.Hash())
			}
		}
	}()

	select {}
}

func (b *Scanner) ScanByBlockHeight(height int64) ([]*bank.Txs, error) {
	startTime := time.Now()

	lisTx := make([]*bank.Txs, 0)

	blockInfo, _, err := b.getBlock(&height)
	if err != nil {
		return nil, errors.Wrap(err, "getBlock")
	}

	blkHeight := blockInfo.Block.Height
	blockTime := blockInfo.Block.Time
	layout := "2006-01-02T15:04:05.000Z"

	fmt.Printf("scan block = %v total = %v\n", height, len(blockInfo.Block.Txs))
	for _, rawData := range blockInfo.Block.Txs {
		tx, err := b.rpcClient.TxConfig.TxDecoder()(rawData)
		if err != nil {
			return nil, errors.Wrap(err, "TxDecoder")
		}

		txBytes, err := b.rpcClient.TxConfig.TxJSONEncoder()(tx)
		if err != nil {
			return nil, errors.Wrap(err, "TxJSONEncoder")
		}

		/*txResult := blockResults.TxsResults[i]
		if !txResult.IsOK() {
			fmt.Printf("Tx = %X at block = %v is failed\n", rawData.Hash(), height)
			continue
		}*/

		ts := blockTime.Format(layout)
		txs := &bank.Txs{
			//Code:        txResult.Code,
			//IsOk:        txResult.IsOK(),
			Time:        ts,
			BlockHeight: blkHeight,
			TxHash:      fmt.Sprintf("%X", rawData.Hash()),
			RawData:     string(txBytes),
		}

		msg := tx.GetMsgs()[0]

		msgEth, ok := msg.(*evmtypes.MsgEthereumTx)
		if ok {
			err := b.bank.ParserEthMsg(txs, msgEth)
			if err != nil {
				return nil, errors.Wrap(err, "getEthMsg")
			}
		}

		msgBankSend, ok := msg.(*banktypes.MsgSend)
		if ok {
			err := b.bank.ParserCosmosMsg(txs, msgBankSend)
			if err != nil {
				return nil, errors.Wrap(err, "getBankSendMsg")
			}
		}

		lisTx = append(lisTx, txs)
	}

	fmt.Printf("end scan block = %v in = %v\n", height, time.Since(startTime).String())
	return lisTx, nil
}

func (b *Scanner) getBlockResults(height *int64) (*ctypes.ResultBlockResults, error) {
	node, err := b.rpcClient.GetNode()
	if err != nil {
		return nil, err
	}

	res, err := node.BlockResults(context.Background(), height)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (b *Scanner) getBlock(height *int64) (*ctypes.ResultBlock, *ctypes.ResultBlockResults, error) {
	// get the node
	node, err := b.rpcClient.GetNode()
	if err != nil {
		return nil, nil, err
	}

	res, err := node.Block(context.Background(), height)
	if err != nil {
		return nil, nil, err
	}

	//fmt.Println(res.Block.Hash().String())

	/*res1, err := node.BlockResults(context.Background(), height)
	if err != nil {
		return nil, nil, err
	}*/

	return res, nil, nil
}

func (b *Scanner) GetChainHeight() (int64, error) {
	node, err := b.rpcClient.GetNode()
	if err != nil {
		return -1, err
	}

	status, err := node.Status(context.Background())
	if err != nil {
		return -1, err
	}

	height := status.SyncInfo.LatestBlockHeight
	return height, nil
}
