package eth

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
)

type Client struct {
	eth *ethclient.Client
}

func NewClient(eth *ethclient.Client) *Client {
	return &Client{eth}
}

func (c *Client) GetClient() *ethclient.Client {
	return c.eth
}

func (c *Client) GenerateAddress() (privKey, pubKey, address string, err error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		err = errors.Wrap(err, "crypto.GenerateKey")
		return
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privKey = hexutil.Encode(privateKeyBytes)[2:]

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		err = errors.New("failed to cast public key to ECDSA")
		return
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	pubKey = hexutil.Encode(publicKeyBytes)[4:]

	address = crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return
}

func (c *Client) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	account := common.HexToAddress(address)
	balance, err := c.eth.BalanceAt(ctx, account, nil)
	if err != nil {
		return nil, errors.Wrap(err, "c.eth.BalanceAt")
	}
	return balance, nil
}

func (c *Client) GetTransaction(ctx context.Context, txAddress string) (uint64, error) {
	hash := common.HexToHash(txAddress)
	receipt, err := c.eth.TransactionReceipt(ctx, hash)
	if err != nil {
		return 0, errors.Wrap(err, "c.eth.GetTransaction")
	}
	return receipt.Status, nil
}

func (c *Client) PendingNonceAt(ctx context.Context, address common.Address) (uint64, error) {
	return c.eth.PendingNonceAt(ctx, address)
}

func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return c.eth.SuggestGasPrice(ctx)
}

func (c *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	return c.eth.NetworkID(ctx)
}

/*func (c *Client) GetEstimatedGasPrice(preference string) (*big.Int, error) {
	minGasPrice := big.NewInt(int64(1e9)) // 1 GWei
	gasPrice, err := core.GetGasPriceFromUpvest(preference)

	if err != nil {
		gasPrice, err = c.SuggestGasPrice(context.Background())
		if err != nil {
			gasPrice = big.NewInt(0)
		}
	}

	if gasPrice.Cmp(minGasPrice) < 0 {
		gasPrice = minGasPrice
	}

	return gasPrice, nil
}*/

func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return c.eth.SendTransaction(ctx, tx)
}

func (c *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return c.eth.TransactionReceipt(ctx, txHash)
}

func (c *Client) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return c.eth.BlockByHash(ctx, hash)
}

func (c *Client) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	return c.eth.TransactionByHash(ctx, hash)
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
func (c *Client) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return c.eth.BlockByNumber(ctx, number)
}

// TransactionsByBlockNumber returns all transactions from the current canonical chain. If number is nil, the
// latest known block is returned.
func (c *Client) TransactionsByBlockNumber(ctx context.Context, number *big.Int) (types.Transactions, error) {
	block, err := c.eth.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	return block.Transactions(), nil
}

func (c *Client) GetNonceByPrivateKey(senderPrivKey string) (uint64, error) {
	privateKey, err := crypto.HexToECDSA(senderPrivKey)
	if err != nil {
		return 0, errors.Wrap(err, "crypto.HexToECDSA")
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := c.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return 0, errors.Wrap(err, "s.ethClient.PendingNonceAt")
	}

	return nonce, nil
}

func (c *Client) GetNonce(txs []string, ctx context.Context) (*big.Int, error) {
	if len(txs) == 0 {
		return nil, nil // No tx => not retry => nonce = nil to auto estimate
	}

	for _, tx := range txs {
		t, _, err := c.TransactionByHash(ctx, common.HexToHash(tx))
		if err != nil {
			continue
		}
		return big.NewInt(int64(t.Nonce())), nil
	}

	return nil, fmt.Errorf("failed getting nonce %v", txs)
}

func (c *Client) GetNonceByTx(tx string, ctx context.Context) (*big.Int, error) {
	if len(tx) == 0 {
		return nil, nil // No tx => not retry => nonce = nil to auto estimate
	}

	t, _, err := c.TransactionByHash(ctx, common.HexToHash(tx))
	if err != nil {
		return nil, err
	}

	return big.NewInt(int64(t.Nonce())), nil
}

func (c *Client) GetMaxGasPrice(txs []string) (*big.Int, error) {
	if len(txs) == 0 {
		return big.NewInt(0), nil
	}

	maxGasPrice := big.NewInt(0)
	for _, tx := range txs {
		t, _, err := c.TransactionByHash(context.Background(), common.HexToHash(tx))
		if err != nil {
			continue
		}
		p := t.GasPrice()
		if p.Cmp(maxGasPrice) > 0 {
			maxGasPrice = p
		}
	}
	return maxGasPrice, nil
}

func (c *Client) ValidateAddress(address string) bool {
	return common.IsHexAddress(address)
}

// transfer
func (c *Client) Transfer(senderPrivKey, receiverAddress string, amount *big.Int) (*types.Transaction, error) {
	privateKey, err := crypto.HexToECDSA(senderPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "crypto.HexToECDSA")
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := c.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, errors.Wrap(err, "s.ethClient.PendingNonceAt")
	}

	gasLimit := uint64(21000)
	gasPrice, err := c.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "s.ethClient.SuggestGasPrice")
	}

	fee := new(big.Int)
	fee.Mul(big.NewInt(int64(gasLimit)), gasPrice)

	toAddress := common.HexToAddress(receiverAddress)
	tx := types.NewTx(
		&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gasLimit,
			To:       &toAddress,
			Value:    amount,
			Data:     nil,
		})

	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "c.NetworkID")
	}

	log.Println("fee:", fee)
	log.Println("amount:", amount)
	log.Println("nonce:", nonce)
	log.Println("chainID:", chainID)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "types.SignTx")
	}

	return signedTx, nil
}

func (c *Client) TransferWithNoneNumber(
	senderPrivKey,
	receiverAddress string,
	amount *big.Int,
	gasPrice *big.Int,
	nonce uint64) (*types.Transaction, error) {
	privateKey, err := crypto.HexToECDSA(senderPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "crypto.HexToECDSA")
	}

	if gasPrice.Uint64() <= 0 {
		return nil, errors.Wrap(err, "GasPrice is empty")
	}

	gasLimit := uint64(21000)

	fee := new(big.Int)
	fee.Mul(big.NewInt(int64(gasLimit)), gasPrice)

	value := new(big.Int)
	value = amount

	toAddress := common.HexToAddress(receiverAddress)

	tx := types.NewTx(
		&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gasLimit,
			To:       &toAddress,
			Value:    value,
			Data:     nil,
		})

	chainID, err := c.NetworkID(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "c.NetworkID")
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "types.SignTx")
	}

	/*	err = c.SendTransaction(context.Background(), signedTx)
		if err != nil {
			return "", errors.Wrap(err, "c.SendTransaction")
		}*/
	//return signedTx.Hash().Hex(), nil
	return signedTx, nil
}

func (c *Client) CheckTx(txHash string) (int, error) {
	context, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	receipt, err := c.GetClient().TransactionReceipt(context, common.HexToHash(txHash))

	if err != nil {
		return -1, errors.Wrap(err, "CheckTx")
	}

	return int(receipt.Status), nil
}
