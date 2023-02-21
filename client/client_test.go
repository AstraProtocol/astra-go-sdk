package client

import (
	"encoding/json"
	"fmt"
	"github.com/AstraProtocol/astra-go-sdk/bank"
	"github.com/AstraProtocol/astra-go-sdk/common"
	"github.com/AstraProtocol/astra-go-sdk/config"
	"github.com/cosmos/cosmos-sdk/types"
	signingTypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"log"
	"math"
	"math/big"
	"os"
	"strings"
	"testing"
)

type AstraSdkTestSuite struct {
	suite.Suite
	Client *Client
}

func (suite *AstraSdkTestSuite) SetupTest() {
	err := godotenv.Load("./../dev.env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	cfg := &config.Config{
		ChainId:       os.Getenv("CHAIN_ID"),
		Endpoint:      os.Getenv("END_POINT"),
		PrefixAddress: "astra",
		TokenSymbol:   "aastra",
	}

	client := NewClient(cfg)
	suite.Client = client
}

func TestAstraSdkTestSuite(t *testing.T) {
	suite.Run(t, new(AstraSdkTestSuite))
}

func (suite *AstraSdkTestSuite) TestInitBank() {
	bankClient := suite.Client.NewBankClient()
	balance, err := bankClient.Balance("astra1p6sscujfpygmrrxqlwqeqqw6r5lxk2x9gz9glh")
	if err != nil {
		panic(err)
	}

	fmt.Println(balance.String())
}

func (suite *AstraSdkTestSuite) TestGenAccount() {
	accClient := suite.Client.NewAccountClient()
	acc, err := accClient.CreateAccount()
	if err != nil {
		panic(err)
	}

	data, _ := acc.String()

	fmt.Println(data)
}

func (suite *AstraSdkTestSuite) TestGenMulSignAccount() {
	accClient := suite.Client.NewAccountClient()
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
}

func (suite *AstraSdkTestSuite) TestTransfer() {
	bankClient := suite.Client.NewBankClient()

	amount := big.NewInt(0).Mul(big.NewInt(4), big.NewInt(0).SetUint64(uint64(math.Pow10(18))))
	fmt.Println("amount", amount.String())

	request := &bank.TransferRequest{
		PrivateKey: "valve season sauce knife burden benefit zone field ask carpet fury vital action donate trade street ability artwork ball uniform garbage sugar warm differ",
		Receiver:   "astra1p6sscujfpygmrrxqlwqeqqw6r5lxk2x9gz9glh",
		Amount:     amount,
		GasLimit:   200000,
		GasPrice:   "10000000000000aastra",
	}

	txBuilder, err := bankClient.TransferRawData(request)
	if err != nil {
		panic(err)
	}

	/*txBuilder, err := bankClient.TransferRawDataAndEstimateGas(request)
	if err != nil {
		panic(err)
	}*/

	txJson, err := common.TxBuilderJsonEncoder(suite.Client.rpcClient.TxConfig, txBuilder)
	if err != nil {
		panic(err)
	}

	fmt.Println("rawData", txJson)

	txByte, err := common.TxBuilderJsonDecoder(suite.Client.rpcClient.TxConfig, txJson)
	if err != nil {
		panic(err)
	}

	txHash := common.TxHash(txByte)
	fmt.Println("txHash", txHash)

	fmt.Println(ethCommon.BytesToHash(txByte).String())

	res, err := suite.Client.rpcClient.BroadcastTxSync(txByte)
	if err != nil {
		panic(err)
	}

	fmt.Println(res)
}

func (suite *AstraSdkTestSuite) TestTransferWithPrivateKey() {
	bankClient := suite.Client.NewBankClient()
	amount := big.NewInt(0).Mul(big.NewInt(10), big.NewInt(0).SetUint64(uint64(math.Pow10(18))))
	fmt.Println("amount", amount.String())

	request := &bank.TransferRequest{
		PrivateKey: "69e2ece17baa00b1112217f530661a8b9d0ecabc8fe122fc1f403761c86a1ccc",
		Receiver:   "astra1p6sscujfpygmrrxqlwqeqqw6r5lxk2x9gz9glh",
		Amount:     amount,
		GasLimit:   200000,
		GasPrice:   "10000000000000aastra",
	}

	txBuilder, err := bankClient.TransferRawDataWithPrivateKey(request)
	if err != nil {
		panic(err)
	}
	/*
		txBuilder, err := bankClient.TransferRawDataWithPrivateKeyAndEstimateGas(request)
		if err != nil {
			panic(err)
		}*/

	txJson, err := common.TxBuilderJsonEncoder(suite.Client.rpcClient.TxConfig, txBuilder)
	if err != nil {
		panic(err)
	}

	fmt.Println("rawData", string(txJson))

	txByte, err := common.TxBuilderJsonDecoder(suite.Client.rpcClient.TxConfig, txJson)
	if err != nil {
		panic(err)
	}

	txHash := common.TxHash(txByte)
	fmt.Println("txHash", txHash)

	fmt.Println(ethCommon.BytesToHash(txByte).String())

	res, err := suite.Client.rpcClient.BroadcastTxSync(txByte)
	if err != nil {
		panic(err)
	}

	fmt.Println(res)
}

func (suite *AstraSdkTestSuite) TestTransferMultiSign() {
	//main address
	/*
		addr astra1ha0vgh05zzlwdeejxq9aq7gqr6jzs7stdhlfra
		pucKey {"@type":"/cosmos.crypto.multisig.LegacyAminoPubKey","threshold":2,"public_keys":[{"@type":"/ethermint.crypto.v1.ethsecp256k1.PubKey","key":"A0ATAOfWQM6XXCA5po9DBsKVGmWudnIN55arHhDYhR89"},{"@type":"/ethermint.crypto.v1.ethsecp256k1.PubKey","key":"A0ks8ww7AVKYQRsKgZSQi9wTfoQzKNt30gLOMpOJNSPn"},{"@type":"/ethermint.crypto.v1.ethsecp256k1.PubKey","key":"A9Q4nSS73SG+Tclghh1JEtfng5vd41dgmG7HJrYW4/Ml"}]}
	*/

	//child address
	/*
		index 0
		{
		 "address": "astra1dmdsy082730stdletm7z6zulfxuez4lsx3tztx",
		 "hexAddress": "0x6Edb023ceAF45F05b7f95efC2d0B9f49B99157F0",
		 "mnemonic": "ignore risk morning strike school street radar silk recipe health december system inflict gold foster item end twenty magic shine oppose island loop impact",
		 "privateKey": "7f1d3df4044f09b1edfab34c7e3fee92396ea23861e96a8ac7429efcf158d794",
		 "publicKey": "{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A0ATAOfWQM6XXCA5po9DBsKVGmWudnIN55arHhDYhR89\"}",
		 "type": "eth_secp256k1",
		 "validatorKey": "astravaloper1dmdsy082730stdletm7z6zulfxuez4lsrg2nsg"
		} <nil>
		index 1
		{
		 "address": "astra1fd39nlc4hsl7ma9knpjwlhcrnunz66dnvf5agx",
		 "hexAddress": "0x4b6259ff15Bc3FEdf4B69864EfdF039F262d69B3",
		 "mnemonic": "seven mean snap illness couch excite item topic tobacco erosion tourist blue van possible wolf gadget combine excess brush goddess glory subway few mind",
		 "privateKey": "8dca20a27b0bfdcf1dacc9b2f71d4b7e7d269a4b87949707c12ef2ba328fd0e9",
		 "publicKey": "{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A0ks8ww7AVKYQRsKgZSQi9wTfoQzKNt30gLOMpOJNSPn\"}",
		 "type": "eth_secp256k1",
		 "validatorKey": "astravaloper1fd39nlc4hsl7ma9knpjwlhcrnunz66dnfs4vng"
		} <nil>
		index 2
		{
		 "address": "astra1gc0v03kjrg9uv7duvzqsndv3nhkhehvkwuhkdr",
		 "hexAddress": "0x461EC7C6D21a0BC679bC608109b5919DEd7Cdd96",
		 "mnemonic": "swap exhaust letter left light trust diet piano pride rifle trust orbit clip suggest achieve unaware please guess lawsuit doctor use bargain jealous weekend",
		 "privateKey": "e3f46776e933129611b3cb6418176dcd2a9badd8188fb4804d5b822548200bac",
		 "publicKey": "{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A9Q4nSS73SG+Tclghh1JEtfng5vd41dgmG7HJrYW4/Ml\"}",
		 "type": "eth_secp256k1",
		 "validatorKey": "astravaloper1gc0v03kjrg9uv7duvzqsndv3nhkhehvkt9k8kd"
		}
	*/

	masterPk, err := common.DecodePublicKey(
		suite.Client.rpcClient,
		"{\"@type\":\"/cosmos.crypto.multisig.LegacyAminoPubKey\",\"threshold\":2,\"public_keys\":[{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A0ATAOfWQM6XXCA5po9DBsKVGmWudnIN55arHhDYhR89\"},{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A0ks8ww7AVKYQRsKgZSQi9wTfoQzKNt30gLOMpOJNSPn\"},{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A9Q4nSS73SG+Tclghh1JEtfng5vd41dgmG7HJrYW4/Ml\"}]}",
	)

	if err != nil {
		panic(err)
	}

	from := types.AccAddress(masterPk.Address())
	fmt.Println("from", from.String())

	bankClient := suite.Client.NewBankClient()

	listPrivate := []string{
		"ignore risk morning strike school street radar silk recipe health december system inflict gold foster item end twenty magic shine oppose island loop impact",
		"seven mean snap illness couch excite item topic tobacco erosion tourist blue van possible wolf gadget combine excess brush goddess glory subway few mind",
		//"swap exhaust letter left light trust diet piano pride rifle trust orbit clip suggest achieve unaware please guess lawsuit doctor use bargain jealous weekend",
	}

	listPrivate = listPrivate[:2]

	amount := big.NewInt(0).Mul(big.NewInt(10), big.NewInt(0).SetUint64(uint64(math.Pow10(18))))
	fmt.Println("amount", amount.String())

	/*	gasPrice, err := bankClient.BaseFee()
		if err != nil {
			panic(err)
		}*/

	/*gasLimit, err := bankClient.TransferMultiSignEstimateGas(listPrivate, masterPk, amount, gasPrice, 200000)
	if err != nil {
		panic(err)
	}*/

	gasPrice := "10000000000000aastra"
	gasLimit := uint64(200000)

	fmt.Println("gas", gasLimit)
	fmt.Println("gasPrice", gasPrice)

	fmt.Println("start signer")
	signList := make([][]signingTypes.SignatureV2, 0)
	for i, s := range listPrivate {
		fmt.Println("index", i)

		request := &bank.SignTxWithSignerAddressRequest{
			SignerPrivateKey:    s,
			MulSignAccPublicKey: masterPk,
			Receiver:            "astra1p6sscujfpygmrrxqlwqeqqw6r5lxk2x9gz9glh",
			Amount:              amount,
			GasLimit:            gasLimit,
			GasPrice:            gasPrice,
		}

		txBuilder, err := bankClient.SignTxWithSignerAddress(request)
		if err != nil {
			panic(err)
		}

		sign, err := common.TxBuilderSignatureJsonEncoder(suite.Client.rpcClient.TxConfig, txBuilder)
		if err != nil {
			panic(err)
		}

		fmt.Println("sign-data", string(sign))

		signByte, err := common.TxBuilderSignatureJsonDecoder(suite.Client.rpcClient.TxConfig, sign)
		if err != nil {
			panic(err)
		}

		signList = append(signList, signByte)
	}

	fmt.Println("start transfer")
	//200
	request := &bank.TransferMultiSignRequest{
		MulSignAccPublicKey: masterPk,
		Receiver:            "astra1p6sscujfpygmrrxqlwqeqqw6r5lxk2x9gz9glh",
		Amount:              amount,
		GasLimit:            gasLimit,
		GasPrice:            gasPrice,
		Sigs:                signList,
	}

	txBuilder, err := bankClient.TransferMultiSignRawData(request)
	if err != nil {
		panic(err)
	}

	txJson, err := common.TxBuilderJsonEncoder(suite.Client.rpcClient.TxConfig, txBuilder)
	if err != nil {
		panic(err)
	}

	fmt.Println("rawData", string(txJson))

	txByte, err := common.TxBuilderJsonDecoder(suite.Client.rpcClient.TxConfig, txJson)
	if err != nil {
		panic(err)
	}

	txHash := common.TxHash(txByte)
	fmt.Println("txHash", txHash)

	_, err = suite.Client.rpcClient.BroadcastTxSync(txByte)
	if err != nil {
		panic(err)
	}

}

func (suite *AstraSdkTestSuite) TestAddressValid() {
	addressCheck := "astra1hann2zj3sx3ympd40ptxdmpd4nd4eypm45zhhr"

	receiver, err := types.AccAddressFromBech32(addressCheck)
	if err != nil {
		panic(err)
	}

	fmt.Println(receiver.String())
	assert.Equal(suite.T(), addressCheck, receiver.String(), "they should be equal")

	rs, _ := common.IsAddressValid(addressCheck)
	assert.Equal(suite.T(), rs, true)
}

func (suite *AstraSdkTestSuite) TestConvertHexToCosmosAddress() {
	eth := "0x9cc92bd19df168539ba7c73b450db998b0e79761"
	cosmos := "astra1nnyjh5va79598xa8cua52rdenzcw09mpwfekts"

	rs, _ := common.EthAddressToCosmosAddress(eth)
	fmt.Println(rs)
	assert.Equal(suite.T(), cosmos, rs)

	rs1, _ := common.CosmosAddressToEthAddress(cosmos)
	fmt.Println(rs1)
	assert.Equal(suite.T(), strings.ToLower(eth), strings.ToLower(rs1))
}

func (suite *AstraSdkTestSuite) TestCheckTx() {
	bankClient := suite.Client.NewBankClient()
	//rs, err := bankClient.CheckTx("646F944DCDB201F674C109E6EF9A594ADBCC33B8F0FA054D7B3F4ABE4CCA2AEB")
	rs, err := bankClient.CheckTx("F977DFB57F7F5B45508989DFB6C56AADDDB7F70EDD03636FDB89CF7A802D5B40")
	if err != nil {
		panic(err)
	}

	fmt.Println(rs.Code)
	if rs != nil && common.BlockedStatus(rs.Code) {
		fmt.Println("blocked")
	}
}

func (suite *AstraSdkTestSuite) TestImportAccountViaHdPath() {
	accClient := suite.Client.NewAccountClient()

	_, err := common.VerifyHdPath("m/44'/60'/0'/0/0")
	if err != nil {
		panic(err)
	}

	nmemonic := "secret immense amount trial polar security mother scare useful hen squeeze confirm right size best trash team clock matter grow copy quiz capital ill"

	for i := 100083357; i <= (100083357 + 20); i++ {
		s := fmt.Sprintf("m/44'/60'/%v'/1/0", i)
		wallet, err := accClient.ImportHdPath(
			nmemonic,
			s,
		)

		if err != nil {
			panic(err)
		}

		fmt.Println("index ", i, s)
		fmt.Println(wallet.String())
	}
}

func (suite *AstraSdkTestSuite) TestImportByNmemonic() {
	accClient := suite.Client.NewAccountClient()
	nmemonic := "secret immense amount trial polar security mother scare useful hen squeeze confirm right size best trash team clock matter grow copy quiz capital ill"

	key, err := accClient.ImportAccount(nmemonic)
	if err != nil {
		panic(err)
	}

	fmt.Println(key.String())
}

func (suite *AstraSdkTestSuite) TestImportByPrivatekey() {
	accClient := suite.Client.NewAccountClient()
	key, err := accClient.ImportPrivateKey("b8f7f2e5bab9c0b08df50cb5aa93ca8d1f5fe4aa11677ebf05232930d28349a9")
	if err != nil {
		panic(err)
	}

	fmt.Println(key.String())
}

func (suite *AstraSdkTestSuite) TestScanner() {
	bankClient := suite.Client.NewBankClient()
	c := suite.Client.NewScanner(bankClient)
	//listTx, err := c.ScanByBlockHeight(2040457) //cosmos
	//listTx, err := c.ScanByBlockHeight(1871260) //erc20
	listTx, err := c.ScanByBlockHeight(980684) //erc20
	if err != nil {
		panic(err)
	}

	rs, _ := json.MarshalIndent(listTx, " ", " ")
	fmt.Println(string(rs))

	height, err := c.GetChainHeight() //erc20

	if err != nil {
		panic(err)
	}

	fmt.Println(height)
}

func (suite *AstraSdkTestSuite) TestGetTxDetail() {
	bankClient := suite.Client.NewBankClient()
	rs, err := bankClient.TxDetail("6189C4A43589AE7EE96D69BF1114B3BA83E427E8149CD7758FF0D8BCF8F05E49")

	if err != nil {
		panic(err)
	}

	rsMarshal, _ := json.MarshalIndent(rs, " ", " ")

	fmt.Println(string(rsMarshal))

}

func (suite *AstraSdkTestSuite) TestBaseFee() {
	bankClient := suite.Client.NewBankClient()
	rs, err := bankClient.BaseFee()

	if err != nil {
		panic(err)
	}

	fmt.Println(rs)
}

func (suite *AstraSdkTestSuite) TestGetAccountRetriever() {
	bankClient := suite.Client.NewBankClient()
	accNum, accSeq, err := bankClient.AccountRetriever("0x661276b8c832da06c709dbc2b0c063e2f1d25ef9")
	if err != nil {
		panic(err)
	}

	fmt.Println(accNum)
	fmt.Println(accSeq)
}

func (suite *AstraSdkTestSuite) TestSequenceNumberFromPk() {
	mulSignAccPubKey := "{\"@type\":\"/cosmos.crypto.multisig.LegacyAminoPubKey\",\"threshold\":2,\"public_keys\":[{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A0UjEVXxXA7JY2oou5HPH7FuPSyJ2hAfDMc4XThXiopM\"},{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"A6DFr74kQmk/k88fCTPCxmf9kyFJMhFUF21IPFY7XoV2\"},{\"@type\":\"/ethermint.crypto.v1.ethsecp256k1.PubKey\",\"key\":\"AgPQELGzKmlAaSb01OKbmuL1f17MHJshkh9s9xAWxMa3\"}]}"
	walletMultiPub, err := common.DecodePublicKey(suite.Client.RpcClient(), mulSignAccPubKey)
	if err != nil {
		panic(err)
	}

	masterHexAddr := ethCommon.BytesToAddress(walletMultiPub.Address().Bytes())
	fmt.Println(masterHexAddr)

	bankClient := suite.Client.NewBankClient()
	accNum, accSeq, err := bankClient.AccountRetriever(masterHexAddr.String())
	if err != nil {
		panic(err)
	}

	fmt.Println(accNum)
	fmt.Println(accSeq)
}

func (suite *AstraSdkTestSuite) TestConvertToDecimal() {
	amount, err := common.ConvertToDecimal("740000000000", 18)
	fmt.Println(err)
	fmt.Println(amount)
}
