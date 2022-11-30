package account

import (
	"encoding/hex"
	"github.com/cosmos/cosmos-sdk/codec"
	codecTypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"
	"github.com/evmos/ethermint/crypto/ethsecp256k1"
	ethermintHd "github.com/evmos/ethermint/crypto/hd"
	ethermintTypes "github.com/evmos/ethermint/types"
	"github.com/pkg/errors"
)

type Account struct {
	coinType uint32
}

func NewAccount(coinType uint32) *Account {
	return &Account{coinType: coinType}
}

//Create new an Account

func (a *Account) CreateAccount() (*PrivateKeySerialized, error) {
	mnemonicEntropySize := 256
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return nil, errors.Wrap(err, "NewEntropy")
	}

	//bip39 mnemonic
	mnemonic, err := bip39.NewMnemonic(entropySeed)
	if err != nil {
		return nil, errors.Wrap(err, "NewMnemonic")
	}

	privKey, err := a.ImportAccount(mnemonic)
	if err != nil {
		return nil, errors.Wrap(err, "importAccount")
	}

	return privKey, nil
}

func (a *Account) CreateMulSignAccount(totalSign, multisigThreshold int) ([]*PrivateKeySerialized, string, string, error) {
	var listPrivate []*PrivateKeySerialized
	pks := make([]cryptoTypes.PubKey, totalSign)
	for i := 0; i < totalSign; i++ {
		k, err := a.CreateAccount()
		if err != nil {
			continue
		}

		listPrivate = append(listPrivate, k)
		pks[i] = k.PublicKey()
	}

	pk := multisig.NewLegacyAminoPubKey(multisigThreshold, pks)

	addr := types.AccAddress(pk.Address())

	apk, err := codecTypes.NewAnyWithValue(pk)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "NewAnyWithValue")
	}
	pkMarshal, err := codec.ProtoMarshalJSON(apk, nil)

	return listPrivate, addr.String(), string(pkMarshal), nil
}

//Import an Account

func (a *Account) ImportAccount(mnemonic string) (*PrivateKeySerialized, error) {
	derivedPriv, err := ethermintHd.EthSecp256k1.Derive()(
		mnemonic,
		keyring.DefaultBIP39Passphrase,
		ethermintTypes.BIP44HDPath)

	if err != nil {
		return nil, errors.Wrap(err, "Derive")
	}

	privateKey := ethermintHd.EthSecp256k1.Generate()(derivedPriv)
	return NewPrivateKeySerialized(mnemonic, privateKey), nil
}

func (a *Account) ImportPrivateKey(privateKeyStr string) (*PrivateKeySerialized, error) {
	priv, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}

	privateKey := &ethsecp256k1.PrivKey{
		Key: priv,
	}

	return NewPrivateKeySerialized("", privateKey), nil
}

func (a *Account) ImportHdPath(mnemonic, hdPath string) (*PrivateKeySerialized, error) {
	bz, err := ethermintHd.EthSecp256k1.Derive()(mnemonic, keyring.DefaultBIP39Passphrase, hdPath)
	if err != nil {
		return nil, errors.Wrap(err, "Derive")
	}

	privateKey := ethermintHd.EthSecp256k1.Generate()(bz)

	return NewPrivateKeySerialized("", privateKey), nil

}
