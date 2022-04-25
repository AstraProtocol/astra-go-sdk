package common

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codecTypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptoCodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	signingTypes "github.com/cosmos/cosmos-sdk/types/tx/signing"

	"github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/pkg/errors"
)

func DecodePublicKey(pkJSON string) (cryptoTypes.PubKey, error) {
	registry := codecTypes.NewInterfaceRegistry()
	cryptoCodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	var pk cryptoTypes.PubKey
	err := cdc.UnmarshalInterfaceJSON([]byte(pkJSON), &pk)

	if err != nil {
		return nil, errors.Wrap(err, "UnmarshalInterfaceJSON`")
	}

	return pk, nil
}

func IsMulSign(pk cryptoTypes.PubKey) (bool, error) {
	lpk, ok := pk.(*multisig.LegacyAminoPubKey)
	if !ok {
		return false, nil
	}

	if lpk.Threshold > 1 {
		return true, nil
	}

	return false, nil
}

func TxJsonDecoder(txConfig client.TxConfig, txJSON string) ([]byte, error) {
	txJSONDecoder, err := txConfig.TxJSONDecoder()([]byte(txJSON))
	if err != nil {
		return nil, err
	}

	txBytes, err := txConfig.TxEncoder()(txJSONDecoder)
	if err != nil {
		panic(err)
	}

	return txBytes, nil
}

func TxJsonEncoder(txConfig client.TxConfig, tx signing.Tx) (string, error) {
	txJSONEncoder, err := txConfig.TxJSONEncoder()(tx)
	if err != nil {
		return "", err
	}

	return string(txJSONEncoder), nil
}

func MarshalSignatureJSON(txConfig client.TxConfig, tx signing.Tx) (string, error) {
	sigs, err := tx.GetSignaturesV2()
	if err != nil {
		return "", err
	}

	json, err := txConfig.MarshalSignatureJSON(sigs)

	return string(json), nil
}

func UnmarshalSignatureJSON(txConfig client.TxConfig, txJson string) ([]signingTypes.SignatureV2, error) {
	return txConfig.UnmarshalSignatureJSON([]byte(txJson))
}
