// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/omega"
)

func VerifySigScript(sign, hash []byte, chainParams *chaincfg.Params) (*AddressPubKeyHash, error) {
	if len(sign) < btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("Incorrect signature")
	}
	k, err := btcec.ParsePubKey(sign[:btcec.PubKeyBytesLenCompressed], btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Incorrect Miner signature. pubkey error")
	}

	pk, _ := NewAddressPubKeyPubKey(*k, chainParams)
	pk.pubKeyFormat = PKFCompressed
	s, err := btcec.ParseSignature(sign[btcec.PubKeyBytesLenCompressed:], btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("Incorrect Miner signature. Signature parse error")
	}

	if !s.Verify(hash, pk.PubKey()) {
		return nil, fmt.Errorf("Incorrect Miner signature. Verification doesn't match")
	}

	return pk.AddressPubKeyHash(), nil
}

func VerifySigScript2(sign, hash, kubkey []byte, chainParams *chaincfg.Params) omega.Err {
	k, err := NewAddressPubKey(kubkey, chainParams)

	if err != nil {
		return omega.ScriptError(omega.ErrInternal,"Incorrect Miner signature. pubkey error")
	}

	s, err := btcec.ParseSignature(sign, btcec.S256())
	if err != nil {
		return omega.ScriptError(omega.ErrInternal,"Incorrect signature. Signature parse error")
	}

	if !s.Verify(hash, k.PubKey()) {
		return omega.ScriptError(omega.ErrInternal,"Incorrect signature. Verification doesn't match")
	}

	return nil
}
