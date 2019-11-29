// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"fmt"
	"encoding/binary"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript/txsparser"
	"github.com/btcsuite/omega/ovm"
)

const (
	// MaxDataCarrierSize is the maximum number of bytes allowed in pushed
	// data to be considered a nulldata transaction
	MaxDataCarrierSize = 80
)

// ScriptInfo houses information about a script pair that is determined by
// CalcScriptInfo.
type ScriptInfo struct {
	// PkScriptClass is the class of the public key script and is equivalent
	// to calling GetScriptClass on it.
	PkScriptClass txsparser.ScriptClass

	// NumInputs is the number of inputs provided by the public key script.
	NumInputs int

	// ExpectedInputs is the number of outputs required by the signature
	// script and any pay-to-script-hash scripts. The number will be -1 if
	// unknown.
	ExpectedInputs int

	// SigOps is the number of signature operations in the script pair.
	SigOps int
}

// CalcScriptInfo returns a structure providing data about the provided script
// pair.  It will error if the pair is in someway invalid such that they can not
// be analysed, i.e. if they do not parse or the pkScript is not a push-only
// script
func CalcScriptInfo(sigScript, pkScript []byte) (*ScriptInfo, error) {
	// Push only sigScript makes little sense.
	si := new(ScriptInfo)
	si.PkScriptClass = txsparser.TypeOfScript(pkScript)

	if si.PkScriptClass == txsparser.ContractHashTy {
		si.NumInputs = 0
		si.SigOps = 0
		si.ExpectedInputs = 0
		return si, nil
	}

	si.NumInputs = 1
	si.ExpectedInputs = 1

	if pkScript[21] < ovm.PAYFUNC_MIN || pkScript[21] > ovm.PAYFUNC_MAX {
		return nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
			"pkscript is not valid")
	}

	switch pkScript[21] {
	case ovm.OP_PAY2MULTIPKH, ovm.OP_PAY2MULTISCRIPTH:
		si.NumInputs = int(binary.LittleEndian.Uint32(pkScript[25:29]))
		si.NumInputs = int(binary.LittleEndian.Uint32(pkScript[29:33]))
	}

	pks := false

	switch pkScript[21] {
	case ovm.OP_PAY2PKH, ovm.OP_PAY2MULTIPKH:
		pks = true
	case ovm.OP_PAY2SCRIPTH, ovm.OP_PAY2MULTISCRIPTH:
		pks = false
	case ovm.OP_PAY2NONE, ovm.OP_PAY2ANY:
		si.SigOps = 0
		return si, nil
	default:
		return nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
			"pkscript is not valid")
	}

	p, _, err := ExtractSigHead(sigScript)

	if err != nil {
		return nil, err
	}

	si.SigOps = 0
	if p >= len(sigScript) {
		return si, nil
	}

	for p < len(sigScript) {
		if sigScript[p] >= byte(ovm.PUSH1) && sigScript[p] <= byte(ovm.PUSH32) {
			p++
			format := int(sigScript[p])
			if pks {
				if format == 0x2 {	// btcec.pubkeyCompressed
					p += 35
				} else if format == 0x4 {	// btcec.pubkeyUncompressed
					p += 68
				} else if format == 0x6 {	// btcec.pubkeyHybrid
					p += 68
				} else {
					return nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
						"sigscript is not valid")
				}
				format := int(sigScript[p])
				p += format + ((format + 31) >> 5)
			} else {
				p += format + 1
			}
			si.SigOps++
		} else {
			return nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
				"sigscript is not valid")
		}
	}

	return si, nil
}

func ExtractSigHead(sigScript []byte) (int, []byte, error) {
	p, sigstart, textadded := 0, false, false
	for p < len(sigScript) && !sigstart {
		if sigScript[p] >= byte(ovm.PUSH1) && sigScript[p] <= byte(ovm.PUSH32) {
			if textadded {
				sigstart = true
			} else {
				p += 1 + int(sigScript[p])
			}
		} else {
			switch sigScript[p] {
			case byte(ovm.ADDSIGNTEXT):
				p++
				textadded = true
				switch sigScript[p] {
				case 0, 1: // specific matching outpoint // specific matching input // specific script
					p++
				case 2, 3, 4: // specific matching outpoint // specific matching input // specific script
					p += 2 + int(sigScript[p + 1])
				default:
					return p, nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
						"sigscript is not valid")
				}
			}
		}
	}
	if !sigstart {
		return p, nil, nil
	}
	return p, sigScript[:p], nil
}
// payToPubKeyHashScript creates a new script to pay a transaction
// output to a 20-byte pubkey hash. It is expected that the input is a valid
// hash.
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddScript(pubKeyHash).AddScript([]byte{ovm.OP_PAY2PKH, 0, 0, 0}).
		Script(), nil
}

// payToScriptHashScript creates a new script to pay a transaction output to a
// script hash. It is expected that the input is a valid hash.
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddScript(scriptHash).AddScript([]byte{ovm.OP_PAY2SCRIPTH, 0, 0, 0}).
		Script(), nil
}

// PayToAddrScript creates a new script to pay a transaction output to a the
// specified address.
func PayToAddrScript(addr btcutil.Address) ([]byte, error) {
	const nilAddrErrStr = "unable to generate payment script for nil address"

	switch addr := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyHashScript(addr.ScriptNetAddress())

	case *btcutil.AddressScriptHash:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToScriptHashScript(addr.ScriptAddress())
	}

	str := fmt.Sprintf("unable to generate payment script for unsupported "+
		"address type %T", addr)
	return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress, str)
}

// NullDataScript creates a provably-prunable script containing OP_RETURN
// followed by the passed data.  An Error with the error code ErrTooMuchNullData
// will be returned if the length of the passed data exceeds MaxDataCarrierSize.
func NullDataScript(data []byte) ([]byte, error) {
	if len(data) > MaxDataCarrierSize {
		str := fmt.Sprintf("data size %d is larger than max "+
			"allowed size %d", len(data), MaxDataCarrierSize)
		return nil, txsparser.ScriptError(txsparser.ErrTooMuchNullData, str)
	}

	v := [21]byte{0x2}

	return NewScriptBuilder().AddScript(v[:]).AddScript([]byte{byte(ovm.RETURN), 0, 0, 0}).AddData(data).Script(), nil
}

// MultiSigScript returns a valid script for a multisignature redemption where
// nrequired of the keys in pubkeys are required to have signed the transaction
// for success.  An Error with the error code ErrTooManyRequiredSigs will be
// returned if nrequired is larger than the number of keys provided.
func MultiSigScript(pubkeys []*btcutil.AddressPubKeyHash, nrequired int) ([]byte, error) {
	if len(pubkeys) < nrequired {
		str := fmt.Sprintf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", nrequired, len(pubkeys))
		return nil, txsparser.ScriptError(txsparser.ErrTooManyRequiredSigs, str)
	}

	builder := NewScriptBuilder()
	builder.AddScript(pubkeys[0].ScriptNetAddress()).AddScript([]byte{byte(ovm.OP_PAY2PKH), 0, 0, 0}).
		AddInt(len(pubkeys)).AddInt(nrequired)

	for i, key := range pubkeys {
		if i != 0 {
			builder.AddData(key.ScriptAddress())
		}
	}

	return builder.Script(), nil
}

// ExtractPkScriptAddrs returns the type of script, addresses and required
// signatures associated with the passed PkScript.  Note that it only works for
// 'standard' transaction script types.  Any data such as public keys which are
// invalid are omitted from the results.
func ExtractPkScriptAddrs(pkScript []byte, chainParams *chaincfg.Params) (txsparser.ScriptClass, []btcutil.Address, int, error) {
	var addrs []btcutil.Address
	var requiredSigs int

	scriptClass := txsparser.TypeOfScript(pkScript)
	switch scriptClass {
	case txsparser.PubKeyHashTy:
		// A pay-to-pubkey-hash script is of the form:
		//  OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
		// Therefore the pubkey hash is the 3rd item on the stack.
		// Skip the pubkey hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressPubKeyHash(pkScript[1:21], chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.ContractHashTy:
		// A contract-hash script is of the form:
		//  OP_CONTRACTCALL <hash>
		requiredSigs = 0
		addr, err := btcutil.NewAddressContract(pkScript[1:21], chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.ScriptHashTy:
		// A pay-to-script-hash script is of the form:
		//  OP_HASH160 <scripthash> OP_EQUAL
		// Therefore the script hash is the 2nd item on the stack.
		// Skip the script hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressScriptHashFromHash(pkScript[1:21],
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.MultiScriptTy:
		// A multi-signature script is of the form:
		//  <numsigs> <pubkey> <pubkey> <pubkey>... <numpubkeys> OP_CHECKMULTISIG
		// Therefore the number of required signatures is the 1st item
		// on the stack and the number of public keys is the 2nd to last
		// item on the stack.
		requiredSigs = int(binary.LittleEndian.Uint32(pkScript[29:33]))
		numPubKeys := int(binary.LittleEndian.Uint32(pkScript[25:29]))

		// Extract the public keys while skipping any that are invalid.
		addrs = make([]btcutil.Address, 1, numPubKeys)
		addrs[0], _ = btcutil.NewAddressScriptHashFromHash(pkScript[1:21], chainParams)

		for i := 1; i < numPubKeys; i++ {
			addr, err := btcutil.NewAddressScriptHashFromHash(pkScript[33 + (i-1) * 20:33 + i * 20], chainParams)
			if err == nil {
				addrs = append(addrs, addr)
			}
		}

	case txsparser.MultiSigTy:
		// A multi-signature script is of the form:
		//  <numsigs> <pubkey> <pubkey> <pubkey>... <numpubkeys> OP_CHECKMULTISIG
		// Therefore the number of required signatures is the 1st item
		// on the stack and the number of public keys is the 2nd to last
		// item on the stack.
		requiredSigs = int(binary.LittleEndian.Uint32(pkScript[29:33]))
		numPubKeys := int(binary.LittleEndian.Uint32(pkScript[25:29]))

		// Extract the public keys while skipping any that are invalid.
		addrs = make([]btcutil.Address, 1, numPubKeys)

		addrs[0], _ = btcutil.NewAddressPubKey(pkScript[1:21], chainParams)

		for i := 1; i < numPubKeys; i++ {
			addr, err := btcutil.NewAddressPubKey(pkScript[33 + (i-1) * 20:33 + i * 20], chainParams)
			if err == nil {
				addrs = append(addrs, addr)
			}
		}

	case txsparser.NullDataTy:
		// Null data transactions have no addresses or required
		// signatures.

	case txsparser.NonStandardTy:
		// Don't attempt to extract addresses or required signatures for
		// nonstandard transactions.
	}

	return scriptClass, addrs, requiredSigs, nil
}
