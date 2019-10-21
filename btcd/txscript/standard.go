// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript/txsparser"
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
func CalcScriptInfo(sigScript, pkScript []byte, witness wire.TxWitness,
	bip16, segwit bool) (*ScriptInfo, error) {

	sigPops, err := txsparser.ParseScript(sigScript)
	if err != nil {
		return nil, err
	}

	pkPops, err := txsparser.ParseScript(pkScript)
	if err != nil {
		return nil, err
	}

	// Push only sigScript makes little sense.
	si := new(ScriptInfo)
	si.PkScriptClass = txsparser.TypeOfScript(pkPops)

	// Can't have a signature script that doesn't just push data.
	if !isPushOnly(parsedOpcode2scriptInfo(sigPops)) {
		return nil, txsparser.ScriptError(txsparser.ErrNotPushOnly,
			"signature script is not push only")
	}

	si.ExpectedInputs = txsparser.ExpectedInputs(pkPops, si.PkScriptClass)

	switch {
	// Count sigops taking into account pay-to-script-hash.
	case si.PkScriptClass == txsparser.ScriptHashTy && bip16 && !segwit:
		// The pay-to-hash-script is the final data push of the
		// signature script.
		script := sigPops[len(sigPops)-1].Data
		shPops, err := txsparser.ParseScript(script)
		if err != nil {
			return nil, err
		}

		shInputs := txsparser.ExpectedInputs(shPops, txsparser.TypeOfScript(shPops))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}
		si.SigOps = getSigOpCount(shPops, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		si.NumInputs = len(sigPops)

	// If segwit is active, and this is a regular p2wkh output, then we'll
	// treat the script as a p2pkh output in essence.
	case si.PkScriptClass == txsparser.WitnessV0PubKeyHashTy && segwit:

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	// We'll attempt to detect the nested p2sh case so we can accurately
	// count the signature operations involved.
	case si.PkScriptClass == txsparser.ScriptHashTy &&
		IsWitnessProgram(sigScript[1:]) && bip16 && segwit:

		// Extract the pushed witness program from the sigScript so we
		// can determine the number of expected inputs.
		pkPops, _ := txsparser.ParseScript(sigScript[1:])
		shInputs := txsparser.ExpectedInputs(pkPops, txsparser.TypeOfScript(pkPops))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)

		si.NumInputs = len(witness)
		si.NumInputs += len(sigPops)

	// If segwit is active, and this is a p2wsh output, then we'll need to
	// examine the witness script to generate accurate script info.
	case si.PkScriptClass == txsparser.WitnessV0ScriptHashTy && segwit:
		// The witness script is the final element of the witness
		// stack.
		witnessScript := witness[len(witness)-1]
		pops, _ := txsparser.ParseScript(witnessScript)

		shInputs := txsparser.ExpectedInputs(pops, txsparser.TypeOfScript(pops))
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	default:
		si.SigOps = getSigOpCount(pkPops, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		si.NumInputs = len(sigPops)
	}

	return si, nil
}

// payToPubKeyHashScript creates a new script to pay a transaction
// output to a 20-byte pubkey hash. It is expected that the input is a valid
// hash.
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(txsparser.OP_DUP).AddOp(txsparser.OP_HASH160).
		AddData(pubKeyHash).AddOp(txsparser.OP_EQUALVERIFY).AddOp(txsparser.OP_CHECKSIG).
		Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// pubkey hash witness program. The passed hash is expected to be valid.
func payToWitnessPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(txsparser.OP_0).AddData(pubKeyHash).Script()
}

// payToScriptHashScript creates a new script to pay a transaction output to a
// script hash. It is expected that the input is a valid hash.
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(txsparser.OP_HASH160).AddData(scriptHash).
		AddOp(txsparser.OP_EQUAL).Script()
}

// payToWitnessPubKeyHashScript creates a new script to pay to a version 0
// script hash witness program. The passed hash is expected to be valid.
func payToWitnessScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(txsparser.OP_0).AddData(scriptHash).Script()
}

// payToPubkeyScript creates a new script to pay a transaction output to a
// public key. It is expected that the input is a valid pubkey.
func payToPubKeyScript(serializedPubKey []byte) ([]byte, error) {
	return NewScriptBuilder().AddData(serializedPubKey).
		AddOp(txsparser.OP_CHECKSIG).Script()
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
		return payToPubKeyHashScript(addr.ScriptAddress())

	case *btcutil.AddressScriptHash:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToScriptHashScript(addr.ScriptAddress())

	case *btcutil.AddressPubKey:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyScript(addr.ScriptAddress())

	case *btcutil.AddressWitnessPubKeyHash:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessPubKeyHashScript(addr.ScriptAddress())
	case *btcutil.AddressWitnessScriptHash:
		if addr == nil {
			return nil, txsparser.ScriptError(txsparser.ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessScriptHashScript(addr.ScriptAddress())
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

	return NewScriptBuilder().AddOp(txsparser.OP_RETURN).AddData(data).Script()
}

// MultiSigScript returns a valid script for a multisignature redemption where
// nrequired of the keys in pubkeys are required to have signed the transaction
// for success.  An Error with the error code ErrTooManyRequiredSigs will be
// returned if nrequired is larger than the number of keys provided.
func MultiSigScript(pubkeys []*btcutil.AddressPubKey, nrequired int) ([]byte, error) {
	if len(pubkeys) < nrequired {
		str := fmt.Sprintf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", nrequired, len(pubkeys))
		return nil, txsparser.ScriptError(txsparser.ErrTooManyRequiredSigs, str)
	}

	builder := NewScriptBuilder().AddInt64(int64(nrequired))
	for _, key := range pubkeys {
		builder.AddData(key.ScriptAddress())
	}
	builder.AddInt64(int64(len(pubkeys)))
	builder.AddOp(txsparser.OP_CHECKMULTISIG)

	return builder.Script()
}


// ExtractPkScriptAddrs returns the type of script, addresses and required
// signatures associated with the passed PkScript.  Note that it only works for
// 'standard' transaction script types.  Any data such as public keys which are
// invalid are omitted from the results.
func ExtractPkScriptAddrs(pkScript []byte, chainParams *chaincfg.Params) (txsparser.ScriptClass, []btcutil.Address, int, error) {
	var addrs []btcutil.Address
	var requiredSigs int

	// No valid addresses or required signatures if the script doesn't
	// parse.
	pops, err := txsparser.ParseScript(pkScript)
	if err != nil {
		return txsparser.NonStandardTy, nil, 0, err
	}

	scriptClass := txsparser.TypeOfScript(pops)
	switch scriptClass {
	case txsparser.PubKeyHashTy:
		// A pay-to-pubkey-hash script is of the form:
		//  OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
		// Therefore the pubkey hash is the 3rd item on the stack.
		// Skip the pubkey hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressPubKeyHash(pops[2].Data, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.ContractHashTy:
		// A contract-hash script is of the form:
		//  OP_CONTRACTCALL <hash>
		requiredSigs = 0
		addr, err := btcutil.NewAddressContract(pops[0].Data, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.WitnessV0PubKeyHashTy:
		// A pay-to-witness-pubkey-hash script is of thw form:
		//  OP_0 <20-byte hash>
		// Therefore, the pubkey hash is the second item on the stack.
		// Skip the pubkey hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressWitnessPubKeyHash(pops[1].Data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.PubKeyTy:
		// A pay-to-pubkey script is of the form:
		//  <pubkey> OP_CHECKSIG
		// Therefore the pubkey is the first item on the stack.
		// Skip the pubkey if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressPubKey(pops[0].Data, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.ScriptHashTy:
		// A pay-to-script-hash script is of the form:
		//  OP_HASH160 <scripthash> OP_EQUAL
		// Therefore the script hash is the 2nd item on the stack.
		// Skip the script hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressScriptHashFromHash(pops[1].Data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.WitnessV0ScriptHashTy:
		// A pay-to-witness-script-hash script is of the form:
		//  OP_0 <32-byte hash>
		// Therefore, the script hash is the second item on the stack.
		// Skip the script hash if it's invalid for some reason.
		requiredSigs = 1
		addr, err := btcutil.NewAddressWitnessScriptHash(pops[1].Data,
			chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}

	case txsparser.MultiSigTy:
		// A multi-signature script is of the form:
		//  <numsigs> <pubkey> <pubkey> <pubkey>... <numpubkeys> OP_CHECKMULTISIG
		// Therefore the number of required signatures is the 1st item
		// on the stack and the number of public keys is the 2nd to last
		// item on the stack.
		requiredSigs = txsparser.AsSmallInt(pops[0].Opcode)
		numPubKeys := txsparser.AsSmallInt(pops[len(pops)-2].Opcode)

		// Extract the public keys while skipping any that are invalid.
		addrs = make([]btcutil.Address, 0, numPubKeys)
		for i := 0; i < numPubKeys; i++ {
			addr, err := btcutil.NewAddressPubKey(pops[i+1].Data,
				chainParams)
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

// AtomicSwapDataPushes houses the data pushes found in atomic swap contracts.
type AtomicSwapDataPushes struct {
	RecipientHash160 [20]byte
	RefundHash160    [20]byte
	SecretHash       [32]byte
	SecretSize       int64
	LockTime         int64
}

// ExtractAtomicSwapDataPushes returns the data pushes from an atomic swap
// contract.  If the script is not an atomic swap contract,
// ExtractAtomicSwapDataPushes returns (nil, nil).  Non-nil errors are returned
// for unparsable scripts.
//
// NOTE: Atomic swaps are not considered standard script types by the dcrd
// mempool policy and should be used with P2SH.  The atomic swap format is also
// expected to change to use a more secure hash function in the future.
//
// This function is only defined in the txscript package due to API limitations
// which prevent callers using txscript to parse nonstandard scripts.
func ExtractAtomicSwapDataPushes(version uint16, pkScript []byte) (*AtomicSwapDataPushes, error) {
	pops, err := txsparser.ParseScript(pkScript)
	if err != nil {
		return nil, err
	}

	if len(pops) != 20 {
		return nil, nil
	}
	isAtomicSwap := pops[0].Opcode.Value == txsparser.OP_IF &&
		pops[1].Opcode.Value == txsparser.OP_SIZE &&
		canonicalPush(pops[2]) &&
		pops[3].Opcode.Value == txsparser.OP_EQUALVERIFY &&
		pops[4].Opcode.Value == txsparser.OP_SHA256 &&
		pops[5].Opcode.Value == txsparser.OP_DATA_32 &&
		pops[6].Opcode.Value == txsparser.OP_EQUALVERIFY &&
		pops[7].Opcode.Value == txsparser.OP_DUP &&
		pops[8].Opcode.Value == txsparser.OP_HASH160 &&
		pops[9].Opcode.Value == txsparser.OP_DATA_20 &&
		pops[10].Opcode.Value == txsparser.OP_ELSE &&
		canonicalPush(pops[11]) &&
		pops[12].Opcode.Value == txsparser.OP_CHECKLOCKTIMEVERIFY &&
		pops[13].Opcode.Value == txsparser.OP_DROP &&
		pops[14].Opcode.Value == txsparser.OP_DUP &&
		pops[15].Opcode.Value == txsparser.OP_HASH160 &&
		pops[16].Opcode.Value == txsparser.OP_DATA_20 &&
		pops[17].Opcode.Value == txsparser.OP_ENDIF &&
		pops[18].Opcode.Value == txsparser.OP_EQUALVERIFY &&
		pops[19].Opcode.Value == txsparser.OP_CHECKSIG
	if !isAtomicSwap {
		return nil, nil
	}

	pushes := new(AtomicSwapDataPushes)
	copy(pushes.SecretHash[:], pops[5].Data)
	copy(pushes.RecipientHash160[:], pops[9].Data)
	copy(pushes.RefundHash160[:], pops[16].Data)
	if pops[2].Data != nil {
		locktime, err := makeScriptNum(pops[2].Data, true, 5)
		if err != nil {
			return nil, nil
		}
		pushes.SecretSize = int64(locktime)
	} else if op := pops[2].Opcode; txsparser.IsSmallInt(op) {
		pushes.SecretSize = int64(txsparser.AsSmallInt(op))
	} else {
		return nil, nil
	}
	if pops[11].Data != nil {
		locktime, err := makeScriptNum(pops[11].Data, true, 5)
		if err != nil {
			return nil, nil
		}
		pushes.LockTime = int64(locktime)
	} else if op := pops[11].Opcode; txsparser.IsSmallInt(op) {
		pushes.LockTime = int64(txsparser.AsSmallInt(op))
	} else {
		return nil, nil
	}
	return pushes, nil
}
