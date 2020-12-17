// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsparser

import (
	"github.com/omegasuite/omega/ovm"
)

// ScriptFlags is a bitmask defining additional operations or tests that will be
// done when executing a script pair.
type ScriptFlags uint32

const (
	// ScriptBip16 defines whether the bip16 threshold has passed and thus
	// pay-to-script hash transactions will be fully validated.
	ScriptBip16 ScriptFlags = 1 << iota

	// ScriptStrictMultiSig defines whether to verify the stack item
	// used by CHECKMULTISIG is zero length.
	ScriptStrictMultiSig

	// ScriptDiscourageUpgradableNops defines whether to verify that
	// NOP1 through NOP10 are reserved for future soft-fork upgrades.  This
	// flag must not be used for consensus critical code nor applied to
	// blocks as this flag is only for stricter standard transaction
	// checks.  This flag is only applied when the above opcodes are
	// executed.
	ScriptDiscourageUpgradableNops

	// ScriptVerifyCheckLockTimeVerify defines whether to verify that
	// a transaction output is spendable based on the locktime.
	// This is BIP0065.
	ScriptVerifyCheckLockTimeVerify

	// ScriptVerifyCheckSequenceVerify defines whether to allow execution
	// pathways of a script to be restricted based on the age of the output
	// being spent.  This is BIP0112.
	ScriptVerifyCheckSequenceVerify

	// ScriptVerifyCleanStack defines that the stack must contain only
	// one stack element after evaluation and that the element must be
	// true if interpreted as a boolean.  This is rule 6 of BIP0062.
	// This flag should never be used without the ScriptBip16 flag nor the
	// ScriptVerifyWitness flag.
	ScriptVerifyCleanStack

	// ScriptVerifyDERSignatures defines that signatures are required
	// to compily with the DER format.
	ScriptVerifyDERSignatures

	// ScriptVerifyLowS defines that signtures are required to comply with
	// the DER format and whose S value is <= order / 2.  This is rule 5
	// of BIP0062.
	ScriptVerifyLowS

	// ScriptVerifyMinimalData defines that signatures must use the smallest
	// push operator. This is both rules 3 and 4 of BIP0062.
	ScriptVerifyMinimalData

	// ScriptVerifyNullFail defines that signatures must be empty if
	// a CHECKSIG or CHECKMULTISIG operation fails.
	ScriptVerifyNullFail

	// ScriptVerifySigPushOnly defines that signature scripts must contain
	// only pushed data.  This is rule 2 of BIP0062.
	ScriptVerifySigPushOnly

	// ScriptVerifyStrictEncoding defines that signature scripts and
	// public keys must follow the strict encoding requirements.
	ScriptVerifyStrictEncoding

	// ScriptVerifyWitness defines whether or not to verify a transaction
	// output using a witness program template.
	ScriptVerifyWitness

	// ScriptVerifyDiscourageUpgradeableWitnessProgram makes witness
	// program with versions 2-16 non-standard.
	ScriptVerifyDiscourageUpgradeableWitnessProgram

	// ScriptVerifyMinimalIf makes a script with an OP_IF/OP_NOTIF whose
	// operand is anything other than empty vector or [0x01] non-standard.
	ScriptVerifyMinimalIf

	// ScriptVerifyWitnessPubKeyType makes a script within a check-sig
	// operation whose public key isn't serialized in a compressed format
	// non-standard.
	ScriptVerifyWitnessPubKeyType
)

const (
	// MaxDataCarrierSize is the maximum number of bytes allowed in pushed
	// data to be considered a nulldata transaction
	MaxDataCarrierSize = 80

	// StandardVerifyFlags are the script flags which are used when
	// executing transaction scripts to enforce additional checks which
	// are required for the script to be considered standard.  These checks
	// help reduce issues related to transaction malleability as well as
	// allow pay-to-script hash transactions.  Note these flags are
	// different than what is required for the consensus rules in that they
	// are more strict.
	//
	// TODO: This definition does not belong here.  It belongs in a policy
	// package.
	StandardVerifyFlags = ScriptVerifyDERSignatures |
		ScriptVerifyStrictEncoding |
		ScriptVerifyMinimalData |
		ScriptStrictMultiSig |
		ScriptDiscourageUpgradableNops |
		ScriptVerifyCleanStack |
		ScriptVerifyNullFail |
		ScriptVerifyCheckLockTimeVerify |
		ScriptVerifyCheckSequenceVerify |
		ScriptVerifyLowS |
		ScriptStrictMultiSig |
		ScriptVerifyWitness |
		ScriptVerifyDiscourageUpgradeableWitnessProgram |
		ScriptVerifyMinimalIf |
		ScriptVerifyWitnessPubKeyType
)

// ScriptClass is an enumeration for the list of standard types of script.
type ScriptClass byte

// String implements the Stringer interface by returning the name of
// the enum script class. If the enum is invalid then "Invalid" will be
// returned.
func (t ScriptClass) String() string {
	if int(t) > len(ScriptClassToName) || int(t) < 0 {
		return "Invalid"
	}
	return ScriptClassToName[t]
}

func IsContractHash(netid byte) bool {
	return netid == 0x88
}

// isPubkey returns true if the script passed is a pay-to-pubkey transaction,
// false otherwise.
func IsPubkey(script []byte) bool {
	return false
}

// isPubkeyHash returns true if the script passed is a pay-to-pubkey-hash
// transaction, false otherwise.
func IsPubkeyHash(script []byte) bool {
	return script[21] == ovm.OP_PAY2PKH
}

// isMultiSig returns true if the passed script is a multisig transaction, false
// otherwise.
func IsMultiSig(script []byte) bool {
	return script[21] == ovm.OP_PAYMULTISIG
}

// isNullData returns true if the passed script is a null data transaction,
// false otherwise.
func IsNullData(script []byte) bool {
	return script[21] == ovm.OP_PAY2NONE
}

// isScriptHash returns true if the script passed is a pay-to-script-hash
// transaction, false otherwise.
func IsScriptHash(script []byte) bool {
	return script[21] == ovm.OP_PAY2SCRIPTH
}

// scriptType returns the type of the script being inspected from the known
// standard types.
func TypeOfScript(pops []byte) ScriptClass {
	if  IsContractHash(pops[0]) {
		return ContractHashTy
	}

	switch pops[21] {
	case ovm.OP_PAY2PKH:
		return PubKeyHashTy
	case ovm.OP_PAY2SCRIPTH:
		return ScriptHashTy
	case ovm.OP_PAY2NONE:
		return NullDataTy
	case ovm.OP_PAY2ANY:
		return PaytoAnyoneTy
	case ovm.OP_PAYMULTISIG:
		return MultiSigTy
	}

	return NonStandardTy
}

// expectedInputs returns the number of arguments required by a script.
// If the script is of unknown type such that the number can not be determined
// then -1 is returned. We are an internal function and thus assume that class
// is the real class of pops (and we can thus assume things that were determined
// while finding out the type).
func ExpectedInputs(pops []byte, class ScriptClass) int {
	switch class {
	case PubKeyHashTy:
		return 2

	case ContractHashTy:
		return 0

	case ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case MultiSigTy:
//	case MultiScriptTy:
		// Standard multisig has a push a small number for the number
		// of sigs and number of keys.  Check the first push instruction
		// to see how many arguments are expected. typeOfScript already
		// checked this so we know it'll be a small int.  Also, due to
		// the original bitcoind bug where OP_CHECKMULTISIG pops an
		// additional item from the stack, add an extra expected input
		// for the extra push that is required to compensate.
		return 1

	case NullDataTy:
		fallthrough
	default:
		return -1
	}
	return -1
}

// GetScriptClass returns the class of the script passed.
//
// NonStandardTy will be returned when the script does not parse.
/*
func GetScriptClass(script []byte) ScriptClass {
	return TypeOfScript(script)
}
 */
