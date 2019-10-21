// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsparser

import (
	"fmt"
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
	StandardVerifyFlags = ScriptBip16 |
		ScriptVerifyDERSignatures |
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

func IsContractHash(pops []ParsedOpcode) bool {
	return len(pops) == 1 && len(pops[0].Data) == 20 && pops[0].Opcode.Value == OP_CONTRACTCALL
}

// isPubkey returns true if the script passed is a pay-to-pubkey transaction,
// false otherwise.
func IsPubkey(pops []ParsedOpcode) bool {
	// Valid pubkeys are either 33 or 65 bytes.
	return len(pops) == 2 &&
		(len(pops[0].Data) == 33 || len(pops[0].Data) == 65) &&
		pops[1].Opcode.Value == OP_CHECKSIG
}

// isPubkeyHash returns true if the script passed is a pay-to-pubkey-hash
// transaction, false otherwise.
func IsPubkeyHash(pops []ParsedOpcode) bool {
	return len(pops) == 5 &&
		pops[0].Opcode.Value == OP_DUP &&
		pops[1].Opcode.Value == OP_HASH160 &&
		pops[2].Opcode.Value == OP_DATA_20 &&
		pops[3].Opcode.Value == OP_EQUALVERIFY &&
		pops[4].Opcode.Value == OP_CHECKSIG
}

// isSmallInt returns whether or not the opcode is considered a small integer,
// which is an OP_0, or OP_1 through OP_16.
func IsSmallInt(op *OpCode) bool {
	if op.Value == OP_0 || (op.Value >= OP_1 && op.Value <= OP_16) {
		return true
	}
	return false
}

// asSmallInt returns the passed opcode, which must be true according to
// isSmallInt(), as an integer.
func AsSmallInt(op *OpCode) int {
	if op.Value == OP_0 {
		return 0
	}

	return int(op.Value - (OP_1 - 1))
}

// isMultiSig returns true if the passed script is a multisig transaction, false
// otherwise.
func IsMultiSig(pops []ParsedOpcode) bool {
	// The absolute minimum is 1 pubkey:
	// OP_0/OP_1-16 <pubkey> OP_1 OP_CHECKMULTISIG
	l := len(pops)
	if l < 4 {
		return false
	}
	if !IsSmallInt(pops[0].Opcode) {
		return false
	}
	if !IsSmallInt(pops[l-2].Opcode) {
		return false
	}
	if pops[l-1].Opcode.Value != OP_CHECKMULTISIG {
		return false
	}

	// Verify the number of pubkeys specified matches the actual number
	// of pubkeys provided.
	if l-2-1 != AsSmallInt(pops[l-2].Opcode) {
		return false
	}

	for _, pop := range pops[1 : l-2] {
		// Valid pubkeys are either 33 or 65 bytes.
		if len(pop.Data) != 33 && len(pop.Data) != 65 {
			return false
		}
	}
	return true
}

// isNullData returns true if the passed script is a null data transaction,
// false otherwise.
func IsNullData(pops []ParsedOpcode) bool {
	// A nulldata transaction is either a single OP_RETURN or an
	// OP_RETURN SMALLDATA (where SMALLDATA is a data push up to
	// MaxDataCarrierSize bytes).
	l := len(pops)
	if l == 1 && pops[0].Opcode.Value == OP_RETURN {
		return true
	}

	return l == 2 &&
		pops[0].Opcode.Value == OP_RETURN &&
		(IsSmallInt(pops[1].Opcode) || pops[1].Opcode.Value <=
			OP_PUSHDATA4) &&
		len(pops[1].Data) <= MaxDataCarrierSize
}

// isWitnessPubKeyHash returns true if the passed script is a
// pay-to-witness-pubkey-hash, and false otherwise.
func IsWitnessPubKeyHash(pops []ParsedOpcode) bool {
	return len(pops) == 2 &&
		pops[0].Opcode.Value == OP_0 &&
		pops[1].Opcode.Value == OP_DATA_20
}

// isScriptHash returns true if the script passed is a pay-to-script-hash
// transaction, false otherwise.
func IsScriptHash(pops []ParsedOpcode) bool {
	return len(pops) == 3 &&
		pops[0].Opcode.Value == OP_HASH160 &&
		pops[1].Opcode.Value == OP_DATA_20 &&
		pops[2].Opcode.Value == OP_EQUAL
}

// isWitnessScriptHash returns true if the passed script is a
// pay-to-witness-script-hash transaction, false otherwise.
func IsWitnessScriptHash(pops []ParsedOpcode) bool {
	return len(pops) == 2 &&
		pops[0].Opcode.Value == OP_0 &&
		pops[1].Opcode.Value == OP_DATA_32
}

// scriptType returns the type of the script being inspected from the known
// standard types.
func TypeOfScript(pops []ParsedOpcode) ScriptClass {
	if IsPubkey(pops) {
		return PubKeyTy
	} else if IsPubkeyHash(pops) {
		return PubKeyHashTy
	} else if IsWitnessPubKeyHash(pops) {
		return WitnessV0PubKeyHashTy
	} else if IsContractHash(pops) {
		return ContractHashTy
	} else if IsScriptHash(pops) {
		return ScriptHashTy
	} else if IsWitnessScriptHash(pops) {
		return WitnessV0ScriptHashTy
	} else if IsMultiSig(pops) {
		return MultiSigTy
	} else if IsNullData(pops) {
		return NullDataTy
	}
	return NonStandardTy
}

// expectedInputs returns the number of arguments required by a script.
// If the script is of unknown type such that the number can not be determined
// then -1 is returned. We are an internal function and thus assume that class
// is the real class of pops (and we can thus assume things that were determined
// while finding out the type).
func ExpectedInputs(pops []ParsedOpcode, class ScriptClass) int {
	switch class {
	case PubKeyTy:
		return 1

	case PubKeyHashTy:
		return 2

	case ContractHashTy:
		return 0

	case WitnessV0PubKeyHashTy:
		return 2

	case ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case WitnessV0ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case MultiSigTy:
		// Standard multisig has a push a small number for the number
		// of sigs and number of keys.  Check the first push instruction
		// to see how many arguments are expected. typeOfScript already
		// checked this so we know it'll be a small int.  Also, due to
		// the original bitcoind bug where OP_CHECKMULTISIG pops an
		// additional item from the stack, add an extra expected input
		// for the extra push that is required to compensate.
		return AsSmallInt(pops[0].Opcode) + 1

	case NullDataTy:
		fallthrough
	default:
		return -1
	}
}


// parseScriptTemplate is the same as parseScript but allows the passing of the
// template list for testing purposes.  When there are parse errors, it returns
// the list of parsed opcodes up to the point of failure along with the error.
func ParseScriptTemplate(script []byte, opcodes *[256]OpCode) ([]ParsedOpcode, error) {
	retScript := make([]ParsedOpcode, 0, len(script))
	for i := 0; i < len(script); {
		instr := script[i]
		op := &opcodes[instr]
		pop := ParsedOpcode{Opcode: op}

		// Parse data out of instruction.
		switch {
		// No additional data.  Note that some of the opcodes, notably
		// OP_1NEGATE, OP_0, and OP_[1-16] represent the data
		// themselves.
		case op.Length == 1:
			i++

			// Data pushes of specific lengths -- OP_DATA_[1-75].
		case op.Length > 1:
			if len(script[i:]) < op.Length {
				str := fmt.Sprintf("opcode %s requires %d "+
					"bytes, but script only has %d remaining",
					op.Name, op.Length, len(script[i:]))
				return retScript, ScriptError(ErrMalformedPush,
					str)
			}

			// Slice out the data.
			pop.Data = script[i+1 : i+op.Length]
			i += op.Length

			// Data pushes with parsed lengths -- OP_PUSHDATAP{1,2,4}.
		case op.Length < 0:
			var l uint
			off := i + 1

			if len(script[off:]) < -op.Length {
				str := fmt.Sprintf("opcode %s requires %d "+
					"bytes, but script only has %d remaining",
					op.Name, -op.Length, len(script[off:]))
				return retScript, ScriptError(ErrMalformedPush,
					str)
			}

			// Next -length bytes are little endian length of data.
			switch op.Length {
			case -1:
				l = uint(script[off])
			case -2:
				l = ((uint(script[off+1]) << 8) |
					uint(script[off]))
			case -4:
				l = ((uint(script[off+3]) << 24) |
					(uint(script[off+2]) << 16) |
					(uint(script[off+1]) << 8) |
					uint(script[off]))
			default:
				str := fmt.Sprintf("invalid opcode length %d",
					op.Length)
				return retScript, ScriptError(ErrMalformedPush,
					str)
			}

			// Move offset to beginning of the data.
			off += -op.Length

			// Disallow entries that do not fit script or were
			// sign extended.
			if int(l) > len(script[off:]) || int(l) < 0 {
				str := fmt.Sprintf("opcode %s pushes %d bytes, "+
					"but script only has %d remaining",
					op.Name, int(l), len(script[off:]))
				return retScript, ScriptError(ErrMalformedPush,
					str)
			}

			pop.Data = script[off : off+int(l)]
			i += 1 - op.Length + int(l)
		}

		retScript = append(retScript, pop)
	}

	return retScript, nil
}

// parseScript preparses the script in bytes into a list of parsedOpcodes while
// applying a number of sanity checks.
func ParseScript(script []byte) ([]ParsedOpcode, error) {
	return ParseScriptTemplate(script, &OpCodeArray)
}

// GetScriptClass returns the class of the script passed.
//
// NonStandardTy will be returned when the script does not parse.
func GetScriptClass(script []byte) ScriptClass {
	pops, err := ParseScript(script)
	if err != nil {
		return NonStandardTy
	}
	return TypeOfScript(pops)
}

// CalcMultiSigStats returns the number of public keys and signatures from
// a multi-signature transaction script.  The passed script MUST already be
// known to be a multi-signature script.
func CalcMultiSigStats(script []byte) (int, int, error) {
	pops, err := ParseScript(script)
	if err != nil {
		return 0, 0, err
	}

	// A multi-signature script is of the pattern:
	//  NUM_SIGS PUBKEY PUBKEY PUBKEY... NUM_PUBKEYS OP_CHECKMULTISIG
	// Therefore the number of signatures is the oldest item on the stack
	// and the number of pubkeys is the 2nd to last.  Also, the absolute
	// minimum for a multi-signature script is 1 pubkey, so at least 4
	// items must be on the stack per:
	//  OP_1 PUBKEY OP_1 OP_CHECKMULTISIG
	if len(pops) < 4 {
		str := fmt.Sprintf("script %x is not a multisig script", script)
		return 0, 0, ScriptError(ErrNotMultisigScript, str)
	}

	numSigs := AsSmallInt(pops[0].Opcode)
	numPubKeys := AsSmallInt(pops[len(pops)-2].Opcode)
	return numPubKeys, numSigs, nil
}

// PushedData returns an array of byte slices containing any pushed data found
// in the passed script.  This includes OP_0, but not OP_1 - OP_16.
func PushedData(script []byte) ([][]byte, error) {
	pops, err := ParseScript(script)
	if err != nil {
		return nil, err
	}

	var data [][]byte
	for _, pop := range pops {
		if pop.Data != nil {
			data = append(data, pop.Data)
		} else if pop.Opcode.Value == OP_0 {
			data = append(data, nil)
		}
	}
	return data, nil
}

// ExtractPkScriptAddrs returns the type of script, addresses and required
// signatures associated with the passed PkScript.  Note that it only works for
// 'standard' transaction script types.  Any data such as public keys which are
// invalid are omitted from the results.
func ExtractContractAddrs(pkScript []byte) (ScriptClass, []byte, int, error) {
	// No valid addresses or required signatures if the script doesn't
	// parse.
	pops, err := ParseScript(pkScript)
	if err != nil {
		return NonStandardTy, nil, 0, err
	}

	scriptClass := TypeOfScript(pops)
	switch scriptClass {
	case ContractHashTy:
		return ContractHashTy, pops[0].Data[:], 0, nil
	}

	return 0, nil, 0, ScriptError(ErrUnsupportedAddress, "Need a contract address.")
}
