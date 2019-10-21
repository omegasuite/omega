// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"

	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/txscript/txsparser"
)

type OpFunc func(*txsparser.ParsedOpcode, *Engine) error

// opcodeArray holds details about all possible opcodes such as how many bytes
// the opcode and any associated data should take, its human-readable name, and
// the handler function.
var opcodeFuncs = [256]OpFunc{
	// Data push opcodes.
	txsparser.OP_FALSE:      opcodeFalse,
	txsparser.OP_DATA_1:     opcodePushData,
	txsparser.OP_DATA_2:     opcodePushData,
	txsparser.OP_DATA_3:     opcodePushData,
	txsparser.OP_DATA_4:     opcodePushData,
	txsparser.OP_DATA_5:     opcodePushData,
	txsparser.OP_DATA_6:     opcodePushData,
	txsparser.OP_DATA_7:     opcodePushData,
	txsparser.OP_DATA_8:     opcodePushData,
	txsparser.OP_DATA_9:     opcodePushData,
	txsparser.OP_DATA_10:    opcodePushData,
	txsparser.OP_DATA_11:    opcodePushData,
	txsparser.OP_DATA_12:    opcodePushData,
	txsparser.OP_DATA_13:    opcodePushData,
	txsparser.OP_DATA_14:    opcodePushData,
	txsparser.OP_DATA_15:    opcodePushData,
	txsparser.OP_DATA_16:    opcodePushData,
	txsparser.OP_DATA_17:    opcodePushData,
	txsparser.OP_DATA_18:    opcodePushData,
	txsparser.OP_DATA_19:    opcodePushData,
	txsparser.OP_DATA_20:    opcodePushData,
	txsparser.OP_DATA_21:    opcodePushData,
	txsparser.OP_DATA_22:    opcodePushData,
	txsparser.OP_DATA_23:    opcodePushData,
	txsparser.OP_DATA_24:    opcodePushData,
	txsparser.OP_DATA_25:    opcodePushData,
	txsparser.OP_DATA_26:    opcodePushData,
	txsparser.OP_DATA_27:    opcodePushData,
	txsparser.OP_DATA_28:    opcodePushData,
	txsparser.OP_DATA_29:    opcodePushData,
	txsparser.OP_DATA_30:    opcodePushData,
	txsparser.OP_DATA_31:    opcodePushData,
	txsparser.OP_DATA_32:    opcodePushData,
	txsparser.OP_DATA_33:    opcodePushData,
	txsparser.OP_DATA_34:    opcodePushData,
	txsparser.OP_DATA_35:    opcodePushData,
	txsparser.OP_DATA_36:    opcodePushData,
	txsparser.OP_DATA_37:    opcodePushData,
	txsparser.OP_DATA_38:    opcodePushData,
	txsparser.OP_DATA_39:    opcodePushData,
	txsparser.OP_DATA_40:    opcodePushData,
	txsparser.OP_DATA_41:    opcodePushData,
	txsparser.OP_DATA_42:    opcodePushData,
	txsparser.OP_DATA_43:    opcodePushData,
	txsparser.OP_DATA_44:    opcodePushData,
	txsparser.OP_DATA_45:    opcodePushData,
	txsparser.OP_DATA_46:    opcodePushData,
	txsparser.OP_DATA_47:    opcodePushData,
	txsparser.OP_DATA_48:    opcodePushData,
	txsparser.OP_DATA_49:    opcodePushData,
	txsparser.OP_DATA_50:    opcodePushData,
	txsparser.OP_DATA_51:    opcodePushData,
	txsparser.OP_DATA_52:    opcodePushData,
	txsparser.OP_DATA_53:    opcodePushData,
	txsparser.OP_DATA_54:    opcodePushData,
	txsparser.OP_DATA_55:    opcodePushData,
	txsparser.OP_DATA_56:    opcodePushData,
	txsparser.OP_DATA_57:    opcodePushData,
	txsparser.OP_DATA_58:    opcodePushData,
	txsparser.OP_DATA_59:    opcodePushData,
	txsparser.OP_DATA_60:    opcodePushData,
	txsparser.OP_DATA_61:    opcodePushData,
	txsparser.OP_DATA_62:    opcodePushData,
	txsparser.OP_DATA_63:    opcodePushData,
	txsparser.OP_DATA_64:    opcodePushData,
	txsparser.OP_DATA_65:    opcodePushData,
	txsparser.OP_DATA_66:    opcodePushData,
	txsparser.OP_DATA_67:    opcodePushData,
	txsparser.OP_DATA_68:    opcodePushData,
	txsparser.OP_DATA_69:    opcodePushData,
	txsparser.OP_DATA_70:    opcodePushData,
	txsparser.OP_DATA_71:    opcodePushData,
	txsparser.OP_DATA_72:    opcodePushData,
	txsparser.OP_DATA_73:    opcodePushData,
	txsparser.OP_DATA_74:    opcodePushData,
	txsparser.OP_DATA_75:    opcodePushData,
	txsparser.OP_PUSHDATA1:  opcodePushData,
	txsparser.OP_PUSHDATA2:  opcodePushData,
	txsparser.OP_PUSHDATA4:  opcodePushData,
	txsparser.OP_1NEGATE:    opcode1Negate,
	txsparser.OP_RESERVED:   opcodeReserved,
	txsparser.OP_TRUE:       opcodeN,
	txsparser.OP_2:          opcodeN,
	txsparser.OP_3:          opcodeN,
	txsparser.OP_4:          opcodeN,
	txsparser.OP_5:          opcodeN,
	txsparser.OP_6:          opcodeN,
	txsparser.OP_7:          opcodeN,
	txsparser.OP_8:          opcodeN,
	txsparser.OP_9:          opcodeN,
	txsparser.OP_10:         opcodeN,
	txsparser.OP_11:         opcodeN,
	txsparser.OP_12:         opcodeN,
	txsparser.OP_13:         opcodeN,
	txsparser.OP_14:         opcodeN,
	txsparser.OP_15:         opcodeN,
	txsparser.OP_16:         opcodeN,

	// Control opcodes.
	txsparser.OP_NOP:                  opcodeNop,
	txsparser.OP_VER:                  opcodeReserved,
	txsparser.OP_IF:                   opcodeIf,
	txsparser.OP_NOTIF:                opcodeNotIf,
	txsparser.OP_VERIF:                opcodeReserved,
	txsparser.OP_VERNOTIF:             opcodeReserved,
	txsparser.OP_ELSE:                 opcodeElse,
	txsparser.OP_ENDIF:                opcodeEndif,
	txsparser.OP_VERIFY:               opcodeVerify,
	txsparser.OP_RETURN:               opcodeReturn,
	txsparser.OP_CHECKLOCKTIMEVERIFY:  opcodeCheckLockTimeVerify,
	txsparser.OP_CHECKSEQUENCEVERIFY:  opcodeCheckSequenceVerify,

	// Stack opcodes.
	txsparser.OP_TOALTSTACK:    opcodeToAltStack,
	txsparser.OP_FROMALTSTACK:  opcodeFromAltStack,
	txsparser.OP_2DROP:         opcode2Drop,
	txsparser.OP_2DUP:          opcode2Dup,
	txsparser.OP_3DUP:          opcode3Dup,
	txsparser.OP_2OVER:         opcode2Over,
	txsparser.OP_2ROT:          opcode2Rot,
	txsparser.OP_2SWAP:         opcode2Swap,
	txsparser.OP_IFDUP:         opcodeIfDup,
	txsparser.OP_DEPTH:         opcodeDepth,
	txsparser.OP_DROP:          opcodeDrop,
	txsparser.OP_DUP:           opcodeDup,
	txsparser.OP_NIP:           opcodeNip,
	txsparser.OP_OVER:          opcodeOver,
	txsparser.OP_PICK:          opcodePick,
	txsparser.OP_ROLL:          opcodeRoll,
	txsparser.OP_ROT:           opcodeRot,
	txsparser.OP_SWAP:          opcodeSwap,
	txsparser.OP_TUCK:          opcodeTuck,

	// Splice opcodes.
	txsparser.OP_CAT:     opcodeDisabled,
	txsparser.OP_SUBSTR:  opcodeDisabled,
	txsparser.OP_LEFT:    opcodeDisabled,
	txsparser.OP_RIGHT:   opcodeDisabled,
	txsparser.OP_SIZE:    opcodeSize,

	// Bitwise logic opcodes.
	txsparser.OP_INVERT:       opcodeDisabled,
	txsparser.OP_AND:          opcodeDisabled,
	txsparser.OP_OR:           opcodeDisabled,
	txsparser.OP_XOR:          opcodeDisabled,
	txsparser.OP_EQUAL:        opcodeEqual,
	txsparser.OP_EQUALVERIFY:  opcodeEqualVerify,
	txsparser.OP_RESERVED1:    opcodeReserved,
	txsparser.OP_RESERVED2:    opcodeReserved,

	// Numeric related opcodes.
	txsparser.OP_1ADD:                opcode1Add,
	txsparser.OP_1SUB:                opcode1Sub,
	txsparser.OP_2MUL:                opcodeDisabled,
	txsparser.OP_2DIV:                opcodeDisabled,
	txsparser.OP_NEGATE:              opcodeNegate,
	txsparser.OP_ABS:                 opcodeAbs,
	txsparser.OP_NOT:                 opcodeNot,
	txsparser.OP_0NOTEQUAL:           opcode0NotEqual,
	txsparser.OP_ADD:                 opcodeAdd,
	txsparser.OP_SUB:                 opcodeSub,
	txsparser.OP_MUL:                 opcodeDisabled,
	txsparser.OP_DIV:                 opcodeDisabled,
	txsparser.OP_MOD:                 opcodeDisabled,
	txsparser.OP_LSHIFT:              opcodeDisabled,
	txsparser.OP_RSHIFT:              opcodeDisabled,
	txsparser.OP_BOOLAND:             opcodeBoolAnd,
	txsparser.OP_BOOLOR:              opcodeBoolOr,
	txsparser.OP_NUMEQUAL:            opcodeNumEqual,
	txsparser.OP_NUMEQUALVERIFY:      opcodeNumEqualVerify,
	txsparser.OP_NUMNOTEQUAL:         opcodeNumNotEqual,
	txsparser.OP_LESSTHAN:            opcodeLessThan,
	txsparser.OP_GREATERTHAN:         opcodeGreaterThan,
	txsparser.OP_LESSTHANOREQUAL:     opcodeLessThanOrEqual,
	txsparser.OP_GREATERTHANOREQUAL:  opcodeGreaterThanOrEqual,
	txsparser.OP_MIN:                 opcodeMin,
	txsparser.OP_MAX:                 opcodeMax,
	txsparser.OP_WITHIN:              opcodeWithin,

	// Crypto opcodes.
	txsparser.OP_RIPEMD160:            opcodeRipemd160,
	txsparser.OP_SHA1:                 opcodeSha1,
	txsparser.OP_SHA256:               opcodeSha256,
	txsparser.OP_HASH160:              opcodeHash160,
	txsparser.OP_HASH256:              opcodeHash256,
	txsparser.OP_CODESEPARATOR:        opcodeCodeSeparator,
	txsparser.OP_CHECKSIG:             opcodeCheckSig,
	txsparser.OP_CHECKSIGVERIFY:       opcodeCheckSigVerify,
	txsparser.OP_CHECKMULTISIG:        opcodeCheckMultiSig,
	txsparser.OP_CHECKMULTISIGVERIFY:  opcodeCheckMultiSigVerify,

	// Reserved opcodes.
	txsparser.OP_NOP1:   opcodeNop,
	txsparser.OP_NOP4:   opcodeNop,
	txsparser.OP_NOP5:   opcodeNop,
	txsparser.OP_NOP6:   opcodeNop,
	txsparser.OP_NOP7:   opcodeNop,
	txsparser.OP_NOP8:   opcodeNop,
	txsparser.OP_NOP9:   opcodeNop,
	txsparser.OP_NOP10:  opcodeNop,

	// Undefined opcodes.
	txsparser.OP_CONTRACTCALL:  opcodeNop,
	txsparser.OP_UNKNOWN187:  opcodeInvalid,
	txsparser.OP_UNKNOWN188:  opcodeInvalid,
	txsparser.OP_UNKNOWN189:  opcodeInvalid,
	txsparser.OP_UNKNOWN190:  opcodeInvalid,
	txsparser.OP_UNKNOWN191:  opcodeInvalid,
	txsparser.OP_UNKNOWN192:  opcodeInvalid,
	txsparser.OP_UNKNOWN193:  opcodeInvalid,
	txsparser.OP_UNKNOWN194:  opcodeInvalid,
	txsparser.OP_UNKNOWN195:  opcodeInvalid,
	txsparser.OP_UNKNOWN196:  opcodeInvalid,
	txsparser.OP_UNKNOWN197:  opcodeInvalid,
	txsparser.OP_UNKNOWN198:  opcodeInvalid,
	txsparser.OP_UNKNOWN199:  opcodeInvalid,
	txsparser.OP_UNKNOWN200:  opcodeInvalid,
	txsparser.OP_UNKNOWN201:  opcodeInvalid,
	txsparser.OP_UNKNOWN202:  opcodeInvalid,
	txsparser.OP_UNKNOWN203:  opcodeInvalid,
	txsparser.OP_UNKNOWN204:  opcodeInvalid,
	txsparser.OP_UNKNOWN205:  opcodeInvalid,
	txsparser.OP_UNKNOWN206:  opcodeInvalid,
	txsparser.OP_UNKNOWN207:  opcodeInvalid,
	txsparser.OP_UNKNOWN208:  opcodeInvalid,
	txsparser.OP_UNKNOWN209:  opcodeInvalid,
	txsparser.OP_UNKNOWN210:  opcodeInvalid,
	txsparser.OP_UNKNOWN211:  opcodeInvalid,
	txsparser.OP_UNKNOWN212:  opcodeInvalid,
	txsparser.OP_UNKNOWN213:  opcodeInvalid,
	txsparser.OP_UNKNOWN214:  opcodeInvalid,
	txsparser.OP_UNKNOWN215:  opcodeInvalid,
	txsparser.OP_UNKNOWN216:  opcodeInvalid,
	txsparser.OP_UNKNOWN217:  opcodeInvalid,
	txsparser.OP_UNKNOWN218:  opcodeInvalid,
	txsparser.OP_UNKNOWN219:  opcodeInvalid,
	txsparser.OP_UNKNOWN220:  opcodeInvalid,
	txsparser.OP_UNKNOWN221:  opcodeInvalid,
	txsparser.OP_UNKNOWN222:  opcodeInvalid,
	txsparser.OP_UNKNOWN223:  opcodeInvalid,
	txsparser.OP_UNKNOWN224:  opcodeInvalid,
	txsparser.OP_UNKNOWN225:  opcodeInvalid,
	txsparser.OP_UNKNOWN226:  opcodeInvalid,
	txsparser.OP_UNKNOWN227:  opcodeInvalid,
	txsparser.OP_UNKNOWN228:  opcodeInvalid,
	txsparser.OP_UNKNOWN229:  opcodeInvalid,
	txsparser.OP_UNKNOWN230:  opcodeInvalid,
	txsparser.OP_UNKNOWN231:  opcodeInvalid,
	txsparser.OP_UNKNOWN232:  opcodeInvalid,
	txsparser.OP_UNKNOWN233:  opcodeInvalid,
	txsparser.OP_UNKNOWN234:  opcodeInvalid,
	txsparser.OP_UNKNOWN235:  opcodeInvalid,
	txsparser.OP_UNKNOWN236:  opcodeInvalid,
	txsparser.OP_UNKNOWN237:  opcodeInvalid,
	txsparser.OP_UNKNOWN238:  opcodeInvalid,
	txsparser.OP_UNKNOWN239:  opcodeInvalid,
	txsparser.OP_UNKNOWN240:  opcodeInvalid,
	txsparser.OP_UNKNOWN241:  opcodeInvalid,
	txsparser.OP_UNKNOWN242:  opcodeInvalid,
	txsparser.OP_UNKNOWN243:  opcodeInvalid,
	txsparser.OP_UNKNOWN244:  opcodeInvalid,
	txsparser.OP_UNKNOWN245:  opcodeInvalid,
	txsparser.OP_UNKNOWN246:  opcodeInvalid,
	txsparser.OP_UNKNOWN247:  opcodeInvalid,
	txsparser.OP_UNKNOWN248:  opcodeInvalid,
	txsparser.OP_UNKNOWN249:  opcodeInvalid,

	// Bitcoin Core internal use opcode.  Defined here for completeness.
	txsparser.OP_SMALLINTEGER:  opcodeInvalid,
	txsparser.OP_PUBKEYS:       opcodeInvalid,
	txsparser.OP_UNKNOWN252:    opcodeInvalid,
	txsparser.OP_PUBKEYHASH:    opcodeInvalid,
	txsparser.OP_PUBKEY:        opcodeInvalid,

	txsparser.OP_INVALIDOPCODE:  opcodeInvalid,
}

// *******************************************
// Opcode implementation functions start here.
// *******************************************

// opcodeDisabled is a common handler for disabled opcodes.  It returns an
// appropriate error indicating the opcode is disabled.  While it would
// ordinarily make more sense to detect if the script contains any disabled
// opcodes before executing in an initial parse step, the consensus rules
// dictate the script doesn't fail until the program counter passes over a
// disabled opcode (even when they appear in a branch that is not executed).
func opcodeDisabled(op *txsparser.ParsedOpcode, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute disabled opcode %s",
		op.Opcode.Name)
	return txsparser.ScriptError(txsparser.ErrDisabledOpcode, str)
}

// opcodeReserved is a common handler for all reserved opcodes.  It returns an
// appropriate error indicating the opcode is reserved.
func opcodeReserved(op *txsparser.ParsedOpcode, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute reserved opcode %s",
		op.Opcode.Name)
	return txsparser.ScriptError(txsparser.ErrReservedOpcode, str)
}

// opcodeInvalid is a common handler for all invalid opcodes.  It returns an
// appropriate error indicating the opcode is invalid.
func opcodeInvalid(op *txsparser.ParsedOpcode, vm *Engine) error {
	str := fmt.Sprintf("attempt to execute invalid opcode %s",
		op.Opcode.Name)
	return txsparser.ScriptError(txsparser.ErrReservedOpcode, str)
}

// opcodeFalse pushes an empty array to the data stack to represent false.  Note
// that 0, when encoded as a number according to the numeric encoding consensus
// rules, is an empty array.
func opcodeFalse(op *txsparser.ParsedOpcode, vm *Engine) error {
	vm.dstack.PushByteArray(nil)
	return nil
}

// opcodePushData is a common handler for the vast majority of opcodes that push
// raw data (bytes) to the data stack.
func opcodePushData(op *txsparser.ParsedOpcode, vm *Engine) error {
	vm.dstack.PushByteArray(op.Data)
	return nil
}

// opcode1Negate pushes -1, encoded as a number, to the data stack.
func opcode1Negate(op *txsparser.ParsedOpcode, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(-1))
	return nil
}

// opcodeN is a common handler for the small integer data push opcodes.  It
// pushes the numeric value the opcode represents (which will be from 1 to 16)
// onto the data stack.
func opcodeN(op *txsparser.ParsedOpcode, vm *Engine) error {
	// The opcodes are all defined consecutively, so the numeric value is
	// the difference.
	vm.dstack.PushInt(scriptNum((op.Opcode.Value - (txsparser.OP_1 - 1))))
	return nil
}

// opcodeNop is a common handler for the NOP family of opcodes.  As the name
// implies it generally does nothing, however, it will return an error when
// the flag to discourage use of NOPs is set for select opcodes.
func opcodeNop(op *txsparser.ParsedOpcode, vm *Engine) error {
	switch op.Opcode.Value {
	case txsparser.OP_NOP1, txsparser.OP_NOP4, txsparser.OP_NOP5,
		txsparser.OP_NOP6, txsparser.OP_NOP7, txsparser.OP_NOP8, txsparser.OP_NOP9, txsparser.OP_NOP10:
		if vm.hasFlag(txsparser.ScriptDiscourageUpgradableNops) {
			str := fmt.Sprintf("OP_NOP%d reserved for soft-fork "+
				"upgrades", op.Opcode.Value-(txsparser.OP_NOP1-1))
			return txsparser.ScriptError(txsparser.ErrDiscourageUpgradableNOPs, str)
		}
	}
	return nil
}

// popIfBool enforces the "minimal if" policy during script execution if the
// particular flag is set.  If so, in order to eliminate an additional source
// of nuisance malleability, post-segwit for version 0 witness programs, we now
// require the following: for OP_IF and OP_NOT_IF, the top stack item MUST
// either be an empty byte slice, or [0x01]. Otherwise, the item at the top of
// the stack will be popped and interpreted as a boolean.
func popIfBool(vm *Engine) (bool, error) {
	// When not in witness execution mode, not executing a v0 witness
	// program, or the minimal if flag isn't set pop the top stack item as
	// a normal bool.
	if !vm.isWitnessVersionActive(0) || !vm.hasFlag(txsparser.ScriptVerifyMinimalIf) {
		return vm.dstack.PopBool()
	}

	// At this point, a v0 witness program is being executed and the minimal
	// if flag is set, so enforce additional constraints on the top stack
	// item.
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return false, err
	}

	// The top element MUST have a length of at least one.
	if len(so) > 1 {
		str := fmt.Sprintf("minimal if is active, top element MUST "+
			"have a length of at least, instead length is %v",
			len(so))
		return false, txsparser.ScriptError(txsparser.ErrMinimalIf, str)
	}

	// Additionally, if the length is one, then the value MUST be 0x01.
	if len(so) == 1 && so[0] != 0x01 {
		str := fmt.Sprintf("minimal if is active, top stack item MUST "+
			"be an empty byte array or 0x01, is instead: %v",
			so[0])
		return false, txsparser.ScriptError(txsparser.ErrMinimalIf, str)
	}

	return asBool(so), nil
}

// opcodeIf treats the top item on the data stack as a boolean and removes it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is true, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> if [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeIf(op *txsparser.ParsedOpcode, vm *Engine) error {
	condVal := txsparser.OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if ok {
			condVal = txsparser.OpCondTrue
		}
	} else {
		condVal = txsparser.OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeNotIf treats the top item on the data stack as a boolean and removes
// it.
//
// An appropriate entry is added to the conditional stack depending on whether
// the boolean is true and whether this if is on an executing branch in order
// to allow proper execution of further opcodes depending on the conditional
// logic.  When the boolean is false, the first branch will be executed (unless
// this opcode is nested in a non-executed branch).
//
// <expression> notif [statements] [else [statements]] endif
//
// Note that, unlike for all non-conditional opcodes, this is executed even when
// it is on a non-executing branch so proper nesting is maintained.
//
// Data stack transformation: [... bool] -> [...]
// Conditional stack transformation: [...] -> [... OpCondValue]
func opcodeNotIf(op *txsparser.ParsedOpcode, vm *Engine) error {
	condVal := txsparser.OpCondFalse
	if vm.isBranchExecuting() {
		ok, err := popIfBool(vm)
		if err != nil {
			return err
		}

		if !ok {
			condVal = txsparser.OpCondTrue
		}
	} else {
		condVal = txsparser.OpCondSkip
	}
	vm.condStack = append(vm.condStack, condVal)
	return nil
}

// opcodeElse inverts conditional execution for other half of if/else/endif.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [... !OpCondValue]
func opcodeElse(op *txsparser.ParsedOpcode, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.Opcode.Name)
		return txsparser.ScriptError(txsparser.ErrUnbalancedConditional, str)
	}

	conditionalIdx := len(vm.condStack) - 1
	switch vm.condStack[conditionalIdx] {
	case txsparser.OpCondTrue:
		vm.condStack[conditionalIdx] = txsparser.OpCondFalse
	case txsparser.OpCondFalse:
		vm.condStack[conditionalIdx] = txsparser.OpCondTrue
	case txsparser.OpCondSkip:
		// Value doesn't change in skip since it indicates this opcode
		// is nested in a non-executed branch.
	}
	return nil
}

// opcodeEndif terminates a conditional block, removing the value from the
// conditional execution stack.
//
// An error is returned if there has not already been a matching OP_IF.
//
// Conditional stack transformation: [... OpCondValue] -> [...]
func opcodeEndif(op *txsparser.ParsedOpcode, vm *Engine) error {
	if len(vm.condStack) == 0 {
		str := fmt.Sprintf("encountered opcode %s with no matching "+
			"opcode to begin conditional execution", op.Opcode.Name)
		return txsparser.ScriptError(txsparser.ErrUnbalancedConditional, str)
	}

	vm.condStack = vm.condStack[:len(vm.condStack)-1]
	return nil
}

// abstractVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned either when there is no
// item on the stack or when that item evaluates to false.  In the latter case
// where the verification fails specifically due to the top item evaluating
// to false, the returned error will use the passed error code.
func abstractVerify(op *txsparser.ParsedOpcode, vm *Engine, c txsparser.ErrorCode) error {
	verified, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}

	if !verified {
		str := fmt.Sprintf("%s failed", op.Opcode.Name)
		return txsparser.ScriptError(c, str)
	}
	return nil
}

// opcodeVerify examines the top item on the data stack as a boolean value and
// verifies it evaluates to true.  An error is returned if it does not.
func opcodeVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	return abstractVerify(op, vm, txsparser.ErrVerify)
}

// opcodeReturn returns an appropriate error since it is always an error to
// return early from a script.
func opcodeReturn(op *txsparser.ParsedOpcode, vm *Engine) error {
	return txsparser.ScriptError(txsparser.ErrEarlyReturn, "script returned early")
}

// verifyLockTime is a helper function used to validate locktimes.
func verifyLockTime(txLockTime, threshold, lockTime int64) error {
	// The lockTimes in both the script and transaction must be of the same
	// type.
	if !((txLockTime < threshold && lockTime < threshold) ||
		(txLockTime >= threshold && lockTime >= threshold)) {
		str := fmt.Sprintf("mismatched locktime types -- tx locktime "+
			"%d, stack locktime %d", txLockTime, lockTime)
		return txsparser.ScriptError(txsparser.ErrUnsatisfiedLockTime, str)
	}

	if lockTime > txLockTime {
		str := fmt.Sprintf("locktime requirement not satisfied -- "+
			"locktime is greater than the transaction locktime: "+
			"%d > %d", lockTime, txLockTime)
		return txsparser.ScriptError(txsparser.ErrUnsatisfiedLockTime, str)
	}

	return nil
}

// opcodeCheckLockTimeVerify compares the top item on the data stack to the
// LockTime field of the transaction containing the script signature
// validating if the transaction outputs are spendable yet.  If flag
// ScriptVerifyCheckLockTimeVerify is not set, the code continues as if OP_NOP2
// were executed.
func opcodeCheckLockTimeVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	// If the ScriptVerifyCheckLockTimeVerify script flag is not set, treat
	// opcode as OP_NOP2 instead.
	if !vm.hasFlag(txsparser.ScriptVerifyCheckLockTimeVerify) {
		if vm.hasFlag(txsparser.ScriptDiscourageUpgradableNops) {
			return txsparser.ScriptError(txsparser.ErrDiscourageUpgradableNOPs,
				"OP_NOP2 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction locktime is a uint32 resulting in a maximum
	// locktime of 2^32-1 (the year 2106).  However, scriptNums are signed
	// and therefore a standard 4-byte scriptNum would only support up to a
	// maximum of 2^31-1 (the year 2038).  Thus, a 5-byte scriptNum is used
	// here since it will support up to 2^39-1 which allows dates beyond the
	// current locktime limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	lockTime, err := makeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKLOCKTIMEVERIFY.
	if lockTime < 0 {
		str := fmt.Sprintf("negative lock time: %d", lockTime)
		return txsparser.ScriptError(txsparser.ErrNegativeLockTime, str)
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the txscript.LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	err = verifyLockTime(int64(vm.tx.LockTime), LockTimeThreshold,
		int64(lockTime))
	if err != nil {
		return err
	}

	// The lock time feature can also be disabled, thereby bypassing
	// OP_CHECKLOCKTIMEVERIFY, if every transaction input has been finalized by
	// setting its sequence to the maximum value (wire.MaxTxInSequenceNum).  This
	// condition would result in the transaction being allowed into the blockchain
	// making the opcode ineffective.
	//
	// This condition is prevented by enforcing that the input being used by
	// the opcode is unlocked (its sequence number is less than the max
	// value).  This is sufficient to prove correctness without having to
	// check every input.
	//
	// NOTE: This implies that even if the transaction is not finalized due to
	// another input being unlocked, the opcode execution will still fail when the
	// input being used by the opcode is locked.
	if vm.tx.TxIn[vm.txIdx].Sequence == wire.MaxTxInSequenceNum {
		return txsparser.ScriptError(txsparser.ErrUnsatisfiedLockTime,
			"transaction input is finalized")
	}

	return nil
}

// opcodeCheckSequenceVerify compares the top item on the data stack to the
// LockTime field of the transaction containing the script signature
// validating if the transaction outputs are spendable yet.  If flag
// ScriptVerifyCheckSequenceVerify is not set, the code continues as if OP_NOP3
// were executed.
func opcodeCheckSequenceVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	// If the ScriptVerifyCheckSequenceVerify script flag is not set, treat
	// opcode as OP_NOP3 instead.
	if !vm.hasFlag(txsparser.ScriptVerifyCheckSequenceVerify) {
		if vm.hasFlag(txsparser.ScriptDiscourageUpgradableNops) {
			return txsparser.ScriptError(txsparser.ErrDiscourageUpgradableNOPs,
				"OP_NOP3 reserved for soft-fork upgrades")
		}
		return nil
	}

	// The current transaction sequence is a uint32 resulting in a maximum
	// sequence of 2^32-1.  However, scriptNums are signed and therefore a
	// standard 4-byte scriptNum would only support up to a maximum of
	// 2^31-1.  Thus, a 5-byte scriptNum is used here since it will support
	// up to 2^39-1 which allows sequences beyond the current sequence
	// limit.
	//
	// PeekByteArray is used here instead of PeekInt because we do not want
	// to be limited to a 4-byte integer for reasons specified above.
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}
	stackSequence, err := makeScriptNum(so, vm.dstack.verifyMinimalData, 5)
	if err != nil {
		return err
	}

	// In the rare event that the argument needs to be < 0 due to some
	// arithmetic being done first, you can always use
	// 0 OP_MAX OP_CHECKSEQUENCEVERIFY.
	if stackSequence < 0 {
		str := fmt.Sprintf("negative sequence: %d", stackSequence)
		return txsparser.ScriptError(txsparser.ErrNegativeLockTime, str)
	}

	sequence := int64(stackSequence)

	// To provide for future soft-fork extensibility, if the
	// operand has the disabled lock-time flag set,
	// CHECKSEQUENCEVERIFY behaves as a NOP.
	if sequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		return nil
	}

	// Transaction version numbers not high enough to trigger CSV rules must
	// fail.
	if vm.tx.Version < 2 {
		str := fmt.Sprintf("invalid transaction version: %d",
			vm.tx.Version)
		return txsparser.ScriptError(txsparser.ErrUnsatisfiedLockTime, str)
	}

	// Sequence numbers with their most significant bit set are not
	// consensus constrained. Testing that the transaction's sequence
	// number does not have this bit set prevents using this property
	// to get around a CHECKSEQUENCEVERIFY check.
	txSequence := int64(vm.tx.TxIn[vm.txIdx].Sequence)
	if txSequence&int64(wire.SequenceLockTimeDisabled) != 0 {
		str := fmt.Sprintf("transaction sequence has sequence "+
			"locktime disabled bit set: 0x%x", txSequence)
		return txsparser.ScriptError(txsparser.ErrUnsatisfiedLockTime, str)
	}

	// Mask off non-consensus bits before doing comparisons.
	lockTimeMask := int64(wire.SequenceLockTimeIsSeconds |
		wire.SequenceLockTimeMask)
	return verifyLockTime(txSequence&lockTimeMask,
		wire.SequenceLockTimeIsSeconds, sequence&lockTimeMask)
}

// opcodeToAltStack removes the top item from the main data stack and pushes it
// onto the alternate data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2 y3 x3]
func opcodeToAltStack(op *txsparser.ParsedOpcode, vm *Engine) error {
	so, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	vm.astack.PushByteArray(so)

	return nil
}

// opcodeFromAltStack removes the top item from the alternate data stack and
// pushes it onto the main data stack.
//
// Main data stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 y3]
// Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2]
func opcodeFromAltStack(op *txsparser.ParsedOpcode, vm *Engine) error {
	so, err := vm.astack.PopByteArray()
	if err != nil {
		return err
	}
	vm.dstack.PushByteArray(so)

	return nil
}

// opcode2Drop removes the top 2 items from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1]
func opcode2Drop(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.DropN(2)
}

// opcode2Dup duplicates the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2 x3]
func opcode2Dup(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.DupN(2)
}

// opcode3Dup duplicates the top 3 items on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x1 x2 x3]
func opcode3Dup(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.DupN(3)
}

// opcode2Over duplicates the 2 items before the top 2 items on the data stack.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
func opcode2Over(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.OverN(2)
}

// opcode2Rot rotates the top 6 items on the data stack to the left twice.
//
// Stack transformation: [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
func opcode2Rot(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.RotN(2)
}

// opcode2Swap swaps the top 2 items on the data stack with the 2 that come
// before them.
//
// Stack transformation: [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
func opcode2Swap(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.SwapN(2)
}

// opcodeIfDup duplicates the top item of the stack if it is not zero.
//
// Stack transformation (x1==0): [... x1] -> [... x1]
// Stack transformation (x1!=0): [... x1] -> [... x1 x1]
func opcodeIfDup(op *txsparser.ParsedOpcode, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	// Push copy of data iff it isn't zero
	if asBool(so) {
		vm.dstack.PushByteArray(so)
	}

	return nil
}

// opcodeDepth pushes the depth of the data stack prior to executing this
// opcode, encoded as a number, onto the data stack.
//
// Stack transformation: [...] -> [... <num of items on the stack>]
// Example with 2 items: [x1 x2] -> [x1 x2 2]
// Example with 3 items: [x1 x2 x3] -> [x1 x2 x3 3]
func opcodeDepth(op *txsparser.ParsedOpcode, vm *Engine) error {
	vm.dstack.PushInt(scriptNum(vm.dstack.Depth()))
	return nil
}

// opcodeDrop removes the top item from the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2]
func opcodeDrop(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.DropN(1)
}

// opcodeDup duplicates the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x3]
func opcodeDup(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.DupN(1)
}

// opcodeNip removes the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x3]
func opcodeNip(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.NipN(1)
}

// opcodeOver duplicates the item before the top item on the data stack.
//
// Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2]
func opcodeOver(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.OverN(1)
}

// opcodePick treats the top item on the data stack as an integer and duplicates
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [xn ... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x1 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x2 x1 x0 x2]
func opcodePick(op *txsparser.ParsedOpcode, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.PickN(val.Int32())
}

// opcodeRoll treats the top item on the data stack as an integer and moves
// the item on the stack that number of items back to the top.
//
// Stack transformation: [xn ... x2 x1 x0 n] -> [... x2 x1 x0 xn]
// Example with n=1: [x2 x1 x0 1] -> [x2 x0 x1]
// Example with n=2: [x2 x1 x0 2] -> [x1 x0 x2]
func opcodeRoll(op *txsparser.ParsedOpcode, vm *Engine) error {
	val, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	return vm.dstack.RollN(val.Int32())
}

// opcodeRot rotates the top 3 items on the data stack to the left.
//
// Stack transformation: [... x1 x2 x3] -> [... x2 x3 x1]
func opcodeRot(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.RotN(1)
}

// opcodeSwap swaps the top two items on the stack.
//
// Stack transformation: [... x1 x2] -> [... x2 x1]
func opcodeSwap(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.SwapN(1)
}

// opcodeTuck inserts a duplicate of the top item of the data stack before the
// second-to-top item.
//
// Stack transformation: [... x1 x2] -> [... x2 x1 x2]
func opcodeTuck(op *txsparser.ParsedOpcode, vm *Engine) error {
	return vm.dstack.Tuck()
}

// opcodeSize pushes the size of the top item of the data stack onto the data
// stack.
//
// Stack transformation: [... x1] -> [... x1 len(x1)]
func opcodeSize(op *txsparser.ParsedOpcode, vm *Engine) error {
	so, err := vm.dstack.PeekByteArray(0)
	if err != nil {
		return err
	}

	vm.dstack.PushInt(scriptNum(len(so)))
	return nil
}

// opcodeEqual removes the top 2 items of the data stack, compares them as raw
// bytes, and pushes the result, encoded as a boolean, back to the stack.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	a, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}
	b, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushBool(bytes.Equal(a, b))
	return nil
}

// opcodeEqualVerify is a combination of opcodeEqual and opcodeVerify.
// Specifically, it removes the top 2 items of the data stack, compares them,
// and pushes the result, encoded as a boolean, back to the stack.  Then, it
// examines the top item on the data stack as a boolean value and verifies it
// evaluates to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeEqualVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	err := opcodeEqual(op, vm)
	if err == nil {
		err = abstractVerify(op, vm, txsparser.ErrEqualVerify)
	}
	return err
}

// opcode1Add treats the top item on the data stack as an integer and replaces
// it with its incremented value (plus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2+1]
func opcode1Add(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(m + 1)
	return nil
}

// opcode1Sub treats the top item on the data stack as an integer and replaces
// it with its decremented value (minus 1).
//
// Stack transformation: [... x1 x2] -> [... x1 x2-1]
func opcode1Sub(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	vm.dstack.PushInt(m - 1)

	return nil
}

// opcodeNegate treats the top item on the data stack as an integer and replaces
// it with its negation.
//
// Stack transformation: [... x1 x2] -> [... x1 -x2]
func opcodeNegate(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(-m)
	return nil
}

// opcodeAbs treats the top item on the data stack as an integer and replaces it
// it with its absolute value.
//
// Stack transformation: [... x1 x2] -> [... x1 abs(x2)]
func opcodeAbs(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m < 0 {
		m = -m
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeNot treats the top item on the data stack as an integer and replaces
// it with its "inverted" value (0 becomes 1, non-zero becomes 0).
//
// NOTE: While it would probably make more sense to treat the top item as a
// boolean, and push the opposite, which is really what the intention of this
// opcode is, it is extremely important that is not done because integers are
// interpreted differently than booleans and the consensus rules for this opcode
// dictate the item is interpreted as an integer.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 0]
func opcodeNot(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m == 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcode0NotEqual treats the top item on the data stack as an integer and
// replaces it with either a 0 if it is zero, or a 1 if it is not zero.
//
// Stack transformation (x2==0): [... x1 0] -> [... x1 0]
// Stack transformation (x2!=0): [... x1 1] -> [... x1 1]
// Stack transformation (x2!=0): [... x1 17] -> [... x1 1]
func opcode0NotEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	m, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if m != 0 {
		m = 1
	}
	vm.dstack.PushInt(m)
	return nil
}

// opcodeAdd treats the top two items on the data stack as integers and replaces
// them with their sum.
//
// Stack transformation: [... x1 x2] -> [... x1+x2]
func opcodeAdd(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v0 + v1)
	return nil
}

// opcodeSub treats the top two items on the data stack as integers and replaces
// them with the result of subtracting the top entry from the second-to-top
// entry.
//
// Stack transformation: [... x1 x2] -> [... x1-x2]
func opcodeSub(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	vm.dstack.PushInt(v1 - v0)
	return nil
}

// opcodeBoolAnd treats the top two items on the data stack as integers.  When
// both of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 0]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 0]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolAnd(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 && v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeBoolOr treats the top two items on the data stack as integers.  When
// either of them are not zero, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
// Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 1]
// Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 1]
// Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
func opcodeBoolOr(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != 0 || v1 != 0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqual treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 1]
// Stack transformation (x1!=x2): [... 5 7] -> [... 0]
func opcodeNumEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 == v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeNumEqualVerify is a combination of opcodeNumEqual and opcodeVerify.
//
// Specifically, treats the top two items on the data stack as integers.  When
// they are equal, they are replaced with a 1, otherwise a 0.  Then, it examines
// the top item on the data stack as a boolean value and verifies it evaluates
// to true.  An error is returned if it does not.
//
// Stack transformation: [... x1 x2] -> [... bool] -> [...]
func opcodeNumEqualVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	err := opcodeNumEqual(op, vm)
	if err == nil {
		err = abstractVerify(op, vm, txsparser.ErrNumEqualVerify)
	}
	return err
}

// opcodeNumNotEqual treats the top two items on the data stack as integers.
// When they are NOT equal, they are replaced with a 1, otherwise a 0.
//
// Stack transformation (x1==x2): [... 5 5] -> [... 0]
// Stack transformation (x1!=x2): [... 5 7] -> [... 1]
func opcodeNumNotEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v0 != v1 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeLessThan treats the top two items on the data stack as integers.  When
// the second-to-top item is less than the top item, they are replaced with a 1,
// otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThan(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeGreaterThan treats the top two items on the data stack as integers.
// When the second-to-top item is greater than the top item, they are replaced
// with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThan(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeLessThanOrEqual treats the top two items on the data stack as integers.
// When the second-to-top item is less than or equal to the top item, they are
// replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeLessThanOrEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 <= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// opcodeGreaterThanOrEqual treats the top two items on the data stack as
// integers.  When the second-to-top item is greater than or equal to the top
// item, they are replaced with a 1, otherwise a 0.
//
// Stack transformation: [... x1 x2] -> [... bool]
func opcodeGreaterThanOrEqual(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 >= v0 {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}

	return nil
}

// opcodeMin treats the top two items on the data stack as integers and replaces
// them with the minimum of the two.
//
// Stack transformation: [... x1 x2] -> [... min(x1, x2)]
func opcodeMin(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 < v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeMax treats the top two items on the data stack as integers and replaces
// them with the maximum of the two.
//
// Stack transformation: [... x1 x2] -> [... max(x1, x2)]
func opcodeMax(op *txsparser.ParsedOpcode, vm *Engine) error {
	v0, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	v1, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if v1 > v0 {
		vm.dstack.PushInt(v1)
	} else {
		vm.dstack.PushInt(v0)
	}

	return nil
}

// opcodeWithin treats the top 3 items on the data stack as integers.  When the
// value to test is within the specified range (left inclusive), they are
// replaced with a 1, otherwise a 0.
//
// The top item is the max value, the second-top-item is the minimum value, and
// the third-to-top item is the value to test.
//
// Stack transformation: [... x1 min max] -> [... bool]
func opcodeWithin(op *txsparser.ParsedOpcode, vm *Engine) error {
	maxVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	minVal, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	x, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	if x >= minVal && x < maxVal {
		vm.dstack.PushInt(scriptNum(1))
	} else {
		vm.dstack.PushInt(scriptNum(0))
	}
	return nil
}

// calcHash calculates the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// opcodeRipemd160 treats the top item of the data stack as raw bytes and
// replaces it with ripemd160(data).
//
// Stack transformation: [... x1] -> [... ripemd160(x1)]
func opcodeRipemd160(op *txsparser.ParsedOpcode, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(calcHash(buf, ripemd160.New()))
	return nil
}

// opcodeSha1 treats the top item of the data stack as raw bytes and replaces it
// with sha1(data).
//
// Stack transformation: [... x1] -> [... sha1(x1)]
func opcodeSha1(op *txsparser.ParsedOpcode, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha1.Sum(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeSha256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(data).
//
// Stack transformation: [... x1] -> [... sha256(x1)]
func opcodeSha256(op *txsparser.ParsedOpcode, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(hash[:])
	return nil
}

// opcodeHash160 treats the top item of the data stack as raw bytes and replaces
// it with ripemd160(sha256(data)).
//
// Stack transformation: [... x1] -> [... ripemd160(sha256(x1))]
func opcodeHash160(op *txsparser.ParsedOpcode, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(buf)
	vm.dstack.PushByteArray(calcHash(hash[:], ripemd160.New()))
	return nil
}

// opcodeHash256 treats the top item of the data stack as raw bytes and replaces
// it with sha256(sha256(data)).
//
// Stack transformation: [... x1] -> [... sha256(sha256(x1))]
func opcodeHash256(op *txsparser.ParsedOpcode, vm *Engine) error {
	buf, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	vm.dstack.PushByteArray(chainhash.DoubleHashB(buf))
	return nil
}

// opcodeCodeSeparator stores the current script offset as the most recently
// seen OP_CODESEPARATOR which is used during signature checking.
//
// This opcode does not change the contents of the data stack.
func opcodeCodeSeparator(op *txsparser.ParsedOpcode, vm *Engine) error {
	vm.lastCodeSep = vm.scriptOff
	return nil
}

// opcodeCheckSig treats the top 2 items on the stack as a public key and a
// signature and replaces them with a bool which indicates if the signature was
// successfully verified.
//
// The process of verifying a signature requires calculating a signature hash in
// the same way the transaction signer did.  It involves hashing portions of the
// transaction based on the hash type byte (which is the final byte of the
// signature) and the portion of the script starting from the most recent
// OP_CODESEPARATOR (or the beginning of the script if there are none) to the
// end of the script (with any other OP_CODESEPARATORs removed).  Once this
// "script hash" is calculated, the signature is checked using standard
// cryptographic methods against the provided public key.
//
// Stack transformation: [... signature pubkey] -> [... bool]
func opcodeCheckSig(op *txsparser.ParsedOpcode, vm *Engine) error {
	pkBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	fullSigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// The signature actually needs needs to be longer than this, but at
	// least 1 byte is needed for the hash type below.  The full length is
	// checked depending on the script flags and upon parsing the signature.
	if len(fullSigBytes) < 1 {
		vm.dstack.PushBool(false)
		return nil
	}

	// Trim off hashtype from the signature string and check if the
	// signature and pubkey conform to the strict encoding requirements
	// depending on the flags.
	//
	// NOTE: When the strict encoding flags are set, any errors in the
	// signature or public encoding here result in an immediate script error
	// (and thus no result bool is pushed to the data stack).  This differs
	// from the logic below where any errors in parsing the signature is
	// treated as the signature failure resulting in false being pushed to
	// the data stack.  This is required because the more general script
	// validation consensus rules do not have the new strict encoding
	// requirements enabled by the flags.
	hashType := SigHashType(fullSigBytes[len(fullSigBytes)-1])
	sigBytes := fullSigBytes[:len(fullSigBytes)-1]
	if err := vm.checkHashTypeEncoding(hashType); err != nil {
		return err
	}
	if err := vm.checkSignatureEncoding(sigBytes); err != nil {
		return err
	}
	if err := vm.checkPubKeyEncoding(pkBytes); err != nil {
		return err
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	subScript := vm.subScript()

	// Generate the signature hash based on the signature hash type.
	var hash []byte
	if vm.isWitnessVersionActive(0) {
		var sigHashes *TxSigHashes
		if vm.hashCache != nil {
			sigHashes = vm.hashCache
		} else {
			sigHashes = NewTxSigHashes(&vm.tx)
		}

		hash, err = calcWitnessSignatureHash(scriptInfo2parsedOpcode(subScript), sigHashes, hashType,
			&vm.tx, vm.txIdx, vm.inputAmount)
		if err != nil {
			return err
		}
	} else {
		// Remove the signature since there is no way for a signature
		// to sign itself.
		subScript := scriptRemoveOpcodeByData(subScript, fullSigBytes)

		hash = calcSignatureHash(scriptInfo2parsedOpcode(subScript), hashType, &vm.tx, vm.txIdx)
	}

	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	var signature *btcec.Signature
	if vm.hasFlag(txsparser.ScriptVerifyStrictEncoding) ||
		vm.hasFlag(txsparser.ScriptVerifyDERSignatures) {

		signature, err = btcec.ParseDERSignature(sigBytes, btcec.S256())
	} else {
		signature, err = btcec.ParseSignature(sigBytes, btcec.S256())
	}
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	var valid bool
	if vm.sigCache != nil {
		var sigHash chainhash.Hash
		copy(sigHash[:], hash)

		valid = vm.sigCache.Exists(sigHash, signature, pubKey)
		if !valid && signature.Verify(hash, pubKey) {
			vm.sigCache.Add(sigHash, signature, pubKey)
			valid = true
		}
	} else {
		valid = signature.Verify(hash, pubKey)
	}

	if !valid && vm.hasFlag(txsparser.ScriptVerifyNullFail) && len(sigBytes) > 0 {
		str := "signature not empty on failed checksig"
		return txsparser.ScriptError(txsparser.ErrNullFail, str)
	}

	vm.dstack.PushBool(valid)
	return nil
}

// opcodeCheckSigVerify is a combination of opcodeCheckSig and opcodeVerify.
// The opcodeCheckSig function is invoked followed by opcodeVerify.  See the
// documentation for each of those opcodes for more details.
//
// Stack transformation: signature pubkey] -> [... bool] -> [...]
func opcodeCheckSigVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	err := opcodeCheckSig(op, vm)
	if err == nil {
		err = abstractVerify(op, vm, txsparser.ErrCheckSigVerify)
	}
	return err
}

// parsedSigInfo houses a raw signature along with its parsed form and a flag
// for whether or not it has already been parsed.  It is used to prevent parsing
// the same signature multiple times when verifying a multisig.
type parsedSigInfo struct {
	signature       []byte
	parsedSignature *btcec.Signature
	parsed          bool
}

// opcodeCheckMultiSig treats the top item on the stack as an integer number of
// public keys, followed by that many entries as raw data representing the public
// keys, followed by the integer number of signatures, followed by that many
// entries as raw data representing the signatures.
//
// Due to a bug in the original Satoshi client implementation, an additional
// dummy argument is also required by the consensus rules, although it is not
// used.  The dummy value SHOULD be an OP_0, although that is not required by
// the consensus rules.  When the ScriptStrictMultiSig flag is set, it must be
// OP_0.
//
// All of the aforementioned stack items are replaced with a bool which
// indicates if the requisite number of signatures were successfully verified.
//
// See the opcodeCheckSigVerify documentation for more details about the process
// for verifying each signature.
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool]
func opcodeCheckMultiSig(op *txsparser.ParsedOpcode, vm *Engine) error {
	numKeys, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}

	numPubKeys := int(numKeys.Int32())
	if numPubKeys < 0 {
		str := fmt.Sprintf("number of pubkeys %d is negative",
			numPubKeys)
		return txsparser.ScriptError(txsparser.ErrInvalidPubKeyCount, str)
	}
	if numPubKeys > MaxPubKeysPerMultiSig {
		str := fmt.Sprintf("too many pubkeys: %d > %d",
			numPubKeys, MaxPubKeysPerMultiSig)
		return txsparser.ScriptError(txsparser.ErrInvalidPubKeyCount, str)
	}
	vm.numOps += numPubKeys
	if vm.numOps > MaxOpsPerScript {
		str := fmt.Sprintf("exceeded max operation limit of %d",
			MaxOpsPerScript)
		return txsparser.ScriptError(txsparser.ErrTooManyOperations, str)
	}

	pubKeys := make([][]byte, 0, numPubKeys)
	for i := 0; i < numPubKeys; i++ {
		pubKey, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	numSigs, err := vm.dstack.PopInt()
	if err != nil {
		return err
	}
	numSignatures := int(numSigs.Int32())
	if numSignatures < 0 {
		str := fmt.Sprintf("number of signatures %d is negative",
			numSignatures)
		return txsparser.ScriptError(txsparser.ErrInvalidSignatureCount, str)

	}
	if numSignatures > numPubKeys {
		str := fmt.Sprintf("more signatures than pubkeys: %d > %d",
			numSignatures, numPubKeys)
		return txsparser.ScriptError(txsparser.ErrInvalidSignatureCount, str)
	}

	signatures := make([]*parsedSigInfo, 0, numSignatures)
	for i := 0; i < numSignatures; i++ {
		signature, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		sigInfo := &parsedSigInfo{signature: signature}
		signatures = append(signatures, sigInfo)
	}

	// A bug in the original Satoshi client implementation means one more
	// stack value than should be used must be popped.  Unfortunately, this
	// buggy behavior is now part of the consensus and a hard fork would be
	// required to fix it.
	dummy, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Since the dummy argument is otherwise not checked, it could be any
	// value which unfortunately provides a source of malleability.  Thus,
	// there is a script flag to force an error when the value is NOT 0.
	if vm.hasFlag(txsparser.ScriptStrictMultiSig) && len(dummy) != 0 {
		str := fmt.Sprintf("multisig dummy argument has length %d "+
			"instead of 0", len(dummy))
		return txsparser.ScriptError(txsparser.ErrSigNullDummy, str)
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	script := vm.subScript()

	// Remove the signature in pre version 0 segwit scripts since there is
	// no way for a signature to sign itself.
	if !vm.isWitnessVersionActive(0) {
		for _, sigInfo := range signatures {
			script = scriptRemoveOpcodeByData(script, sigInfo.signature)
		}
	}

	success := true
	numPubKeys++
	pubKeyIdx := -1
	signatureIdx := 0
	for numSignatures > 0 {
		// When there are more signatures than public keys remaining,
		// there is no way to succeed since too many signatures are
		// invalid, so exit early.
		pubKeyIdx++
		numPubKeys--
		if numSignatures > numPubKeys {
			success = false
			break
		}

		sigInfo := signatures[signatureIdx]
		pubKey := pubKeys[pubKeyIdx]

		// The order of the signature and public key evaluation is
		// important here since it can be distinguished by an
		// OP_CHECKMULTISIG NOT when the strict encoding flag is set.

		rawSig := sigInfo.signature
		if len(rawSig) == 0 {
			// Skip to the next pubkey if signature is empty.
			continue
		}

		// Split the signature into hash type and signature components.
		hashType := SigHashType(rawSig[len(rawSig)-1])
		signature := rawSig[:len(rawSig)-1]

		// Only parse and check the signature encoding once.
		var parsedSig *btcec.Signature
		if !sigInfo.parsed {
			if err := vm.checkHashTypeEncoding(hashType); err != nil {
				return err
			}
			if err := vm.checkSignatureEncoding(signature); err != nil {
				return err
			}

			// Parse the signature.
			var err error
			if vm.hasFlag(txsparser.ScriptVerifyStrictEncoding) ||
				vm.hasFlag(txsparser.ScriptVerifyDERSignatures) {

				parsedSig, err = btcec.ParseDERSignature(signature,
					btcec.S256())
			} else {
				parsedSig, err = btcec.ParseSignature(signature,
					btcec.S256())
			}
			sigInfo.parsed = true
			if err != nil {
				continue
			}
			sigInfo.parsedSignature = parsedSig
		} else {
			// Skip to the next pubkey if the signature is invalid.
			if sigInfo.parsedSignature == nil {
				continue
			}

			// Use the already parsed signature.
			parsedSig = sigInfo.parsedSignature
		}

		if err := vm.checkPubKeyEncoding(pubKey); err != nil {
			return err
		}

		// Parse the pubkey.
		parsedPubKey, err := btcec.ParsePubKey(pubKey, btcec.S256())
		if err != nil {
			continue
		}

		// Generate the signature hash based on the signature hash type.
		var hash []byte
		if vm.isWitnessVersionActive(0) {
			var sigHashes *TxSigHashes
			if vm.hashCache != nil {
				sigHashes = vm.hashCache
			} else {
				sigHashes = NewTxSigHashes(&vm.tx)
			}

			hash, err = calcWitnessSignatureHash(scriptInfo2parsedOpcode(script), sigHashes, hashType,
				&vm.tx, vm.txIdx, vm.inputAmount)
			if err != nil {
				return err
			}
		} else {
			hash = calcSignatureHash(scriptInfo2parsedOpcode(script), hashType, &vm.tx, vm.txIdx)
		}

		var valid bool
		if vm.sigCache != nil {
			var sigHash chainhash.Hash
			copy(sigHash[:], hash)

			valid = vm.sigCache.Exists(sigHash, parsedSig, parsedPubKey)
			if !valid && parsedSig.Verify(hash, parsedPubKey) {
				vm.sigCache.Add(sigHash, parsedSig, parsedPubKey)
				valid = true
			}
		} else {
			valid = parsedSig.Verify(hash, parsedPubKey)
		}

		if valid {
			// PubKey verified, move on to the next signature.
			signatureIdx++
			numSignatures--
		}
	}

	if !success && vm.hasFlag(txsparser.ScriptVerifyNullFail) {
		for _, sig := range signatures {
			if len(sig.signature) > 0 {
				str := "not all signatures empty on failed checkmultisig"
				return txsparser.ScriptError(txsparser.ErrNullFail, str)
			}
		}
	}

	vm.dstack.PushBool(success)
	return nil
}

// opcodeCheckMultiSigVerify is a combination of opcodeCheckMultiSig and
// opcodeVerify.  The opcodeCheckMultiSig is invoked followed by opcodeVerify.
// See the documentation for each of those opcodes for more details.
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool] -> [...]
func opcodeCheckMultiSigVerify(op *txsparser.ParsedOpcode, vm *Engine) error {
	err := opcodeCheckMultiSig(op, vm)
	if err == nil {
		err = abstractVerify(op, vm, txsparser.ErrCheckMultiSigVerify)
	}
	return err
}

// OpcodeByName is a map that can be used to lookup an opcode by its
// human-readable name (OP_CHECKMULTISIG, OP_CHECKSIG, etc).
var OpcodeByName = make(map[string]byte)

func init() {
	// Initialize the opcode name to value map using the contents of the
	// opcode array.  Also add entries for "OP_FALSE", "OP_TRUE", and
	// "OP_NOP2" since they are aliases for "OP_0", "OP_1",
	// and "OP_CHECKLOCKTIMEVERIFY" respectively.
	for _, op := range txsparser.OpCodeArray {
		OpcodeByName[op.Name] = op.Value
	}
	OpcodeByName["OP_FALSE"] = txsparser.OP_FALSE
	OpcodeByName["OP_TRUE"] = txsparser.OP_TRUE
	OpcodeByName["OP_NOP2"] = txsparser.OP_CHECKLOCKTIMEVERIFY
	OpcodeByName["OP_NOP3"] = txsparser.OP_CHECKSEQUENCEVERIFY
}
