/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"encoding/hex"
	"fmt"
	"github.com/omegasuite/omega"

	//	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/omega/token"
	"math/big"
)

const (
	NOWRITE    = 0x1
	NOSPENDING = 0x2
	NOOUTPUT   = 0x4
	NODEFINE   = 0x8
	NOMINT     = 0x10

	INHERIT     = 0x20

	PUREMASK = 0x3F
)

type Address [20]byte

func (d Address) Big() * big.Int {
	z := big.NewInt(0)
	z.SetBytes(d[:])
	return z
}

func AddressFromString(src string) (Address, error) {
	// Return error if hash string is too long.
	if len(src) > 40 {
		return Address{}, fmt.Errorf("Address Src is too long")
	}

	// Hex decoder expects the hash to be a multiple of two.  When not, pad
	// with a leading zero.
	var srcBytes []byte
	if len(src)%2 == 0 {
		srcBytes = []byte(src)
	} else {
		srcBytes = make([]byte, 1+len(src))
		srcBytes[0] = '0'
		copy(srcBytes[1:], src)
	}

	// Hex decode the source bytes to a temporary destination.
	var addr Address
	_, err := hex.Decode(addr[:], srcBytes)
	if err != nil {
		return Address{}, err
	}

	return addr, nil
}

// ContractRef is a reference to the contract's backing object
type ContractRef interface {
	Address() Address
}

// AccountRef implements ContractRef.
//
// Account references are used during EVM initialisation and
// it's primary use is to fetch addresses. Removing this object
// proves difficult because of the cached jump destinations which
// are fetched from the parent contract (i.e. the caller), which
// is a ContractRef.
type AccountRef Address

// Address casts AccountRef to a Address
func (ar AccountRef) Address() Address { return (Address)(ar) }

type inst struct {
	op OpCode
	param []byte
}

func (s * inst) Op() OpCode { return s.op }
func (s * inst) Param() []byte { return s.param }

type lib struct{
	address int32		// code address
	end int32			// code end
	base int32			// lib global Data
	pure byte
}

// Contract represents an contract in the state database. It contains
// the the contract code, calling arguments. Contract implements ContractRef
type Contract struct {
	self          ContractRef
	isnew	bool

	libs map[Address]lib

	Code     []inst
//	CodeHash chainhash.Hash
	CodeAddr []byte				// precompiled code. 4-byte ABI func code. code 0-255 reserved for sys call
	Input    []byte

	pure byte

	value *token.Token
	Args []byte
}

// NewContract returns a new contract environment for the execution of EVM.
func NewContract(object Address, value *token.Token) *Contract {
	c := &Contract{
		self: AccountRef(object),
		isnew: true,
		Args: nil,
		libs:	make(map[Address]lib),
//		jumpdests: make(destinations),
		value: value,
	}
	return c
}

// GetOp returns the n'th element in the contract's byte array
func (c *Contract) GetOp(n int) OpCode {
	return OpCode(c.GetInst(n).op)
}

func (c *Contract) GetInst(n int) inst {
	if n < len(c.Code) {
		return c.Code[n]
	}

	return inst{0, nil }
}

// GetByte returns the n'th byte in the contract's byte array
func (c *Contract) GetBytes(n int) []byte {
	if n < len(c.Code) {
		return c.Code[n].param
	}

	return nil
}

// Address returns the contracts address
func (c *Contract) Address() Address {
	return c.self.Address()
}

// Value returns the contracts value (sent to it from it's caller)
func (c *Contract) Value() *token.Token {
	return c.value
}

// SetCallCode sets the code of the contract and address of the backing Data
// object
func (self *Contract) SetCallCode(addr []byte, code []byte) omega.Err {
	if code == nil {
		err := omega.ScriptError(omega.ErrInternal, "code not found")
		err.ErrorLevel = omega.RecoverableLevel
		return err
	}
	self.Code = ByteCodeParser(code)
//	self.CodeHash = hash
	self.CodeAddr = addr
	return nil
}

func ByteCodeParser(code []byte) []inst {
	instructions := make([]inst, 0, len(code) / 32)
	var tmp inst
	empty := true
	for i := 0; i < len(code); i++ {
		switch {
		case code[i] == ' ' || code[i] == '\t' || code[i] == '\r':		// skip space or tab

		case code[i] != ';' && code[i] != '\n':	// ";\n":
			if empty {
				tmp.op = OpCode(code[i])
				empty = false
				tmp.param = make([]byte, 0, 32)
			} else {
				tmp.param = append(tmp.param, code[i])
			}

		default:	// ";\n":
			instructions = append(instructions, tmp)
			for ; i < len(code) && code[i] != '\n'; i++ {}
			empty = true
		}
	}
	if !empty {
		instructions = append(instructions, tmp)
	}

	return instructions
}

type codeValidator func ([]byte) int

var validators = map[OpCode]codeValidator {
	EVAL8:  opEval8Validator,
	EVAL16:  opEval16Validator,
	EVAL32:  opEval32Validator,
	EVAL64:  opEval64Validator,
	EVAL256:  opEval256Validator,
	CONV:   opConvValidator,
	HASH:   opHashValidator,
	HASH160:  opHash160Validator,
	SIGCHECK:   opSigCheckValidator,
	IF:  opIfValidator,
	CALL:  opCallValidator,
	EXEC:  opExecValidator,
	LOAD:  opLoadValidator,
	STORE:   opStoreValidator,
	DEL: opDelValidator,
	LIBLOAD:   opLibLoadValidator,
	MALLOC:  opMallocValidator,
	ALLOC:  opAllocValidator,
	COPY: opCopyValidator,
	COPYIMM:  opCopyImmValidator,
	RECEIVED: opReceivedValidator,
	TXFEE: opTxFeeValidator,
	GETCOIN: opGetCoinValidator,
	NOP: func ([]byte) int { return 1},
	TXIOCOUNT:  opTxIOCountValidator,
//	GETTXIN: opGetTxInValidator,
//	GETTXOUT: opGetTxOutValidator,
	SPEND:         opSpendValidator,
	ADDDEF:        opAddDefValidator,
	ADDTXOUT:      opAddTxOutValidator,
	GETDEFINITION: opGetDefinitionValidator,
	GETUTXO:       opGetUtxoValidator,
	SELFDESTRUCT:  opSuicideValidator,
	REVERT:        opRevertValidator,
	STOP:          opStopValidator,
	RETURN:        opReturnValidator,
	MINT:          opMintValidator,
	META:          opMetaValidator,
	TIME:          opTimeValidator,
	HEIGHT: opHeightValidator,
	VERSION: opVersionValidator,
	TOKENCONTRACT: opTokenContractValidator,
	LOG: opLogValidator,
}

func ByteCodeValidator(code []inst) omega.Err {
	for i, c := range code {
		if v, ok := validators[c.op]; ok {
			offset := v(c.param)
			if i+offset < 0 || i+offset > len(code) {
				return omega.ScriptError(omega.ErrInternal,fmt.Sprintf("Illegal instruction %c %s in contract code.", c.op, string(c.param)))
			}
		} else {
			return omega.ScriptError(omega.ErrInternal,fmt.Sprintf("Illegal instruction %c in contract code.", c.op))
		}
	}

	return nil
}