// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ovm

import (
	"math/big"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/omega/token"
)

type Address [20]byte

func (d Address) Big() * big.Int {
	z := big.NewInt(0)
	z.SetBytes(d[:])
	return z
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

// Contract represents an contract in the state database. It contains
// the the contract code, calling arguments. Contract implements ContractRef
type Contract struct {
	self          ContractRef	// contract address = hash160(owner + CodeHash)
								// note: self is 0x000...000 for system contract.

	owner Address				// address of owner. for system contract, owner = 0x000...000
								// contracts with 0 zddress may execute privilege instructions

//	jumpdests destinations		// result of JUMPDEST analysis. privilege instructions are handled here

	Code     []inst
	CodeHash chainhash.Hash
	CodeAddr []byte				// precompiled code. 4-byte ABI func code. code 0-255 reserved for sys call
	Input    []byte

	pure bool

	value *token.Token
	Args []byte
}

// NewContract returns a new contract environment for the execution of EVM.
func NewContract(object Address, value *token.Token) *Contract {
	c := &Contract{
		self: AccountRef(object),
		Args: nil,
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

// SetCallCode sets the code of the contract and address of the backing data
// object
func (self *Contract) SetCallCode(addr []byte, hash chainhash.Hash, code []byte) {
	self.Code = ByteCodeParser(code)
	self.CodeHash = hash
	self.CodeAddr = addr
}

func ByteCodeParser(code []byte) []inst {
	instructions := make([]inst, 0, len(code) / 32)
	var tmp inst
	empty := true
	for i := 0; i < len(code); i++ {
		switch {
		case empty:
			tmp.op = OpCode(code[i])
			empty = false
			tmp.param = make([]byte, 0, 32)

		case code[i] != 0x3b && code[i] != 10:	// ";\n":
			tmp.param = append(tmp.param, code[i])

		case code[i] == 0x3b || code[i] == 10:	// ";\n":
			instructions = append(instructions, tmp)
			if code[i] == 0x3b {
				for ; i < len(code) && code[i] != 10; i++ {}
			}
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
	SIGNTEXT:  opAddSignTextValidator,
	IF:  opIfValidator,
	CALL:  opCallValidator,
	EXEC:  opExecValidator,
	LOAD:  opLoadValidator,
	STORE:   opStoreValidator,
	LIBLOAD:   opLibLoadValidator,
	MALLOC:  opMallocValidator,
	ALLOC:  opAllocValidator,
	COPY: opCopyValidator,
	COPYIMM:  opCopyImmValidator,
	CODECOPY: opCodeCopyValidator,
	RECEIVED: opReceivedValidator,
	TXIOCOUNT:  opTxIOCountValidator,
	GETTXIN: opGetTxInValidator,
	GETTXOUT: opGetTxOutValidator,
	SPEND:  opSpendValidator,
	ADDRIGHTDEF:  opAddRightValidator,
	ADDTXOUT: opAddTxOutValidator,
	GETDEFINITION: opGetDefinitionValidator,
	GETCOIN:  opGetCoinValidator,
	GETUTXO:  opGetUtxoValidator,
	SELFDESTRUCT:  opSuicideValidator,
	REVERT: opRevertValidator,
	STOP: opStopValidator,
	RETURN: opReturnValidator,
}

func ByteCodeValidator(code []inst) bool {
	for i, c := range code {
		offset := validators[c.op](c.param)
		if i + offset < 0 || i + offset >= len(code) {
			return false
		}
	}

	return true
}