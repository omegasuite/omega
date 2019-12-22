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
	"errors"
	"fmt"
	"github.com/btcsuite/omega/viewpoint"
	"math/big"
	"io"

	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"bytes"
	"encoding/binary"
)

var (
	bigZero                  = new(big.Int)
	tt255                    = new(big.Int).Lsh(big.NewInt(2), 255)
	tt256                    = new(big.Int).Lsh(big.NewInt(2), 256)
	tt256m1					 = new(big.Int).Sub(tt256, big.NewInt(1))
	errWriteProtection       = errors.New("evm: write protection")
	errReturnDataOutOfBounds = errors.New("evm: return data out of bounds")
	errExecutionReverted     = errors.New("evm: execution reverted")
	errMaxCodeSizeExceeded   = errors.New("evm: max code size exceeded")
)

const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)

func U256(y *big.Int) *big.Int {
	y.And(y, tt256m1)
	return y
}

func S256(x *big.Int) *big.Int {
	if x.Cmp(tt255) < 0 {
		return x
	} else {
		return new(big.Int).Sub(x, tt256)
	}
}

func Exp(base, exponent *big.Int) *big.Int {
	result := big.NewInt(1)

	for _, word := range exponent.Bits() {
		for i := 0; i < wordBits; i++ {
			if word&1 == 1 {
				U256(result.Mul(result, base))
			}
			U256(base.Mul(base, base))
			word >>= 1
		}
	}
	return result
}

func Byte(bigint *big.Int, padlength, n int) byte {
	if n >= padlength {
		return byte(0)
	}
	return bigEndianByteAt(bigint, padlength-1-n)
}

func bigEndianByteAt(bigint *big.Int, n int) byte {
	words := bigint.Bits()
	// Check word-bucket the byte will reside in
	i := n / wordBytes
	if i >= len(words) {
		return byte(0)
	}
	word := words[i]
	// Offset of the byte
	shift := 8 * uint(n%wordBytes)

	return byte(word >> shift)
}

func opAdd(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	U256(y.Add(x, y))

	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opSub(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	U256(y.Sub(x, y))

	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opMul(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()
	stack.push(U256(x.Mul(x, y)))

	evm.interpreter.intPool.put(y)

	return nil, nil
}

func opDiv(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if y.Sign() != 0 {
		U256(y.Div(x, y))
	} else {
		y.SetUint64(0)
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opSdiv(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := S256(stack.pop()), S256(stack.pop())
	res := evm.interpreter.intPool.getZero()

	if y.Sign() == 0 || x.Sign() == 0 {
		stack.push(res)
	} else {
		if x.Sign() != y.Sign() {
			res.Div(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Div(x.Abs(x), y.Abs(y))
		}
		stack.push(U256(res))
	}
	evm.interpreter.intPool.put(x, y)
	return nil, nil
}

func opMod(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()
	if y.Sign() == 0 {
		stack.push(x.SetUint64(0))
	} else {
		stack.push(U256(x.Mod(x, y)))
	}
	evm.interpreter.intPool.put(y)
	return nil, nil
}

func opSmod(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := S256(stack.pop()), S256(stack.pop())
	res := evm.interpreter.intPool.getZero()

	if y.Sign() == 0 {
		stack.push(res)
	} else {
		if x.Sign() < 0 {
			res.Mod(x.Abs(x), y.Abs(y))
			res.Neg(res)
		} else {
			res.Mod(x.Abs(x), y.Abs(y))
		}
		stack.push(U256(res))
	}
	evm.interpreter.intPool.put(x, y)
	return nil, nil
}

func opExp(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	base, exponent := stack.pop(), stack.pop()
	stack.push(Exp(base, exponent))

	evm.interpreter.intPool.put(base, exponent)

	return nil, nil
}

func opSignExtend(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	back := stack.pop()
	if back.Cmp(big.NewInt(31)) < 0 {
		bit := uint(back.Uint64()*8 + 7)
		num := stack.pop()
		mask := back.Lsh(big.NewInt(1), bit)
		mask.Sub(mask, big.NewInt(1))
		if num.Bit(int(bit)) > 0 {
			num.Or(num, mask.Not(mask))
		} else {
			num.And(num, mask)
		}

		stack.push(U256(num))
	}

	evm.interpreter.intPool.put(back)
	return nil, nil
}

func opNot(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.peek()
	U256(x.Not(x))
	return nil, nil
}

func opLt(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) < 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opGt(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) > 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opSlt(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(1)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(0)

	default:
		if x.Cmp(y) < 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opSgt(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()

	xSign := x.Cmp(tt255)
	ySign := y.Cmp(tt255)

	switch {
	case xSign >= 0 && ySign < 0:
		y.SetUint64(0)

	case xSign < 0 && ySign >= 0:
		y.SetUint64(1)

	default:
		if x.Cmp(y) > 0 {
			y.SetUint64(1)
		} else {
			y.SetUint64(0)
		}
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opEq(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	if x.Cmp(y) == 0 {
		y.SetUint64(1)
	} else {
		y.SetUint64(0)
	}
	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opIszero(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x := stack.peek()
	if x.Sign() > 0 {
		x.SetUint64(0)
	} else {
		x.SetUint64(1)
	}
	return nil, nil
}

func opAnd(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.pop()
	stack.push(x.And(x, y))

	evm.interpreter.intPool.put(y)
	return nil, nil
}

func opOr(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	y.Or(x, y)

	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opXor(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y := stack.pop(), stack.peek()
	y.Xor(x, y)

	evm.interpreter.intPool.put(x)
	return nil, nil
}

func opByte(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	th, val := stack.pop(), stack.peek()
	if th.Cmp(big.NewInt(32)) < 0 {
		b := Byte(val, 32, int(th.Int64()))
		val.SetUint64(uint64(b))
	} else {
		val.SetUint64(0)
	}
	evm.interpreter.intPool.put(th)
	return nil, nil
}

func opAddmod(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		x.Add(x, y)
		x.Mod(x, z)
		stack.push(U256(x))
	} else {
		stack.push(x.SetUint64(0))
	}
	evm.interpreter.intPool.put(y, z)
	return nil, nil
}

func opMulmod(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	x, y, z := stack.pop(), stack.pop(), stack.pop()
	if z.Cmp(bigZero) > 0 {
		x.Mul(x, y)
		x.Mod(x, z)
		stack.push(U256(x))
	} else {
		stack.push(x.SetUint64(0))
	}
	evm.interpreter.intPool.put(y, z)
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := U256(stack.pop()), U256(stack.peek())
	defer evm.interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(big.NewInt(256)) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	U256(value.Lsh(value, n))

	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := U256(stack.pop()), U256(stack.peek())
	defer evm.interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(big.NewInt(256)) >= 0 {
		value.SetUint64(0)
		return nil, nil
	}
	n := uint(shift.Uint64())
	U256(value.Rsh(value, n))

	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Note, S256 returns (potentially) a new bigint, so we're popping, not peeking this one
	shift, value := U256(stack.pop()), S256(stack.pop())
	defer evm.interpreter.intPool.put(shift) // First operand back into the pool

	if shift.Cmp(big.NewInt(256)) >= 0 {
		if value.Sign() > 0 {
			value.SetUint64(0)
		} else {
			value.SetInt64(-1)
		}
		stack.push(U256(value))
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.Rsh(value, n)
	stack.push(U256(value))

	return nil, nil
}

func opSha3(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	data := memory.Get(offset.Int64(), size.Int64())

	hash := chainhash.HashB(data)

	stack.push(evm.interpreter.intPool.get().SetBytes(hash))

	evm.interpreter.intPool.put(offset, size)
	return nil, nil
}

func opAddress(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(contract.Address().Big())
	return nil, nil
}

func opBalance(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// query balance of a type of token with other criteria
	tokentype, criteria := stack.pop(), stack.pop()
	var hash chainhash.Hash
	var right chainhash.Hash
	if criteria.Uint64() & 1 != 0 {
		s := stack.pop()
		hash = BigToHash(s)
		evm.interpreter.intPool.put(s)
	}
	if criteria.Uint64() & 2 != 0 {
		s := stack.pop()
		right = BigToHash(s)
		evm.interpreter.intPool.put(s)
	}
	stack.push(evm.StateDB[contract.Address()].GetBalance(tokentype.Uint64(), criteria.Uint64(), hash, right))

	evm.interpreter.intPool.put(tokentype, criteria)
	return nil, nil
}

func opOrigin(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(evm.Origin.Big())
//	return nil, nil
}

func opCaller(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(contract.Caller().Big())
//	return nil, nil
}

func opCallValue(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(evm.interpreter.intPool.get().Set(contract.value))
//	return nil, nil
}

func opCallDataLoad(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.interpreter.intPool.get().SetBytes(getDataBig(contract.Input, stack.pop(), big32)))
	return nil, nil
}

func opCallDataSize(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.interpreter.intPool.get().SetInt64(int64(len(contract.Input))))
	return nil, nil
}

func opCallDataCopy(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		dataOffset = stack.pop()
		length     = stack.pop()
	)
	memory.Set(memOffset.Uint64(), length.Uint64(), getDataBig(contract.Input, dataOffset, length))

	evm.interpreter.intPool.put(memOffset, dataOffset, length)
	return nil, nil
}

func opReturnDataSize(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.interpreter.intPool.get().SetUint64(uint64(len(evm.interpreter.returnData))))
	return nil, nil
}

func opReturnDataCopy(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		dataOffset = stack.pop()
		length     = stack.pop()

		end = evm.interpreter.intPool.get().Add(dataOffset, length)
	)
	defer evm.interpreter.intPool.put(memOffset, dataOffset, length, end)

	if end.BitLen() > 64 || uint64(len(evm.interpreter.returnData)) < end.Uint64() {
		return nil, errReturnDataOutOfBounds
	}
	memory.Set(memOffset.Uint64(), length.Uint64(), evm.interpreter.returnData[dataOffset.Uint64():end.Uint64()])

	return nil, nil
}

func opExtCodeSize(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opExtCodeSize")
//	slot := stack.peek()
//	slot.SetUint64(uint64(evm.StateDB[contract.Address()].GetCodeSize(BigToAddress(slot))))

//	return nil, nil
}

func opCodeSize(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	l := evm.interpreter.intPool.get().SetInt64(int64(len(contract.Code)))
	stack.push(l)

	return nil, nil
}

func opCodeCopy(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	var (
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	codeCopy := getDataBig(contract.Code, codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	evm.interpreter.intPool.put(memOffset, codeOffset, length)
	return nil, nil
}

func opExtCodeCopy(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opExtCodeCopy")
/*
	var (
		addr       = common.BigToAddress(stack.pop())
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	codeCopy := getDataBig(evm.StateDB[contract.Address()].GetCode(addr), codeOffset, length)
	memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	evm.interpreter.intPool.put(memOffset, codeOffset, length)
	return nil, nil
*/
}

func opGasprice(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(evm.interpreter.intPool.get().Set(evm.GasPrice))
//	return nil, nil
}

func opBlockhash(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	num := stack.pop()
	bigblknum := big.NewInt(int64(evm.BlockNumber()))

	n := evm.interpreter.intPool.get().Sub(bigblknum, big.NewInt(257))
	if num.Cmp(n) > 0 && num.Cmp(bigblknum) < 0 {
		stack.push(evm.GetHash(num.Uint64()).Big())
	} else {
		stack.push(evm.interpreter.intPool.getZero())
	}
	evm.interpreter.intPool.put(num, n)
	return nil, nil
}

/*
func opCoinbase(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.Coinbase.Big())
	return nil, nil
}
*/

func opTimestamp(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(U256(evm.interpreter.intPool.get().SetInt64(evm.Time.Unix())))
//	return nil, nil
}

func opNumber(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(U256(evm.interpreter.intPool.get().SetUint64(evm.BlockNumber())))
	return nil, nil
}

func opDifficulty(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(U256(evm.interpreter.intPool.get().Set(evm.Difficulty)))
//	return nil, nil
}

func opGasLimit(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
//	stack.push(U256(evm.interpreter.intPool.get().SetUint64(evm.GasLimit)))
//	return nil, nil
}

func opPop(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	evm.interpreter.intPool.put(stack.pop())
	return nil, nil
}

func opMload(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset := stack.pop()
	val := evm.interpreter.intPool.get().SetBytes(memory.Get(offset.Int64(), 32))
	stack.push(val)

	evm.interpreter.intPool.put(offset)
	return nil, nil
}

func opMstore(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// pop value of the stack
	mStart, val := stack.pop(), stack.pop()
	var v [32]byte
	copy(v[:], val.Bytes())

	memory.Set(mStart.Uint64(), 32, v[:])

	evm.interpreter.intPool.put(mStart, val)
	return nil, nil
}

func opMstore8(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	off, val := stack.pop().Int64(), stack.pop().Int64()
	memory.store[off] = byte(val & 0xff)

	return nil, nil
}

func opSload(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := chainhash.Hash{}
	copy(loc[:], stack.pop().Bytes())

	val := evm.StateDB[contract.Address()].GetState(&loc).Big()
	stack.push(val)
	return nil, nil
}

func opSstore(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	loc := chainhash.Hash{}
	copy(loc[:], stack.pop().Bytes())
	val := stack.pop()

	h := chainhash.Hash{}
	copy(h[:], val.Bytes())
	evm.StateDB[contract.Address()].SetState(&loc, h)

	evm.interpreter.intPool.put(val)
	return nil, nil
}

func opJump(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos := stack.pop()
	if !contract.jumpdests.has(contract.CodeHash, contract.Code, pos) {
		nop := contract.GetOp(pos.Uint64())
		return nil, fmt.Errorf("invalid jump destination (%v) %v", nop, pos)
	}

	if evm.vmConfig.NoLoop {
		if pos.Uint64() < *pc {
			return nil, fmt.Errorf("invalid jump destination %v", pos.Uint64())
		}
	}
	*pc = pos.Uint64()

	evm.interpreter.intPool.put(pos)
	return nil, nil
}

func opJumpi(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pos, cond := stack.pop(), stack.pop()
	if cond.Sign() != 0 {
		if !contract.jumpdests.has(contract.CodeHash, contract.Code, pos) {
			nop := contract.GetOp(pos.Uint64())
			return nil, fmt.Errorf("invalid jump destination (%v) %v", nop, pos)
		}
		if evm.vmConfig.NoLoop {
			if pos.Uint64() < *pc {
				return nil, fmt.Errorf("invalid jump destination %v", pos.Uint64())
			}
		}
		*pc = pos.Uint64()
	} else {
		*pc++
	}

	evm.interpreter.intPool.put(pos, cond)
	return nil, nil
}

func opJumpdest(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.interpreter.intPool.get().SetUint64(*pc))
	return nil, nil
}

func opMsize(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	stack.push(evm.interpreter.intPool.get().SetInt64(int64(memory.Len())))
	return nil, nil
}

func opCreate(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCreate")
/*
	var (
		value        = stack.pop()
		offset, size = stack.pop(), stack.pop()
		input        = memory.Get(offset.Int64(), size.Int64())
	)

	res, addr, suberr := evm.Create(contract, input, value)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if suberr == ErrCodeStoreOutOfGas {
		stack.push(evm.interpreter.intPool.getZero())
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stack.push(evm.interpreter.intPool.getZero())
	} else {
		stack.push(big.NewInt(0).SetBytes(addr.ScriptAddress()))
	}
	evm.interpreter.intPool.put(value, offset, size)

	if suberr == errExecutionReverted {
		return res, nil
	}
	return nil, nil
*/
}

// Helper functions
type memoryIO struct {
	m * Memory
	offset int64
}

func (m * memoryIO) Read(p []byte) (n int, err error) {
	s := m.m.Get(m.offset, int64(len(p)))
	copy(p, s)
	m.offset += int64(len(s))
	return len(s), nil
}

func (m * memoryIO) Write(p []byte) (n int, err error) {
	m.m.Set(uint64(m.offset), uint64(len(p)), p)
	m.offset += int64(len(p))
	return len(p), nil
}

func memToToken(offset int64, memory *Memory) (* token.Token, int64) {
	rd := memoryIO{memory, offset}
	t := token.Token{}
	t.Read(io.Reader(&rd), 0, 0)
	return &t, rd.offset
}

func tokenToMem(offset int64, size int64, memory *Memory, t * token.Token) int64 {
	rd := memoryIO{memory, offset}
	if t.Size() > int(size) {
		return 0
	}
	t.Write(io.Writer(&rd), 0, 0)
	return rd.offset
}

func opCall(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// Pop other call parameters.
	// don't allow value xfer by direct contract call. force it to go through TxOut
	// addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	addr, inOffset, inSize, vOffset, vSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	defer evm.interpreter.intPool.put(addr, inOffset, inSize, vOffset, vSize, retOffset, retSize)

	var value * token.Token
	if vSize.Uint64() == 0 {
		value = nil
	} else {
		value,_ = memToToken(vOffset.Int64(), memory)
	}

	toAddr := BigToAddress(addr)

	// Get the arguments from the memory.
	args := memory.Get(inOffset.Int64(), inSize.Int64())

	if value != nil {
		if err := evm.StateDB[contract.Address()].Debt(*value); err != nil {
			return nil, err
		}
	}

	ret, err := evm.Call(toAddr, args[:4], value, args)		// nil=>value

	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	if err == nil && value != nil {
		evm.StateDB[toAddr].Credit(*value)
	}

	return ret, err
}

func opCallCode(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opCallCode")
/*
	// Pop other call parameters.
	addr, inOffset, inSize, vOffset, vSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	defer evm.interpreter.intPool.put(addr, inOffset, inSize, vOffset, vSize, retOffset, retSize)

	toAddr := BigToAddress(addr)

	// Get arguments from the memory.
	args := memory.Get(inOffset.Int64(), inSize.Int64())

	var value * token.Token
	if vSize.Uint64() == 0 {
		value = nil
	} else {
		value = memToToken(vOffset.Int64(), memory)
	}

	if err := evm.StateDB[contract.Address()].Debt(*value); err != nil {
		return nil, err
	}

	ret, err := evm.CallCode(contract, toAddr, args, value)

	if err == nil {
		evm.StateDB[toAddr].Credit(*value)
	}

	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	return ret, err
*/
}

func opDelegateCall(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opDelegateCall")
/*
	// Pop gas. The actual gas is in evm.callGasTemp.
	evm.interpreter.intPool.put(stack.pop())
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.Get(inOffset.Int64(), inSize.Int64())

	ret, returnGas, err := evm.DelegateCall(contract, toAddr, args, gas)
	if err != nil {
		stack.push(evm.interpreter.intPool.getZero())
	} else {
		stack.push(evm.interpreter.intPool.get().SetUint64(1))
	}
	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	evm.interpreter.intPool.put(addr, inOffset, inSize, retOffset, retSize)
	return ret, nil
*/
}

func opStaticCall(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, fmt.Errorf("Unsupported instruction: opStaticCall")
/*
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	defer evm.interpreter.intPool.put(addr, inOffset, inSize, retOffset, retSize)

	toAddr := BigToAddress(addr)
	// Get arguments from the memory.
	args := memory.Get(inOffset.Int64(), inSize.Int64())

	ret, err := evm.StaticCall(contract, toAddr, args)

	if err == nil || err == errExecutionReverted {
		memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	return ret, nil
*/
}

func opReturn(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	evm.interpreter.intPool.put(offset, size)
	return ret, nil
}

func opStackReturn(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	wbuf := make([]byte, 32 * stack.len())
	p := 0
	for i := stack.len(); i != 0; i-- {
		dret := stack.pop()
		copy(wbuf[p:], dret.Bytes())
		p += 32
		evm.interpreter.intPool.put(dret)
	}

	return wbuf, nil
}

func opAddSignImmData(code []byte) uint64 {
	it := code[0]

	var clen = uint64(0)

	switch it {	// text encoding
	case 2:		// specific matching outpoint
		clen = uint64(code[1]) + 1

	case 3:		// specific matching input
		clen = uint64(code[1]) + 1

	case 4:		// specific script
		l := binary.LittleEndian.Uint32(code[1:])
		clen = 4 + uint64(l)
	}

	return 1 + clen
}

func opAddSignText(pc *uint64, ovm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	*pc++
	it := contract.GetOp(*pc)

	sz := stack.pop()
	size := sz.Uint64()

	inidx := binary.LittleEndian.Uint32(contract.Args)
	var clen = uint64(0)

ret:
	switch it {	// text encoding
	case 0:		// current outpoint
		size += 36

		if stack.len() + 3 > int(StackLimit) {
			ovm.interpreter.intPool.put(sz)
			return nil, fmt.Errorf("stack limit reached %d (%d)", stack.len(), StackLimit)
		}

		bit := ovm.interpreter.intPool.get()
		bit.SetInt64(int64(ovm.GetTx().TxIn[inidx].PreviousOutPoint.Index))
		stack.push(bit)

		bit = ovm.interpreter.intPool.get()
		*bit = *common.HashToBig(&ovm.GetTx().TxIn[inidx].PreviousOutPoint.Hash)
		stack.push(bit)

	case 1:		// all output
		var wbuf bytes.Buffer
		for _, txo := range ovm.GetTx().TxOut {
			if txo.TokenType == 0xFFFFFFFFFFFFFFFF {
				break
			}
			err := txo.WriteTxOut(&wbuf, 0, ovm.GetTx().Version, wire.BaseEncoding)
			if err != nil {
				ovm.interpreter.intPool.put(sz)
				return nil, err
			}
		}
		buf := wbuf.Bytes()
		for p := ((len(buf) + 31) ^ 0x1F) - 32; p >= 0; p -= 32 {
			var hash chainhash.Hash
			copy(hash[:], buf[p:])

			if stack.len() + 2 > int(StackLimit) {
				ovm.interpreter.intPool.put(sz)
				return nil, fmt.Errorf("stack limit reached %d (%d)", stack.len(), StackLimit)
			}

			bit := ovm.interpreter.intPool.get()
			*bit = *common.HashToBig(&hash)
			stack.push(bit)
		}
		size += uint64(len(buf))

	case 2:		// specific matching outpoint
		*pc++
		clen = uint64(contract.Code[*pc]) + 1
		for _, txo := range ovm.GetTx().TxOut {
			if txo.TokenType == 0xFFFFFFFFFFFFFFFF {
				break
			}
			var wbuf bytes.Buffer
			err := txo.WriteTxOut(&wbuf, 0, ovm.GetTx().Version, wire.BaseEncoding)
			if err != nil {
				*pc += clen
				ovm.interpreter.intPool.put(sz)
				return nil, err
			}
			if uint64(wbuf.Len()) != clen {
				continue
			}
			if bytes.Compare(wbuf.Bytes(), contract.Code[*pc + 1:uint64(*pc) + clen]) == 0 {
				buf := wbuf.Bytes()
				for p := ((len(buf) + 31) ^ 0x1F) - 32; p >= 0; p -= 32 {
					var hash chainhash.Hash
					copy(hash[:], buf[p:])

					if stack.len() + 2 > int(StackLimit) {
						ovm.interpreter.intPool.put(sz)
						*pc += clen
						return nil, fmt.Errorf("stack limit reached %d (%d)", stack.len(), StackLimit)
					}

					bit := ovm.interpreter.intPool.get()
					*bit = *common.HashToBig(&hash)
				}
				size += uint64(len(buf))
				break ret
			}
		}
		ovm.interpreter.intPool.put(sz)
		*pc += clen
		return nil, fmt.Errorf("No matching output found.")

	case 3:		// specific matching input
		*pc++
		clen = uint64(contract.Code[*pc]) + 1
		for _, txi := range ovm.GetTx().TxIn {
			buf := txi.PreviousOutPoint.ToBytes()
			if bytes.Compare(buf, contract.Code[*pc + 1:uint64(*pc) + clen]) == 0 {
				for p := ((len(buf) + 31) ^ 0x1F) - 32; p >= 0; p -= 32 {
					var hash chainhash.Hash
					copy(hash[:], buf[p:])

					if stack.len() + 2 > int(StackLimit) {
						ovm.interpreter.intPool.put(sz)
						*pc += clen
						return nil, fmt.Errorf("stack limit reached %d (%d)", stack.len(), StackLimit)
					}

					bit := ovm.interpreter.intPool.get()
					*bit = *common.HashToBig(&hash)
				}
				size += uint64(len(buf))
				break ret
			}
		}
		ovm.interpreter.intPool.put(sz)
		*pc += clen
		return nil, fmt.Errorf("No matching input found.")

	case 4:		// specific script
		l := binary.LittleEndian.Uint32(contract.Code[*pc + 1:])
		buf := contract.Code[*pc + 5:uint32(*pc) + 5 + l]
		for p := ((len(buf) + 31) ^ 0x1F) - 32; p >= 0; p -= 32 {
			var hash chainhash.Hash
			copy(hash[:], buf[p:])

			if stack.len() + 2 > int(StackLimit) {
				ovm.interpreter.intPool.put(sz)
				*pc += 5 + uint64(l)
				return nil, fmt.Errorf("stack limit reached %d (%d)", stack.len(), StackLimit)
			}

			bit := ovm.interpreter.intPool.get()
			*bit = *common.HashToBig(&hash)
		}
		size += uint64(len(buf))
		*pc += 5 + uint64(l)

	default:
		ovm.interpreter.intPool.put(sz)
		return nil, fmt.Errorf("Unknown text coding")
	}

	sz.SetUint64(size)
	stack.push(sz)
	return nil, nil
}

func opRevert(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	offset, size := stack.pop(), stack.pop()
	ret := memory.GetPtr(offset.Int64(), size.Int64())

	evm.interpreter.intPool.put(offset, size)
	return ret, nil
}

func opStop(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	return nil, nil
}

func opSuicide(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	pkScript := make([]byte, 25)
	pkScript[0] = 1		// regular account
	t := BigToAddress(stack.pop())
	copy(pkScript[1:], t[:])
	copy(pkScript[21:], []byte{2, 0, 0, 0})	// pay2pkh: pay to public key hash
	for _, w := range evm.StateDB[contract.Address()].wallet {
		evm.Spend(w.Token)
		evm.AddTxOutput(wire.TxOut{
			w.Token,
			pkScript,
		})
	}

	evm.StateDB[contract.Address()].Suicide()
	return nil, nil
}

// following functions are used by the instruction jump  table
func makePushImm(size uint64) immDataFunc {
	return func ([]byte) uint64 {
		return size
	}
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		codeLen := len(contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := evm.interpreter.intPool.get()
		stack.push(integer.SetBytes(RightPadBytes(contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		return nil, nil
	}
}

// make push instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.dup(evm.interpreter.intPool, int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size += 1
	return func(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
		stack.swap(int(size))
		return nil, nil
	}
}

// new ops
func opGetTx(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	tx := evm.GetTx()
	n := uint64(16)
	n += uint64(36 * len(tx.TxIn))
	adj := 0
	for _,t := range tx.TxOut {
		if t.TokenType == 0xFFFFFFFFFFFFFFFF {
			adj--
			continue
		}
		if t.TokenType & 1 == 0 {
			n += 16
		} else {
			n += 40
		}

		if t.TokenType & 2 == 2 {
			n += 32
		}
		n += 21
	}

	ptr := uint64(len(memory.store))
	memory.Resize(uint64(len(memory.store)) + n)

	p := ptr
	memory.SetUint32(p, uint32(tx.Version))
	p += 4

	memory.SetUint32(p, uint32(len(tx.TxIn)))
	p += 4
	for _,t := range tx.TxIn {
		memory.Set(p, 32, t.PreviousOutPoint.Hash[:])
		p += 32
		memory.SetUint32(p, t.Sequence)
		p += 4
	}

	memory.SetUint32(p, uint32(len(tx.TxOut) + adj))
	p += 4
	for _,t := range tx.TxOut {
		if t.TokenType == 0xFFFFFFFFFFFFFFFF {
			continue
		}
		p = uint64(tokenToMem(int64(p), int64(n), memory, &t.Token))
		// we take only address part
		memory.Set(p, 21, t.PkScript[:21])
		p += 21
	}

	stack.push(big.NewInt(int64(n)))
	stack.push(big.NewInt(int64(ptr)))

	return nil, nil
}

func opSpend(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	inOffset := stack.pop()
	defer evm.interpreter.intPool.put(inOffset)

	t,_ := memToToken(inOffset.Int64(), memory)

	if evm.Spend(*t) {
		stack.push(big.NewInt(1))
	} else {
		stack.push(big.NewInt(0))
	}

	return nil, nil
}

// Helper
func memToDef(offset int64, dtype uint64, memory *Memory) token.Definition {
	switch dtype {
	case token.DefTypeRight:
		t := token.RightDef{}
		memrdr := memoryIO{memory, offset }
		if err := t.MemRead(io.Reader(&memrdr), 0); err != nil {
			return nil
		}
		return &t
	}
	return nil
}

func defToMem(t token.Definition, offset int64, size uint64, memory *Memory) (int64, error) {
	memrdr := memoryIO{memory, offset }
	if t.Size() > int(size) {
		return 0, fmt.Errorf("insufficient return size.")
	}
	t.MemWrite(io.Writer(&memrdr), 0)
	return memrdr.offset, nil
}

func opAddRight(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	inOffset := stack.pop()
	defer evm.interpreter.intPool.put(inOffset)

	t := memToDef(inOffset.Int64(), token.DefTypeRight, memory)

	if t == nil {
		stack.push(big.NewInt(0))
	} else if evm.AddRight(t.(*token.RightDef)) {
		stack.push(big.NewInt(1))
	} else {
		stack.push(big.NewInt(0))
	}

	return nil, nil
}

func opAddTxOut(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	inOffset, size := stack.pop(), stack.pop()
	defer evm.interpreter.intPool.put(inOffset, size)

	tl, p := memToToken(inOffset.Int64(), memory)

	t := wire.TxOut{
		*tl,
		memory.Get(p, size.Int64() - int64(tl.Size())),
	}

	if isContract(t.PkScript[0]) {
		return nil, fmt.Errorf("Contract may not add a txout paybale to contract address")
	}

	if evm.AddTxOutput(t) {
		stack.push(big.NewInt(1))
	} else {
		stack.push(big.NewInt(0))
	}

	return nil, nil
}

func opGetCoin(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	// get coins of a type of token matching other criteria
	tokentype, criteria := stack.pop(), stack.pop()
	defer evm.interpreter.intPool.put(tokentype, criteria)

	var hash chainhash.Hash
	var right chainhash.Hash

	if criteria.Uint64() & 1 != 0 {
		s := stack.pop()
		hash = BigToHash(s)
		evm.interpreter.intPool.put(s)
	}
	if criteria.Uint64() & 2 != 0 {
		s := stack.pop()
		right = BigToHash(s)
		evm.interpreter.intPool.put(s)
	}

	c := evm.StateDB[contract.Address()].GetCoins(tokentype.Uint64(), criteria.Uint64(), hash, right)

	if c == nil || len(c) == 0 {
		stack.push(big.NewInt(int64(0)))
		stack.push(big.NewInt(int64(0)))

		return nil, nil
	}

	n := uint64(len(c))
	ptr := uint64(len(memory.store))
	memory.Resize(uint64(len(memory.store)) + n)

	stack.push(big.NewInt(int64(n)))
	stack.push(big.NewInt(int64(ptr)))

	return nil, nil
}

func opGetUtxo(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	tx, seq := stack.pop(), stack.pop()
	defer evm.interpreter.intPool.put(tx, seq)

	t := evm.GetUtxo(BigToHash(tx), seq.Uint64())

	if t == nil {
		stack.push(big.NewInt(int64(0)))
		stack.push(big.NewInt(int64(0)))
		return nil, nil
	}

	n := uint64(t.Size())
	ptr := uint64(len(memory.store))
	memory.Resize(uint64(len(memory.store)) + n)

	w := memoryIO{memory, int64(ptr) }
	t.Write(&w, 0, 0)

	stack.push(big.NewInt(int64(n)))
	stack.push(big.NewInt(int64(ptr)))

	return nil, nil
}

func opGetDefinition(pc *uint64, evm *OVM, contract *Contract, memory *Memory, stack *Stack) ([]byte, error) {
	hash, defType := stack.pop(), stack.pop()

	defer evm.interpreter.intPool.put(hash, defType)

	ptr := uint64(len(memory.store))
	tx := evm.GetTx()
	n := uint64(0)
	fetch := BigToHash(hash)

	for _, def := range tx.TxDef {
		h := def.Hash()
		if defType.Uint64() == uint64(def.DefType()) && h.IsEqual(&fetch) {
			n = uint64(def.Size())
			memory.Resize(uint64(len(memory.store)) + n)
			defToMem(def, int64(ptr), n, memory)
			stack.push(big.NewInt(int64(n)))
			stack.push(big.NewInt(int64(ptr)))

			return nil, nil
		}
	}

	var t token.Definition

	switch defType.Uint64() {
	case token.DefTypeBorder:
		b, err := evm.views.Border.FetchEntry(evm.views.Db, &fetch)
		if err != nil {
			stack.push(big.NewInt(int64(0)))
			stack.push(big.NewInt(int64(0)))
			return nil, nil
		}
		t = token.Definition(b.ToToken())
	case token.DefTypePolygon:
		b, err := evm.views.Polygon.FetchEntry(evm.views.Db, &fetch)
		if err != nil {
			stack.push(big.NewInt(int64(0)))
			stack.push(big.NewInt(int64(0)))
			return nil, nil
		}
		t = token.Definition(b.ToToken())
	case token.DefTypeRight:
		b, err := evm.views.Rights.FetchEntry(evm.views.Db, &fetch)
		if err != nil {
			stack.push(big.NewInt(int64(0)))
			stack.push(big.NewInt(int64(0)))
			return nil, nil
		}
		t = token.Definition(b.(*viewpoint.RightEntry).ToToken())
	case token.DefTypeRightSet:
		b, err := evm.views.Rights.FetchEntry(evm.views.Db, &fetch)
		if err != nil {
			stack.push(big.NewInt(int64(0)))
			stack.push(big.NewInt(int64(0)))
			return nil, nil
		}
		t = token.Definition(b.(*viewpoint.RightSetEntry).ToToken())
	case token.DefTypeVertex:
		v, err := evm.views.Vertex.FetchEntry(evm.views.Db, &fetch)
		if err != nil {
			stack.push(big.NewInt(int64(0)))
			stack.push(big.NewInt(int64(0)))
			return nil, nil
		}
		t = token.Definition(v.ToToken())
	default:
		stack.push(big.NewInt(int64(0)))
		stack.push(big.NewInt(int64(0)))
		return nil, nil
	}

	n = uint64(t.Size())
	memory.Resize(uint64(len(memory.store)) + n)
	defToMem(t, int64(ptr), n, memory)

	stack.push(big.NewInt(int64(n)))
	stack.push(big.NewInt(int64(ptr)))

	return nil, nil
}
