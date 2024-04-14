/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega"
	"github.com/omegasuite/omega/viewpoint"
	"golang.org/x/crypto/ripemd160"
	"math"
	"math/big"
	"time"

	"bytes"
	"encoding/binary"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	//	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/omega/token"
)

type SigHashType byte

// dup of what's in txscript because we can't import txacript here due to circular importation
const (
	SigHashAll          SigHashType = 0x1
	SigHashNone         SigHashType = 0x2
	SigHashSingle       SigHashType = 0x3
	SigHashDouble       SigHashType = 0x4
	SigHashTriple       SigHashType = 0x5
	SigHashQuardruple   SigHashType = 0x6
	SigMultiSigMark     SigHashType = 0x1f // marks end of a multi-sig segment
	SigHashAnyOneCanPay SigHashType = 0x80

	// sigHashMask defines the number of bits of the hash type which is used
	// to identify which outputs are signed.
	SigHashMask = 0x1f
)

// TBD: big endian math
// memoery range check in copies

// blockIndexBucketName is the next token type number that can be used.
// all token type under 256 are reserved. curently are used as:
// 0 - main currency (OMC)
// 3 - polygon with rights
// 0xFF - separator
var IssuedTokenTypes = []byte("issuedTokens")

// operators: u+-*/><=?|*^~%[](>=)(<=)(!=)
// u: unsigned
// +-*/%#: +-*/%#(exp)
// ><=!(): compare: >, <, ==, !=, <=, >=
// ?: select
// |&~^: bitwise/logical: |&~^
// []: shift: <<, >>
// '": offset

// operands:
// [0-9a-f]+: number
// n: negative
// g: global
// l: lib base
// i: indirect
// x: hex number
// ,: end of operand
// RBWDQHK - 21bit address, byte, word, dword, qword, big int, uncompressed pubkey
// rhk - 20bit address, hash, compressed pub key
// kK are only valid for COPY, STORE, LOAD, COPYIMM insts

// first operand is a pointer

var checkTop = map[uint8]int{'+': 1, '-': 1, '*': 1, '/': 1, '%': 1, '#': 1, '&': 1,
	'[': 1, ']': 1, '|': 1, '^': 1, '>': 1, '<': 1, '=': 1, ')': 1, '(': 1, '!': 1, '?': 2}
var sizeOfType = map[byte]uint32{'R': 21, 'r': 20,
	'B': 1, 'W': 2, 'D': 4, 'Q': 8, 'H': 32, 'h': 32,
	'k': 33, 'K': 65}

func (stack *Stack) getNum(param []byte, dataType byte) (int64, int, omega.Err) {
	ln := len(param)
	hex := false
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	global := byte(0)
	sign := 1
	offset := 0
	hasoffset := 0
	indirect := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // 0 - 9
			if hex {
				tmp = tmp*16 + int64(param[j]-0x30)
			} else {
				tmp = tmp*10 + int64(param[j]-0x30)
			}
			nums[offset] = tmp

		case 'a', 'b', 'c', 'd', 'e', 'f': // 0 - 9
			hex = true
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp

		case 'x': // x
			hex = true

		case 'n': // n
			sign = -1

		case 'i': // i
			indirect++
			if indirect > 6 {
				return 0, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
			}

		case 'g': // g
			global = 1

			//		case 'l':	// l
			//			global = 2

		case '\'': // " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0

		case '"': // " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0

		case ',': // ,
			t := int64(0)
			num := int64(0)
			if global == 0 {
				t = int64(stack.callTop)
			} else {
				t = int64(stack.data[stack.callTop].gbase)
			}

			if indirect > 0 { // || dataType == 0xFF {
				p := pointer((t << 32) | nums[0])
				if indirect > 0 {
					var err omega.Err
					p, err = stack.addressing(indirect, global, hasoffset, nums[:], dataType != 0xFF)
					if err != nil {
						return 0, 0, err
					}
				}

				switch dataType {
				case 'B': // byte
					b, err := stack.toByte(&p)
					if err != nil {
						return 0, 0, err
					}
					num = int64(int(b) * sign)
				case 'W': // word
					b, err := stack.toInt16(&p)
					if err != nil {
						return 0, 0, err
					}
					num = int64(int(b) * sign)
				case 'D': // dword
					b, err := stack.toInt32(&p)
					if err != nil {
						return 0, 0, err
					}
					num = int64(int(b) * sign)
				case 'Q': // qword
					b, err := stack.toInt64(&p)
					if err != nil {
						return 0, 0, err
					}
					num = int64(b * int64(sign))
				case 0xFF: // pointer
					num = int64(p)
				}
				indirect = 0
			} else {
				num = nums[0]
				num *= int64(sign)
			}
			return num, j, nil

		default:
			return 0, j - 1, omega.ScriptError(omega.ErrInternal, "Malformed operand")
		}
	}
	return 0, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
}

func opEval8(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int8, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var store pointer
	var r bool
	var tl int
	var err omega.Err

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression. Evaluation stack underflow.")
			}
			top -= d
		}
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'n', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			j += tl
			if dataType == 0xFF {
				store = pointer(num)
			} else {
				scratch[top] = int8(num)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			dataType = 0x42

		case 'u': // u
			unsigned = true

		case '@':
			if top != 0 {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression.")
			}

		case 'B', 'W', 'D', 'Q', 'H':
			dataType = 0x42

		case '+': // +
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) + uint8(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-': // -
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) - uint8(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*': // *
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) * uint8(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/': // /
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) / uint8(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%': // %
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) % uint8(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#': // # - exp
			if unsigned {
				scratch[top-1] = int8(math.Pow(float64(uint8(scratch[top-1])), float64(uint8(scratch[top]))))
			} else {
				scratch[top-1] = int8(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[': // <<
			scratch[top-1] <<= scratch[top]

		case ']': // >>
			scratch[top-1] >>= scratch[top]

		case '|': // |
			scratch[top-1] |= scratch[top]

		case '&': // &
			scratch[top-1] &= scratch[top]

		case '^': // &^
			scratch[top-1] ^= scratch[top]

		case '~': // ~
			scratch[top-1] = ^scratch[top-1]

		case '>': // >
			if unsigned {
				r = uint8(scratch[top-1]) > uint8(scratch[top])
			} else {
				r = scratch[top-1] > scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '<': // <
			if unsigned {
				r = uint8(scratch[top-1]) < uint8(scratch[top])
			} else {
				r = scratch[top-1] < scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '=': // =
			if unsigned {
				r = uint8(scratch[top-1]) == uint8(scratch[top])
			} else {
				r = scratch[top-1] == scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case ')': // >=
			if unsigned {
				r = uint8(scratch[top-1]) >= uint8(scratch[top])
			} else {
				r = scratch[top-1] >= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '(': // <=
			if unsigned {
				r = uint8(scratch[top-1]) <= uint8(scratch[top])
			} else {
				r = scratch[top-1] <= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '!': // !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?': // ?
			if scratch[top+1] == 0 {
				scratch[top-1] = scratch[top]
			}
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveByte(&store, byte(scratch[0]))
}

func opEval16(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int16, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var store pointer
	var r bool
	var tl int
	var err omega.Err

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression. Evaluation stack underflow.")
			}
			top -= d
		}
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'n', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			j += tl
			if dataType == 0xFF {
				store = pointer(num)
			} else {
				scratch[top] = int16(num)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			dataType = 0x57

		case '@':
			if top != 0 {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression.")
			}

		case 'B':
			dataType = param[j]

		case 'W', 'D', 'Q', 'H':
			dataType = 0x57

		case 'u': // u
			unsigned = true

		case '+': // +
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) + uint16(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-': // -
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) - uint16(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*': // *
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) * uint16(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/': // /
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) / uint16(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%': // %
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) % uint16(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#': // # - exp
			if unsigned {
				scratch[top-1] = int16(math.Pow(float64(uint16(scratch[top-1])), float64(uint16(scratch[top]))))
			} else {
				scratch[top-1] = int16(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[': // <<
			scratch[top-1] <<= scratch[top]

		case ']': // >>
			scratch[top-1] >>= scratch[top]

		case '|': // |
			scratch[top-1] |= scratch[top]

		case '&': // &
			scratch[top-1] &= scratch[top]

		case '^': // &^
			scratch[top-1] ^= scratch[top]

		case '~': // ~
			scratch[top-1] = ^scratch[top-1]

		case '>': // >
			if unsigned {
				r = uint16(scratch[top-1]) > uint16(scratch[top])
			} else {
				r = scratch[top-1] > scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '<': // <
			if unsigned {
				r = uint16(scratch[top-1]) < uint16(scratch[top])
			} else {
				r = scratch[top-1] < scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '=': // =
			if unsigned {
				r = uint16(scratch[top-1]) == uint16(scratch[top])
			} else {
				r = scratch[top-1] == scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case ')': // >=
			if unsigned {
				r = uint16(scratch[top-1]) >= uint16(scratch[top])
			} else {
				r = scratch[top-1] >= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '(': // <=
			if unsigned {
				r = uint16(scratch[top-1]) <= uint16(scratch[top])
			} else {
				r = scratch[top-1] <= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '!': // !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?': // ?
			if scratch[top+1] == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveInt16(&store, scratch[0])
}

func opEval32(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int32, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var store pointer
	var err omega.Err
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression. Evaluation stack underflow.")
			}
			top -= d
		}
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'n', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			j += tl
			if dataType == 0xFF {
				store = pointer(num)
			} else {
				scratch[top] = int32(num)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			dataType = 0x44

		case '@':
			if top != 0 {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression.")
			}

		case 'B', 'W':
			dataType = param[j]

		case 'D', 'Q', 'H':
			dataType = 0x44

		case 'u': // u
			unsigned = true

		case '+': // +
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) + uint32(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-': // -
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) - uint32(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*': // *
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) * uint32(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/': // /
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) / uint32(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%': // %
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) % uint32(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#': // # - exp
			if unsigned {
				scratch[top-1] = int32(math.Pow(float64(uint32(scratch[top-1])), float64(uint32(scratch[top]))))
			} else {
				scratch[top-1] = int32(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[': // <<
			scratch[top-1] <<= scratch[top]

		case ']': // >>
			scratch[top-1] >>= scratch[top]

		case '|': // |
			scratch[top-1] |= scratch[top]

		case '&': // &
			scratch[top-1] &= scratch[top]

		case '^': // &^
			scratch[top-1] ^= scratch[top]

		case '~': // ~
			scratch[top-1] = ^scratch[top-1]

		case '>': // >
			var r bool
			if unsigned {
				r = uint32(scratch[top-1]) > uint32(scratch[top])
			} else {
				r = scratch[top-1] > scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '<': // <
			var r bool
			if unsigned {
				r = uint32(scratch[top-1]) < uint32(scratch[top])
			} else {
				r = scratch[top-1] < scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '=': // =
			var r bool
			if unsigned {
				r = uint32(scratch[top-1]) == uint32(scratch[top])
			} else {
				r = scratch[top-1] == scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case ')': // >=
			var r bool
			if unsigned {
				r = uint32(scratch[top-1]) >= uint32(scratch[top])
			} else {
				r = scratch[top-1] >= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '(': // <=
			var r bool
			if unsigned {
				r = uint32(scratch[top-1]) <= uint32(scratch[top])
			} else {
				r = scratch[top-1] <= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '!': // !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?': // ?
			if scratch[top+1] == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveInt32(&store, scratch[0])
}

func opEval64(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int64, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var r bool
	var err omega.Err
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression. Evaluation stack underflow.")
			}
			top -= d
		}
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'n', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			j += tl

			scratch[top] = num
			top++
			if top == lim {
				scratch = append(scratch, 0)
				lim++
			}
			dataType = 0x51

		case '@': // @
			dataType = 0xFF

		case 'B', 'W', 'D':
			dataType = param[j]

		case 'Q', 'H':
			dataType = 0x51

		case 'u': // u
			unsigned = true

		case 'P': // deference
			tp := pointer(scratch[top-1])
			if scratch[top-1], err = stack.toInt64(&tp); err != nil {
				return err
			}

		case '+': // +
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) + uint64(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-': // -
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) - uint64(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*': // *
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) * uint64(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/': // /
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) / uint64(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%': // %
			if scratch[top] == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) % uint64(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#': // # - exp
			if unsigned {
				scratch[top-1] = int64(math.Pow(float64(uint64(scratch[top-1])), float64(uint64(scratch[top]))))
			} else {
				scratch[top-1] = int64(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[': // <<
			scratch[top-1] <<= scratch[top]

		case ']': // >>
			scratch[top-1] >>= scratch[top]

		case '|': // |
			scratch[top-1] |= scratch[top]

		case '&': // &
			scratch[top-1] &= scratch[top]

		case '^': // &^
			scratch[top-1] ^= scratch[top]

		case '~': // ~
			scratch[top-1] = ^scratch[top-1]

		case '>': // >
			if unsigned {
				r = uint64(scratch[top-1]) > uint64(scratch[top])
			} else {
				r = scratch[top-1] > scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '<': // <
			if unsigned {
				r = uint64(scratch[top-1]) < uint64(scratch[top])
			} else {
				r = scratch[top-1] < scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '=': // =
			if unsigned {
				r = uint64(scratch[top-1]) == uint64(scratch[top])
			} else {
				r = scratch[top-1] == scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case ')': // >=
			if unsigned {
				r = uint64(scratch[top-1]) >= uint64(scratch[top])
			} else {
				r = scratch[top-1] >= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '(': // <=
			if unsigned {
				r = uint64(scratch[top-1]) <= uint64(scratch[top])
			} else {
				r = scratch[top-1] <= scratch[top]
			}
			if r {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '!': // !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?': // ?
			if scratch[top+1] == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	store := pointer(scratch[0])

	return stack.saveInt64(&store, scratch[1])
}

var (
	bigZero   = big.NewInt(0)
	bigOne    = big.NewInt(1)
	bigNegOne = big.NewInt(-1)
)

func (stack *Stack) addressing(indirect int, global byte, hasoffset int, offsets []int64, notaddr bool) (pointer, omega.Err) {
	if indirect <= 0 {
		return 0, nil
	}

	t := int64(0)

	if global == 0 {
		t = int64(stack.callTop)
	} else {
		t = int64(stack.data[stack.callTop].gbase)
	}

	p := pointer((t << 32) | offsets[0])
	var err omega.Err

	for ; indirect > 1; indirect-- {
		if p, err = stack.toPointer(&p); err != nil {
			return 0, err
		}
		p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(offsets[1])) & 0xFFFFFFFF)) // head offset is added to the first indirection
		offsets[1] = 0
	}
	if (hasoffset & 2) != 0 {
		p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(offsets[2])) & 0xFFFFFFFF))
	}

	if _, ok := stack.data[int32(p>>32)]; !ok {
		return 0, omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	if notaddr && int(p&0xFFFFFFFF) >= len(stack.data[int32(p>>32)].space) {
		return 0, omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	return p, nil
}

func (stack *Stack) getBig(param []byte) (*big.Int, int, omega.Err) {
	ln := len(param)
	hex := false
	num := *bigZero
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	global := byte(0)
	sign := *bigOne
	offset := 0
	hasoffset := 0
	indirect := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // 0 - 9
			if offset == 0 {
				if hex {
					tmp = tmp*16 + int64(param[j]-0x30)
					num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j]-0x30)))
				} else {
					tmp = tmp*10 + int64(param[j]-0x30)
					num = *num.Add(num.Mul(&num, big.NewInt(10)), big.NewInt(int64(param[j]-0x30)))
				}
			} else {
				if hex {
					tmp = tmp*16 + int64(param[j]-0x30)
				} else {
					tmp = tmp*10 + int64(param[j]-0x30)
				}
			}
			nums[offset] = tmp

		case 'a', 'b', 'c', 'd', 'e', 'f': // 0 - 9
			hex = true
			num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j]-0x30)))
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp

		case 'x': // x
			hex = true

		case 'n': // n
			sign = *bigNegOne

		case 'i': // i
			indirect++
			if indirect > 6 {
				return bigZero, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
			}

		case 'g': // g
			global = 1

			//		case 'l':	// l
			//			global = 2

		case '\'': // ' - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case '"': // " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case ',': // ,
			if indirect > 0 {
				p, err := stack.addressing(indirect, global, hasoffset, nums[:], true)
				if err != nil {
					return nil, 0, err
				}
				if h, err := stack.toHash(&p); err != nil {
					return nil, 0, err
				} else {
					// stored big numbers are little-endians, make it big-endian
					for i := 0; i < 16; i++ {
						s, t := h[i], h[31-i]
						h[i], h[31-i] = t, s
					}
					num.SetBytes(h[:])
					num = *num.Mul(&num, &sign)
				}
				indirect = 0
			} else {
				num = *num.Mul(&num, &sign)
			}
			return &num, j, nil

		default:
			return nil, j - 1, omega.ScriptError(omega.ErrInternal, "Malformed operand")
		}
	}
	return nil, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
}

func (stack *Stack) getHash(param []byte) (chainhash.Hash, int, omega.Err) {
	ln := len(param)
	hex := false
	var num [64]byte
	d := 0
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	global := byte(0)
	offset := 0
	hasoffset := 0
	indirect := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // 0 - 9
			if hex {
				tmp = tmp*16 + int64(param[j]-0x30)
			} else {
				tmp = tmp*10 + int64(param[j]-0x30)
			}
			nums[offset] = tmp
			if offset == 0 && hex {
				num[d] = param[j] - 0x30
				d++
			}

		case 'a', 'b', 'c', 'd', 'e', 'f': // 0 - 9
			hex = true
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp
			if offset == 0 {
				num[d] = param[j] - 0x61 + 10
				d++
			}

		case 'x': // x
			hex = true

		case 'i': // i
			indirect++
			if indirect > 6 {
				return chainhash.Hash{}, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
			}

		case 'g': // g
			global = 1

			//		case 'l':	// l
			//			global = 2

		case '\'': // " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case '"': // " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case ',': // ,
			if indirect > 0 {
				p, err := stack.addressing(indirect, global, hasoffset, nums[:], true)
				if err != nil {
					return chainhash.Hash{}, 0, err
				}

				if h, err := stack.toHash(&p); err != nil {
					return chainhash.Hash{}, 0, err
				} else {
					return h, j, nil
				}
			} else {
				var h chainhash.Hash
				for i := 0; i < 32; i++ {
					if i >= d {
						i = 32
						continue
					}
					if i&1 == 0 {
						h[i/2] = num[d-i-1]
					} else {
						h[i/2] |= num[d-i-1] << 4
					}
				}
				return h, j, nil
			}

		default:
			return chainhash.Hash{}, j - 1, omega.ScriptError(omega.ErrInternal, "Malformed hash operand")
		}
	}
	return chainhash.Hash{}, ln, omega.ScriptError(omega.ErrInternal, "Malformed hash operand")
}

func (stack *Stack) getBytesLen(param []byte, dlen uint32) ([]byte, int, omega.Err) {
	ln := len(param)
	tmp := make([]byte, 0, 66) // byte buffer
	t := byte(0)               // current byte
	even := false
	hex := false
	indirect := 0
	global := byte(0)
	offset := 0
	hasoffset := 0
	tnum := int64(0)          // current number
	nums := [3]int64{0, 0, 0} // offsets

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9': // 0 - 9
			if hex {
				t = (t << 4) + byte(param[j]-0x30)
				tnum = tnum*16 + int64(param[j]-0x30)
			} else {
				tnum = tnum*10 + int64(param[j]-0x30)
			}
			nums[offset] = tnum
			if hex && even && offset == 0 {
				tmp = append(tmp, t)
				t = 0
			}
			even = !even

		case 'a', 'b', 'c', 'd', 'e', 'f': // 0 - 9
			hex = true
			t = (t << 4) + byte(param[j]-0x61) + 10
			tnum = (tnum << 4) + int64(param[j]-0x61) + 10
			nums[offset] = tnum
			if even && offset == 0 {
				tmp = append(tmp, t)
				t = 0
			}
			even = !even

		case 'x': // x
			hex = true

		case 'i': // i
			indirect++
			if indirect > 6 {
				return nil, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
			}

		case 'g': // g
			global = 1

			//		case 'l':	// l
			//			global = 2

		case '\'': // " - head offset
			hasoffset |= 1
			offset = 1
			tnum = 0
			hex = false

		case '"': // " - tail offset
			hasoffset |= 2
			offset = 2
			tnum = 0
			hex = false

		case ',': // ,
			if indirect > 0 {
				p, err := stack.addressing(indirect, global, hasoffset, nums[:], true)
				if err != nil {
					return nil, 0, err
				}
				s := uint32(p & 0xFFFFFFFF)
				if _, ok := stack.data[int32(p>>32)]; !ok {
					return nil, j - 1, omega.ScriptError(omega.ErrInternal, "Memory address fault")
				}
				tmp = stack.data[int32(p>>32)].space[s : s+dlen]
			}
			return tmp, j, nil

		default:
			return nil, j - 1, omega.ScriptError(omega.ErrInternal, "Malformed operand")
		}
	}
	return nil, ln, omega.ScriptError(omega.ErrInternal, "Malformed operand")
}

func (stack *Stack) getBytes(param []byte, dataType byte, dln uint32) ([]byte, int, omega.Err) {
	return stack.getBytesLen(param, sizeOfType[dataType]+dln)
}

func opEval256(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	// to contract, big numbers are little-endian. But in big.Int, numbers are
	// big-endian. So for every math op, we need to do a conversion before and
	// after op.
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]*big.Int, lim)

	top := 0
	var num *big.Int
	var store pointer
	var err omega.Err
	var tl int
	dataType := byte(0xFF)

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression. Evaluation stack underflow.")
			}
			top -= d
		}
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'n', 'i', 'g':
			if dataType == 0xFF {
				if p, tl, err := stack.getNum(param[j:], 0xFF); err != nil {
					return err
				} else {
					scratch[top] = big.NewInt(p)
					top++
					j += tl
				}
			} else if dataType == 0x48 {
				if num, tl, err = stack.getBig(param[j:]); err != nil {
					return err
				}
				j += tl
				scratch[top] = num
				top++
				if top == lim {
					scratch = append(scratch, nil)
					lim++
				}
			} else {
				var qnum int64
				if qnum, tl, err = stack.getNum(param[j:], dataType); err != nil {
					return err
				}
				j += tl

				scratch[top] = big.NewInt(qnum)
				top++
				if top == lim {
					scratch = append(scratch, nil)
					lim++
				}
			}
			dataType = 0x48

		case 'B', 'W', 'D', 'Q', 'H':
			dataType = param[j]

		case '@': // @
			dataType = 0xFF

		case 'P': // deference as address
			tp := pointer(scratch[top-1].Int64())
			if tp, err = stack.toPointer(&tp); err != nil {
				scratch[top-1].SetInt64(int64(tp))
				return err
			}

		case 'Z': // deference as big
			tp := pointer(scratch[top-1].Int64())
			if scratch[top-1], err = stack.toBig(&tp); err != nil {
				return err
			}

		case '+': // +
			scratch[top-1] = scratch[top-1].Add(scratch[top-1], scratch[top])

		case '-': // -
			scratch[top-1] = scratch[top-1].Sub(scratch[top-1], scratch[top])

		case '*': // *
			scratch[top-1] = scratch[top-1].Mul(scratch[top-1], scratch[top])

		case '/': // /
			if scratch[top].Cmp(bigZero) == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Div(scratch[top-1], scratch[top])

		case '%': // %
			if scratch[top].Cmp(bigZero) == 0 {
				return omega.ScriptError(omega.ErrInternal, "Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Mod(scratch[top-1], scratch[top])

		case '#': // # - exp
			scratch[top-1] = Exp(scratch[top-1], scratch[top])

		case '|': // logical |
			if scratch[top-1].Cmp(bigZero) == 0 || scratch[top].Cmp(bigZero) == 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case '&': // logical &
			if scratch[top-1].Cmp(bigZero) != 0 && scratch[top].Cmp(bigZero) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '^': // logical &^
			b1 := scratch[top-1].Cmp(bigZero) != 0
			b2 := scratch[top].Cmp(bigZero) != 0
			if b1 != b2 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '~': // logical ~
			if scratch[top-1].Cmp(bigZero) != 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case '>': // >
			if scratch[top-1].Cmp(scratch[top]) > 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '<': // <
			if scratch[top-1].Cmp(scratch[top]) < 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '=': // =
			if scratch[top-1].Cmp(scratch[top]) == 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case ')': // >=
			if scratch[top-1].Cmp(scratch[top]) >= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '(': // <=
			if scratch[top-1].Cmp(scratch[top]) <= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '!': // !=
			if scratch[top-1].Cmp(scratch[top]) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '?': // ?
			if scratch[top+1].Cmp(bigZero) == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
	}

	if top < 2 {
		return nil
	}

	var h chainhash.Hash

	b := scratch[top-1].Bytes()
	if len(b) > 32 {
		return omega.ScriptError(omega.ErrInternal, "Big number overflow")
	}
	for i := len(b) - 1; i >= 0; i-- {
		h[len(b)-1-i] = b[i]
	}

	store = pointer(scratch[0].Int64())

	return stack.saveHash(&store, h)
}

// 0x41: r - address, 20 bytes
// 0x61: R - address with netid, 21 bytes
// 0x42: B - byte, 1 byte
// 0x57: W - word, 2 bytes
// 0x44: D - dword, 4 bytes
// 0x51: Q - qword, 8 bytes
// 0x48: H - big, 32 bytes
// 0x68: h - hash, 32 bytes (string upto 32 bytes)
// 0x6b: k - compressed public key, 33 bytes
// 0x4b: K - uncompressed public key, 65 bytes

type convOperand struct {
	dtype byte
	p     pointer
}

func opConv(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	var scratch [2]convOperand

	ln := len(param)

	top := 0
	dtype := byte(0)
	num := int64(0)
	unsigned := false
	var err omega.Err
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl
			scratch[top] = convOperand{dtype, pointer(num)}
			dtype = 0
			top++

		case 'B', 'W', 'D', 'Q', 'H': // b
			// BWDQH - byte, word, dword, qword, big int
			dtype = param[j]

		case 'u': // u
			unsigned = true
		}
	}

	srcType := scratch[0].dtype
	destType := scratch[1].dtype
	n := sizeOfType[srcType]
	m := sizeOfType[destType]

	if srcType == 0x42 && destType == 0x48 {
		srcType = 0x48
	}
	if srcType == 0x48 && destType == 0x42 {
		destType = 0x48
	}

	p0 := int32(scratch[0].p >> 32)
	p1 := int32(scratch[1].p >> 32)
	if _, ok := stack.data[p0]; !ok {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}
	if _, ok := stack.data[p1]; !ok {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	if srcType == destType {
		n := sizeOfType[destType]
		copy(stack.data[p1].space[uint32(scratch[1].p):],
			stack.data[p0].space[uint32(scratch[0].p):uint32(scratch[0].p)+n])
	} else if m > n {
		copy(stack.data[p1].space[uint32(scratch[1].p):],
			stack.data[p0].space[uint32(scratch[0].p):uint32(scratch[0].p)+n])
		if unsigned || stack.data[p0].space[uint32(scratch[0].p)+n-1]&0x80 == 0 {
			copy(stack.data[p1].space[uint32(scratch[1].p)+n:],
				make([]byte, m-n))
		} else {
			for ; n < m; n++ {
				stack.data[p1].space[uint32(scratch[1].p)+n] = 0xFF
			}
		}
	} else {
		if unsigned || stack.data[p0].space[uint32(scratch[0].p)+m-1]&0x80 == 0 {
			for i := m; i < n; i++ {
				if stack.data[p0].space[uint32(scratch[0].p)+i] != 0 {
					return omega.ScriptError(omega.ErrInternal, "Numeric overflow in conversion.")
				}
			}
		} else {
			for i := m; i < n; i++ {
				if stack.data[p0].space[uint32(scratch[0].p)+i] != 0xFF {
					return omega.ScriptError(omega.ErrInternal, "Numeric overflow in conversion.")
				}
			}
		}
		copy(stack.data[p1].space[uint32(scratch[1].p):],
			stack.data[p0].space[uint32(scratch[0].p):uint32(scratch[0].p)+m])
	}

	return nil
}

func opHash(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)
	// dest, src, len

	var scratch [3]pointer
	ln := len(param)

	top := 0
	num := int64(0)
	var err omega.Err
	var tl int

	dataType := []byte{0xFF, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			scratch[top] = pointer(num)
			top++
		}
	}

	t := scratch[1]
	a := t & 0xFFFFFFFF
	b := a + (scratch[2] & 0xFFFFFFFF)
	if _, ok := stack.data[int32(t>>32)]; !ok {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}
	hash := chainhash.HashB(stack.data[int32(t>>32)].space[a:b])

	return stack.saveBytes(&scratch[0], hash)
}

func opHash160(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)
	// dest, src, len, ripemd160 only flag

	var scratch [4]pointer
	ln := len(param)

	top := 0
	num := int64(0)
	var err omega.Err
	var tl int

	dataType := []byte{0xFF, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			scratch[top] = pointer(num)
			top++
		}
	}

	t := scratch[1]
	a := t & 0xFFFFFFFF
	b := a + (scratch[2] & 0xFFFFFFFF)
	if _, ok := stack.data[int32(t>>32)]; !ok || len(stack.data[int32(t>>32)].space) < int(b) {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	var hash []byte

	if top < 4 || scratch[3] == 0 {
		hash = btcutil.Hash160(stack.data[int32(t>>32)].space[a:b])
	} else {
		ripemd160 := ripemd160.New()
		ripemd160.Write(stack.data[int32(t>>32)].space[a:b])
		hash = ripemd160.Sum(nil)
	}
	//		hash160(stack.Data[int32(t >> 32)].space[a:b])

	return stack.saveBytes(&scratch[0], hash)
}

func opSigCheck(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	//	{addrOperand, 0xffffffff}, - retVal
	//	{patOperand, 0}, - hash
	//	{addrOperand, 0xFFFFFFFF}, - pubKey
	//	{addrOperand, 0xFFFFFFFF}, - sig address

	param := contract.GetBytes(*pc)
	// dest, src, len

	var tp pointer
	var retVal pointer
	var hash chainhash.Hash
	var pubKey []byte
	var sig []byte
	var err omega.Err
	var tl int

	ln := len(param)

	top := 0
	num := int64(0)

	paramTypes := []byte{0xFF, 'h', 'K', 0xFF}

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 'h' {
				hash, tl, err = stack.getHash(param[j:])
			} else if dataType == 'K' {
				pubKey, tl, err = stack.getBytes(param[j:], 'K', 1)
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				retVal = pointer(num)

			case 1:

			case 2:
				format := pubKey[0]
				if format != btcec.PubKeyBytesLenCompressed && format != btcec.PubKeyBytesLenHybrid {
					return omega.ScriptError(omega.ErrInternal, fmt.Sprintf("invalid magic in pubkey str: %d", format))
				}

				pubKey = pubKey[1 : format+1]

			case 3:
				tp = pointer(num)
				tp2 := tp + 1
				sl2, err := stack.toByte(&tp2)
				if err != nil {
					return err
				}
				sig, err = stack.toBytesLen(&tp, int(sl2+2))
				if err != nil {
					return err
				}
			}

			top++
			num = 0
		}
	}

	result := byte(0)

	err = btcutil.VerifySigScript2(sig, hash[:], pubKey[:], evm.chainConfig)

	if err == nil {
		result = 1
	}

	return stack.saveByte(&retVal, result)
}

func opIf(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var scratch [2]int32

	top := 0
	num := int64(0)
	var err omega.Err
	var tl int

	dataType := []byte{0x42, 0x44}
	sign := int64(1)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			scratch[top] = int32(num * sign)
			sign = 1
			top++

		case 'n':
			sign = -1
		}
	}

	var target int

	if scratch[0] == 0 {
		target = *pc + 1
	} else {
		target = *pc + int(scratch[1])
	}

	inlib := stack.data[stack.callTop].inlib
	if target < int(contract.libs[inlib].address) || target >= int(contract.libs[inlib].end) {
		return omega.ScriptError(omega.ErrInternal, "Out of range jump")
	}
	*pc = target

	return nil
}

func opCall(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)
	// base, entry, params
	// if address == 0, entry is relative to pc, target must be in current code seg
	// if address != 0, lib address, entry is func abi, target is lib entry (0)

	ln := len(param)

	top := 0
	num := int64(0)
	var bnum []byte
	var libAddr Address
	var err omega.Err
	var tl int

	offset := 0

	f := newFrame()
	f.space = append(f.space, []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	binary.LittleEndian.PutUint32(f.space[4:], uint32(stack.callTop+1))
	inlen := 8

	paramTypes := []byte{'L', 'D', 'Q', 'Q'}

	isself := true
	sign := 1

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 'n':
			sign = -1

		case '@':
			if top == 2 {
				paramTypes[top] = 0xFF
			}

		case 'B', 'W', 'D', 'Q':
			if top == 2 {
				paramTypes[top] = param[j]
			}

		case 'H':
			if top == 2 {
				paramTypes[top] = 'Q'
			}

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 'L' {
				bnum, tl, _ = stack.getBytes(param[j:], 'r', 0)
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil {
				return err
			}
			j += tl
			paramTypes[2] = 'Q'

			switch top {
			case 0:
				copy(libAddr[:], bnum)
				if _, ok := contract.libs[libAddr]; !ok {
					return omega.ScriptError(omega.ErrInternal, "Lib not loaded")
				}
				isself = allZero(libAddr[:]) || bytes.Compare(libAddr[:], stack.data[stack.callTop].inlib[:]) == 0
				top++

			case 1:
				offset = int(num) * sign // entry point
				sign = 1
				if !isself {
					var bn [4]byte
					binary.LittleEndian.PutUint32(bn[:], uint32(offset))
					f.space = append(f.space, bn[:]...)
					inlen += 4
				}
				top++

			case 3:
				fallthrough

			case 2:
				var bn [8]byte
				binary.LittleEndian.PutUint64(bn[:], uint64(num))
				f.space = append(f.space, bn[:]...)
				inlen += 8
			}
		}
	}
	binary.LittleEndian.PutUint32(f.space[:], uint32(inlen))

	if top >= 2 {
		f.pc = *pc
		f.pure = stack.data[stack.callTop].pure | contract.libs[libAddr].pure
		if isself {
			libAddr = stack.data[stack.callTop].inlib
		} else if evm.BlockVersion() >= wire.Version2 {
			binary.LittleEndian.PutUint32(f.space[4:8], uint32(contract.libs[libAddr].base))
		}
		f.gbase = contract.libs[libAddr].base
		f.inlib = libAddr

		var target int32
		if isself {
			target = int32(*pc + offset)
			if target < contract.libs[libAddr].address || target >= contract.libs[libAddr].end {
				return omega.ScriptError(omega.ErrInternal, "Out of range func call")
			}
		} else {
			target = contract.libs[libAddr].address
			/*
			   			if evm.BlockVersion() >= wire.Version3 {
			   				copy(stack.data[f.gbase].space[8:], f.space[8:])
			   //				if len (stack.data[f.gbase].space) < len(f.space) {
			   //					append(stack.data[f.gbase].space, f.space[len (stack.data[f.gbase].space):]...)
			   //				}
			   				f.space = f.space[:0]
			   			}
			*/
		}
		*pc = int(target)
		stack.callTop++
		stack.data[stack.callTop] = f
		if stack.callTop > 1024 {
			return omega.ScriptError(omega.ErrInternal, "Call stack depth exceeds the max 1024 limit")
		}
		return nil
	}

	return omega.ScriptError(omega.ErrInternal, "Malformed function call")
}

func opLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	dataType := []byte{0xFF, 'Q', 'Z'}
	var err omega.Err
	var tl int
	var h []byte
	var store pointer
	top := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] == 'Z' {
				var hash chainhash.Hash
				if hash, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				} else {
					h = hash[:]
				}
			} else if dataType[top] == 'Q' {
				if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
					return err
				}
				if num >= 0 && num < (1<<32) {
					h = make([]byte, 4)
					binary.LittleEndian.PutUint32(h, uint32(num))
				} else {
					h = make([]byte, 8)
					binary.LittleEndian.PutUint64(h, uint64(num))
				}
			} else {
				if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
					return err
				}
				store = pointer(num)
			}
			top++
			j += tl

		case 'Z', 'z':
			top++
		}
	}

	d := evm.GetState(contract.self.Address(), string(h))

	var n uint32
	n = uint32(len(d))

	stack.saveInt32(&store, int32(n))
	store += 4
	p := store
	/*
		p,err := stack.toPointer(&store)
		if err != nil {
			return err
		}
	*/
	for i := uint32(0); i < n; i++ {
		if err := stack.saveByte(&p, d[i]); err != nil {
			return err
		}
		p++
	}

	//	log.Debugf("loading %x = %x (%d)", h, d, n)

	return nil
}

func opStore(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	//	{patOperand, 0}, - key
	//	{dataType, 0}, - Data type/length
	//	{patOperand, 0}, - Data
	if stack.data[stack.callTop].pure&NOWRITE != 0 {
		return omega.ScriptError(omega.ErrInternal, fmt.Sprintf("Store forbidden in lib %x", stack.data[stack.callTop].inlib))
	}

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := chainhash.Hash{}
	var tl int
	var err omega.Err
	var scratch [3][]byte
	top := 0 // indicate where we are wrt source syntax. 0 - key 1 - Data type/length 2 - Data
	idx := 0 // position in Data stack (scratch)

	dataType := []byte{'Q', 'L', 'B', 'B'}
	dt := byte('Q') // expected Data item type
	var dlen uint32
	dlen = sizeOfType[dt]
	fdlen := dlen
	dts := []byte{'Q', 'D', 'L'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'i', 'g', 'z', 'Z':
			if param[j] == 'g' || param[j] == 'i' {
				dt = dts[top]
			} else {
				dt = 'h'
			}
			fallthrough

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x':
			switch dt {
			case 'k', 'K', 'r', 'R':
				var num []byte
				if num, tl, err = stack.getBytes(param[j:], dt, 0); err != nil {
					return err
				}
				scratch[idx] = num
			case 'H', 'h':
				if num, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
				scratch[idx] = num[:]
			case 'L':
				var num []byte
				if num, tl, err = stack.getBytesLen(param[j:], dlen); err != nil {
					return err
				}
				scratch[idx] = num
			default:
				num := int64(0)
				if num, tl, err = stack.getNum(param[j:], dt); err != nil {
					return err
				}
				var d [8]byte
				binary.LittleEndian.PutUint64(d[:], uint64(num))
				if top == 0 && num >= 0 && num < (1<<32) {
					scratch[idx] = d[:4] // 4-byte index
				} else if top == 1 {
					dt = 'L'
					dlen = uint32(num)
					j += tl
					top++
					continue
				} else {
					scratch[idx] = d[:sizeOfType[dt]]
				}
			}
			fdlen = dlen
			top++
			dt = dataType[top]
			dlen = sizeOfType[dt]
			idx++
			j += tl

		case 'R', 'r', 'B', 'W', 'D', 'Q', 'H', 'h', 'k', 'K': // b
			// BWDQHA - byte, word, dword, qword, big int, hash, address
			dt = param[j]
			dlen = sizeOfType[dt]
			top++

		case 'L': // long Data
			dt = 'L'
			j++
			num := int64(0)
			if num, tl, err = stack.getNum(param[j:], 'D'); err != nil {
				return err
			}
			j += tl
			dlen = uint32(num)
		}
	}

	evm.SetState(contract.self.Address(), string(scratch[0]), scratch[1][:fdlen])

	return nil
}

func opDel(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var tl int

	var err omega.Err
	var d [8]byte
	var k []byte
	var dt byte

	dt = 'D'

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'D', 'Q':
			dt = param[j]

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num := int64(0)
			if num, tl, err = stack.getNum(param[j:], dt); err != nil {
				return err
			}
			binary.LittleEndian.PutUint64(d[:], uint64(num))
			if num >= 0 && num < (1<<32) {
				k = d[:4]
			} else {
				k = d[:]
			}
			j += tl
		}
	}
	evm.DeleteState(contract.self.Address(), string(k))

	return nil
}

func opReceived(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	outpoint := ovm.GetCurrentOutput()

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	var tl int
	var err omega.Err

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			//			var w bytes.Buffer
			//			if _, err := w.Write(outpoint.ToBytes()); err != nil {
			//				return err
			//			}

			var p pointer
			p = pointer(num)

			return stack.saveBytes(&p, outpoint.ToBytes())
		}
	}

	return nil
}

func opExec(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	// format: exec contract_addr,pure,return_receiver,coin,param_len,params
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	//	var bnum *big.Int
	top := 0

	var toAddr Address
	var value *token.Token
	var retspace pointer
	var data pointer
	var datalen int32
	var tl int
	var err omega.Err
	var args []byte
	var bl []byte

	pure := byte(0)

	paramTypes := []byte{'r', 'B', 0xFF, 0xFF, 0x44, 0xFF}

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 'r' {
				bl, tl, err = stack.getBytes(param[j:], 'r', 0)
				//			} else if dataType == 0x48 {
				//				bnum, tl, err = stack.getBig(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0: // contract address
				copy(toAddr[:], bl)

			case 1:
				pure = byte(num)

			case 2:
				// mem. location to accept result
				retspace = pointer(num)

			case 3:
				if num != 0 {
					value = &token.Token{}
					var r bytes.Reader
					if _, ok := stack.data[int32(num>>32)]; !ok {
						return omega.ScriptError(omega.ErrInternal, "Memory address fault")
					}
					r.Reset(stack.data[int32(num>>32)].space[num&0xFFFFFFFF:])
					value.Read(&r, 0, 0)
				}

			case 4:
				datalen = int32(num)

			case 5:
				data = pointer(num)
				if _, ok := stack.data[int32(data>>32)]; !ok {
					return omega.ScriptError(omega.ErrInternal, "Memory address fault")
				}
				if int(int64(data)&0xFFFFFFFF)+int(datalen) > len(stack.data[int32(data>>32)].space) {
					return omega.ScriptError(omega.ErrInternal, "Memory address fault")
				}
				args = stack.data[int32(data>>32)].space[data&0xFFFFFFFF : int32(int64(data)&0xFFFFFFFF)+datalen]

			default:
				return omega.ScriptError(omega.ErrInternal, "Malformed parameters")
			}
			top++
		}
	}

	pks := make([]byte, 25+len(args))
	pks[0] = 0x88
	copy(pks[1:], toAddr[:])
	copy(pks[21:], args)

	pure |= stack.data[stack.callTop].pure

	oldop := evm.GetCurrentOutput

	if (pure&0x1F) != 0x1F || (value != nil && (value.TokenType&1 != 0 ||
		(value.TokenType&1 == 0 && value.Value.(*token.NumToken).Val != 0))) {
		// if allowed to write something, will add a txout. note: can't decide
		// whether to add txout based on value given to the contract only, because
		// we determine Rollback Data based on presence of contract in txout
		tx := evm.GetTx()

		if tx == nil {
			return omega.ScriptError(omega.ErrInternal, "Contract call not in a transaction.")
		}
		msg := tx.MsgTx()
		if !tx.HasOuts {
			// this servers as a separater. only TokenType is serialized
			to := wire.TxOut{}
			to.Token = token.Token{TokenType: token.DefTypeSeparator}
			msg.AddTxOut(&to)
			tx.HasOuts = true
			evm.exeout = append(evm.exeout, true)
		}
		evm.exeout = append(evm.exeout, true)
		op := uint32(msg.AddTxOut(&wire.TxOut{PkScript: pks, Token: *value}))

		evm.GetCurrentOutput = func() wire.OutPoint {
			return wire.OutPoint{oldop().Hash, op}
		}
	}

	for _, d := range evm.contractStack {
		if d == toAddr {
			return omega.ScriptError(omega.ErrInternal, "Circular contract calls.")
		}
	}
	evm.contractStack = append(evm.contractStack, toAddr)

	ret, err := evm.Call(toAddr, args[:4], value, args, pure) // nil=>value
	evm.contractStack = evm.contractStack[:len(evm.contractStack)-1]

	evm.GetCurrentOutput = oldop

	evm.StateDB[toAddr].spendables[evm.GetCurrentOutput()] = struct{}{}

	if err != nil {
		return err
	}

	m := len(ret)
	if retspace != 0 {
		var p pointer
		if m > 0 {
			if int32(retspace>>32) == stack.callTop {
				p, _ = stack.alloc(m)
			} else {
				p, _ = stack.malloc(m)
			}
			if _, ok := stack.data[int32(p>>32)]; !ok {
				return omega.ScriptError(omega.ErrInternal, "Memory address fault")
			}
			copy(stack.data[int32(p>>32)].space[p&0xFFFFFFFF:], ret)
			if err := stack.saveInt64(&retspace, int64(p)); err != nil {
				return err
			}
		} else if err := stack.saveInt64(&retspace, 0); err != nil {
			return err
		}
		retspace += 8
		if err := stack.saveInt32(&retspace, int32(m)); err != nil {
			return err
		}
	}

	return err
}

func opLibLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var bnum []byte
	top := 0

	pure := byte(0)
	var tl int
	var err omega.Err

	paramTypes := []byte{'B', 'L', 'Q'}
	f := newFrame()

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case '@':
			if top == 2 {
				paramTypes[top] = 0xFF
			}

		case 'B', 'W', 'D', 'Q':
			if top == 2 {
				paramTypes[top] = param[j]
			}

		case 'H':
			if top == 2 {
				paramTypes[top] = 'Q'
			}

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 'L' {
				bnum, tl, err = stack.getBytes(param[j:], 'r', 0)
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				pure = byte(num)
				top++

			case 1:
				var d [20]byte

				entry := int32(len(contract.Code))

				copy(d[:], bnum[:20])
				_, ok := contract.libs[d]
				if ok {
					//					if pure & INHERIT == 0 {	always
					*pc++
					//					}
					return nil
				}

				//				if _, xt := evm.StateDB[d]; !xt {	 always
				sd := NewStateDB(evm.views.Db, d)

				existence := sd.Exists(true)
				if !existence {
					return omega.ScriptError(omega.ErrInternal, "The library does not exist")
				}
				evm.StateDB[d] = sd
				//				}

				ccode := ByteCodeParser(evm.GetCode(d))
				contract.Code = append(contract.Code, ccode...)

				if pure&INHERIT == 0 {
					stack.libTop--
					if stack.libTop < -1024 {
						return omega.ScriptError(omega.ErrInternal, "Lib loaded exceeds the max 1024 limit")
					}

					contract.libs[d] = lib{
						address: entry,
						end:     entry + int32(len(ccode)),
						base:    stack.libTop,
						pure:    pure,
					}

					g := newFrame()
					g.inlib, g.gbase, g.pure = d, stack.libTop, pure
					g.space = append(g.space, []byte{4, 0, 0, 0, 0, 0, 0, 0, OP_INIT, 0, 0, 0}...)
					binary.LittleEndian.PutUint32(g.space[4:], uint32(contract.libs[d].base))
					stack.data[stack.libTop] = g

					// execute init call
					f.space = append(f.space, []byte{4, 0, 0, 0, 0, 0, 0, 0}...)
					binary.LittleEndian.PutUint32(f.space[4:], uint32(stack.callTop+1))

					var bn [4]byte
					binary.LittleEndian.PutUint32(bn[:], uint32(OP_INIT)) // entry point for init()
					f.space = append(f.space, bn[:]...)
					f.space = append(f.space, []byte{0, 0, 0, 0}...)
					f.pc = *pc
					f.pure = pure | stack.data[stack.callTop].pure
					f.inlib = d
					f.gbase = contract.libs[d].base

					stack.callTop++
					stack.data[stack.callTop] = f
				} else if stack.callTop != 0 || stack.libTop != 0 {
					return omega.ScriptError(omega.ErrInternal, "Improper use of contract inheritance")
				} else {
					contract.libs[d] = lib{
						address: entry,
						end:     entry + int32(len(ccode)),
						base:    0,
						pure:    pure,
					}

					stack.data[0].pure |= pure

					lb := contract.libs[stack.data[0].inlib]
					lb.end = int32(len(contract.Code))

					contract.libs[stack.data[0].inlib] = lb
				}
				*pc = int(entry)
				top++

			case 2:
				ln := binary.LittleEndian.Uint32(f.space[:4])
				ln += 8
				binary.LittleEndian.PutUint32(f.space[:4], ln)

				var bn [8]byte
				binary.LittleEndian.PutUint64(bn[:], uint64(num))
				f.space = append(f.space[ln:], bn[:]...)
			}
		}
	}
	if top == 2 {
		return nil
	}
	return omega.ScriptError(omega.ErrInternal, "Malformed parameters")
}

func opMalloc(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	return opMAalloc(pc, evm, contract, stack, true)
}

func opMAalloc(pc *int, evm *OVM, contract *Contract, stack *Stack, glob bool) omega.Err {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	top := 0
	var tl int
	var err omega.Err

	var retspace pointer
	paramType := []byte{0xFF, 'D'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'B', 'W', 'D', 'Q':
			if top == 1 {
				paramType[top] = param[j]
			}

		case 'H':
			if top == 1 {
				paramType[top] = 'Q'
			}

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], paramType[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				retspace = pointer(num)

			case 1:
				var p pointer

				total := uint64(num)
				for _, k := range stack.data {
					total += uint64(len(k.space))
				}
				if total >= 0x40000000 {
					return omega.ScriptError(omega.ErrInternal, "Memory requested exceeds 1GB")
				}

				if glob {
					p, _ = stack.malloc(int(num))
				} else {
					p, _ = stack.alloc(int(num))
				}

				if retspace != 0 {
					return stack.saveInt64(&retspace, int64(p))
				}

				return nil
			}
			top++
		}
	}
	return omega.ScriptError(omega.ErrInternal, "Malformed parameters")
}

func opAlloc(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	return opMAalloc(pc, evm, contract, stack, false)
}

func opCopy(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var src pointer
	var dest pointer
	var tl int
	var err omega.Err

	var dtype = []byte{0xFF, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'B', 'W', 'D', 'Q':
			if top == 2 {
				dtype[top] = param[j]
			}

		case 'H':
			if top == 2 {
				dtype[top] = 'Q'
			}

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dtype[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				src = pointer(num)

			case 2:
				sb, err := stack.toBytesLen(&src, int(num))
				if err != nil {
					return err
				}
				err = stack.saveBytes(&dest, sb)
				if err != nil {
					return err
				}

				//				num += int64(src) & 0xFFFFFFFF
				//				copy(stack.Data[dest >> 32].space[dest & 0xFFFFFFFF:], stack.Data[src >> 32].space[src & 0xFFFFFFFF:num])
				return nil
			}
			top++
		}
	}
	return omega.ScriptError(omega.ErrInternal, "Malformed parameters")
}

func opCopyImm(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)

	var dest pointer
	var tl int
	var err omega.Err
	var h []byte
	var hash chainhash.Hash
	var dlen int64

	dataType := byte(0xFF)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'R', 'r', 'B', 'W', 'D', 'Q', 'H', 'h', 'k', 'K': // b
			dataType = param[j]

		case 'L':
			dataType = 'L'
			if dlen, tl, err = stack.getNum(param[j+1:], dataType); err != nil {
				return err
			}
			j += tl + 1

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			switch dataType {
			case 0xFF, 'B', 'D', 'W', 'Q':
				if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
					return err
				}
			case 'k', 'K', 'r', 'R':
				if h, tl, err = stack.getBytes(param[j:], dataType, 0); err != nil {
					return err
				}
			case 'h', 'H':
				if hash, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
			case 'L':
				if h, tl, err = stack.getBytes(param[j:], dataType, uint32(dlen)); err != nil {
					return err
				}
			}
			j += tl

			switch dataType {
			case 0xFF:
				dest = pointer(num)

			case 'B':
				if err := stack.saveByte(&dest, byte(num)); err != nil {
					return err
				}
				dest++

			case 'D':
				if err := stack.saveInt32(&dest, int32(num)); err != nil {
					return err
				}
				dest += 4

			case 'Q':
				if err := stack.saveInt64(&dest, num); err != nil {
					return err
				}
				dest += 8

			case 'W':
				if err := stack.saveInt16(&dest, int16(num)); err != nil {
					return err
				}
				dest += 2

			case 'k', 'K', 'r', 'R':
				if err := stack.saveBytes(&dest, h); err != nil {
					return err
				}
				dest += 32

			case 'h', 'H':
				if err := stack.saveHash(&dest, hash); err != nil {
					return err
				}
				dest += 32

			case 'L':
				if err := stack.saveBytes(&dest, h[:dlen]); err != nil {
					return err
				}
				dest += pointer(dlen)
			}
		}
	}

	return nil
}

func opTxFee(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var dest pointer
	var tl int
	var err omega.Err
	dataType := []byte{0xFF, 'B'}

	zeroHash := chainhash.Hash{}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				tx := evm.GetTx()
				if tx == nil {
					return omega.ScriptError(omega.ErrInternal, "Contract call not in a transaction.")
				}
				msgTx := tx.MsgTx()
				serializedSize := int64(msgTx.SerializeSize())

				n := 0
				storage := int64(0) // storage fees need to be paid by this tx

				//				v2 := blockversion >= chaincfg.Version2
				v2 := evm.BlockNumber() >= 5463957 // since we don't have all block info., we hard code height where vwesion 2 begins
				minFee := int64(0)

				if v2 {
					serializedSize = int64(msgTx.SerializeSizeFull())
					for _, d := range msgTx.TxDef {
						if d.DefType() == token.DefTypeBorder && d.(*token.BorderDef).Father.IsEqual(&zeroHash) {
							n++
						}
					}

					storagefees := make(map[[20]byte]int64)
					paidstoragefees := make(map[[20]byte]int64)

					for _, txOut := range msgTx.TxOut {
						if txOut.IsSeparator() || !chaincfg.IsContractAddrID(txOut.PkScript[0]) {
							continue
						}

						var addr [20]byte
						copy(addr[:], txOut.PkScript[1:21])
						if _, ok := storagefees[addr]; !ok {
							storagefees[addr] = int64(evm.NewUage(addr))
						}
					}

					for addr, t := range storagefees {
						if t <= 0 {
							continue
						}
						if s, ok := paidstoragefees[addr]; ok {
							if t <= s {
								continue
							}
							storage += t - s
						} else {
							storage += t
						}
						paidstoragefees[addr] = t
					}
					if num&1 != 0 {
						serializedSize += 256 // add an input
					}
					if num&2 != 0 {
						serializedSize += 140 // add an output
					}
					minFee = int64(n*evm.chainConfig.MinBorderFee) + evm.chainConfig.MinRelayTxFee*(storage+serializedSize)/1000
				} else {
					if num&1 != 0 {
						serializedSize += 44 // add an input
					}
					if num&2 != 0 {
						serializedSize += 35 // add an output
					}
					minFee = (serializedSize * int64(evm.chainConfig.MinRelayTxFee)) / 1000
				}

				if minFee == 0 && evm.chainConfig.MinRelayTxFee > 0 {
					minFee = int64(evm.chainConfig.MinRelayTxFee)
				}

				if minFee < 0 || minFee > btcutil.MaxHao {
					minFee = btcutil.MaxHao
				}

				if err := stack.saveInt64(&dest, minFee); err != nil {
					return err
				}

				return nil
			}
			top++
		}
	}
	return omega.ScriptError(omega.ErrInternal, "Malformed parameters")
}

func opSuicide(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	if contract.pure != 0 {
		return omega.ScriptError(omega.ErrInternal, "Suicide instruction restricted by contract right")
	}

	param := contract.GetBytes(*pc)

	ln := len(param)

	var tl int
	var err omega.Err
	var h []byte
	var dlen int64
	top := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if top == 0 {
				if dlen, tl, err = stack.getNum(param[j:], 'D'); err != nil {
					return err
				}
			} else {
				if h, tl, err = stack.getBytesLen(param[j:], uint32(dlen)); err != nil {
					return err
				}
			}
			j += tl
			top++
		}
	}

	mtype, _ := evm.StateDB[contract.Address()].GetMint()
	if dlen != 0 && len(h) > 20 && mtype != -1 {
		// exec contract
		version, addr, method, cparam := parsePkScript(h)

		if addr == nil {
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}
		if zeroaddr(addr) {
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}
		if !isContract(version) {
			return omega.ScriptError(omega.ErrInternal, "Script is not a contract exec.")
		}

		var d Address
		copy(d[:], addr)

		if d == contract.Address() {
			return omega.ScriptError(omega.ErrInternal, "Trying to trans mint to itself.")
		}

		if _, ok := evm.StateDB[d]; !ok {
			t := NewStateDB(evm.views.Db, d)

			if !t.Exists(true) {
				return omega.ScriptError(omega.ErrInternal, "Contract does not exist.")
			}

			evm.StateDB[d] = t
		}

		for _, toAddr := range evm.contractStack {
			if d == toAddr {
				return omega.ScriptError(omega.ErrInternal, "Circular contract calls.")
			}
		}

		tx := evm.GetTx()
		if tx == nil {
			return omega.ScriptError(omega.ErrInternal, "Contract call not in a transaction.")
		}
		msg := tx.MsgTx()
		if !tx.HasOuts {
			// this servers as a separater. only TokenType is serialized
			to := wire.TxOut{}
			to.Token = token.Token{TokenType: token.DefTypeSeparator}
			msg.AddTxOut(&to)
			tx.HasOuts = true
		}
		msg.AddTxOut(&wire.TxOut{PkScript: h, Token: token.Token{0, &token.NumToken{0}, nil}})

		evm.contractStack = append(evm.contractStack, d)
		evm.TokenTypes[uint64(mtype)] = contract.Address()

		evm.StateDB[contract.Address()].transferrable = true
		_, err := evm.Call(d, method, nil, cparam, 0)

		if evm.StateDB[contract.Address()].transferrable {
			err = omega.ScriptError(omega.ErrInternal, "Mint right not transferred.")
		}
		if err != nil {
			evm.StateDB[contract.Address()].transferrable = false
			evm.TokenTypes[uint64(mtype)] = contract.Address()
			return err
		}
	} else if dlen != 0 || h != nil {
		return omega.ScriptError(omega.ErrInternal, "Bad suicide instruction")
	}

	evm.StateDB[contract.Address()].Suicide()
	return nil
}

func opRevert(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	return nil
}

func opStop(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	return nil
}

func opReturn(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	if stack.callTop <= 0 {
		return nil
	}
	*pc = stack.data[stack.callTop].pc
	//	contract.pure = stack.Data[stack.callTop].pure
	delete(stack.data, stack.callTop)
	stack.callTop--

	if !debugging || !dbgreturn {
		return nil
	}

	dbgreturn = false

	var buf [4]byte

	log.Infof("opReturn: break at %d", *pc)

	common.LittleEndian.PutUint32(buf[:], uint32((*pc)-dbgcodebase))
	Control <- &DebugCmd{Reply: nil, Data: buf[:], Cmd: Breaked}

	log.Infof("opReturn: waiting inspector")

	select {
	case <-inspector:
	case <-time.After(5 * time.Minute):
		// if no activity in 5 min., cancel debugging
		debugging = false
	}

	return nil
}

var negHash = chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

func opSpend(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	if stack.data[stack.callTop].pure&NOSPENDING != 0 {
		return omega.ScriptError(omega.ErrInternal, "Spend instruction restricted by contract right")
	}

	param := contract.GetBytes(*pc)

	ln := len(param)

	var dtype = []byte{0x68, 0x44, 0xFF} // hash, index, optional sig
	top := 0
	p := wire.OutPoint{}
	var sig pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'B', 'W', 'D':
			dtype[1] = param[j]

		case 'H', 'Q':
			dtype[1] = 'D'

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dtype[top] == 0x68 {
				if hash, tl, err := stack.getHash(param[j:]); err != nil {
					return err
				} else {
					j += tl
					p.Hash = hash
				}
				top++
			} else {
				if num, tl, err := stack.getNum(param[j:], dtype[top]); err != nil {
					return err
				} else {
					j += tl
					if dtype[top] == 0x44 {
						p.Index = uint32(num)
					} else {
						sig = pointer(num)
					}
					top++
				}
			}
		}
	}

	if p.Hash.IsEqual(&chainhash.Hash{}) && sig == 0 {
		// it is ok to add a separator (p.Index == 0) or padding (p.Index != 0)
		evm.Spend(p, nil)
	} else if sig == pointer(0) {
		// validate outpoint: it belongs to this contract
		u := evm.GetUtxo(p.Hash, uint64(p.Index))
		var pks []byte
		if u == nil {
			cb := evm.GetCoinBase()
			cbh := cb.Hash()
			if bytes.Compare(p.Hash[:], negHash[:]) == 0 || bytes.Compare(p.Hash[:], (*cbh)[:]) == 0 {
				pks = cb.MsgTx().TxOut[p.Index].PkScript
			}
		} else {
			pks = u.PkScript
		}

		addr := contract.Address()

		if pks == nil {
			if _, ok := evm.StateDB[addr].spendables[p]; !ok {
				return omega.ScriptError(omega.ErrInternal, "Contract try to spend what does not exist. UTXO = "+p.Hash.String())
			}
			delete(evm.StateDB[addr].spendables, p)
		} else {
			if !isContract(pks[0]) || bytes.Compare(pks[1:21], addr[:]) != 0 {
				return omega.ScriptError(omega.ErrInternal, "Contract try to spend what does not belong to it.")
			}
		}

		if evm.Spend(p, nil) {
			log.Debugf("Spend: %s:%d", p.Hash.String(), p.Index)
			return nil
		}
	} else {
		d, err := stack.toInt32(&sig) // len of sig
		if err != nil {
			return err
		}
		sig += 4
		loc := int32(sig & 0xFFFFFFFF) // begininning of sig data
		if evm.Spend(p, stack.data[int32(int64(sig)>>32)].space[loc:loc+d]) {
			log.Debugf("Spend: %s:%d", p.Hash.String(), p.Index)
			return nil
		}
	}

	return omega.ScriptError(omega.ErrInternal, "Spend failed")
}

func opAddDef(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	if contract.pure&NODEFINE != 0 {
		return omega.ScriptError(omega.ErrInternal, "AddDef instruction restricted by contract right")
	}

	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err omega.Err
	var defType byte
	dest := pointer(0)

	var coinbase = false

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			dest = pointer(num)
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

		case '@': // @

		case 'C':
			coinbase = true

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
	}

	if _, ok := stack.data[int32(num>>32)]; !ok {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	defType = stack.data[int32(num>>32)].space[num&0xFFFFFFFF]
	var tk token.Definition

	switch defType {
	case token.DefTypeBorder:
		tk = &token.BorderDef{}

	case token.DefTypePolygon:
		tk = &token.PolygonDef{}

	case token.DefTypeRight:
		tk = &token.RightDef{}

	case token.DefTypeRightSet:
		tk = &token.RightSetDef{}

	default:
		return omega.ScriptError(omega.ErrInternal, "Unknown definition type")
	}

	var r bytes.Reader

	num++
	r.Reset(stack.data[int32(num>>32)].space[num&0xFFFFFFFF:])
	if err := tk.MemRead(&r, 0); err != nil {
		e := omega.ScriptError(omega.ErrInternal, err.Error())
		return e
	}

	hash := evm.AddDef(tk, coinbase)

	if dest != pointer(0) {
		stack.saveHash(&dest, hash)
	}

	return nil
}

func opGetIOCount(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	num := int64(0)
	var err omega.Err
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '@':

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, _, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			dest = pointer(num)

			tx := evm.GetTx()
			if tx == nil {
				return omega.ScriptError(omega.ErrInternal, "Contract call not in a transaction.")
			}
			count := int32(len(tx.MsgTx().TxIn) | (len(tx.MsgTx().TxOut) << 16))

			if dest != 0 {
				stack.saveInt32(&dest, count)
			}

			return nil
		}
	}

	return omega.ScriptError(omega.ErrInternal, "Malformed expression")
}

func opAddTxOut(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	if stack.data[stack.callTop].pure&NOOUTPUT != 0 {
		return omega.ScriptError(omega.ErrInternal, fmt.Sprintf("AddTxOut forbidden in lib %x", stack.data[stack.callTop].inlib))
	}

	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err omega.Err
	top := 0
	var dest pointer
	var src pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '@':

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			if top == 1 {
				dest = src
			} else if top > 1 {
				return omega.ScriptError(omega.ErrInternal, "Malformed expression")
			}

			src = pointer(num)
			top++

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
	}

	tk := wire.TxOut{}
	num = int64(src)

	var r bytes.Reader

	if _, ok := stack.data[int32(num>>32)]; !ok {
		return omega.ScriptError(omega.ErrInternal, "Memory address fault")
	}

	r.Reset(stack.data[int32(num>>32)].space[num&0xFFFFFFFF : (num&0xFFFFFFFF)+100])
	if err := tk.Read(&r, 0, 0, wire.SignatureEncoding); err != nil {
		e := omega.ScriptError(omega.ErrInternal, err.Error())
		return e
	}

	var zeroaddr [20]byte
	if tk.TokenType != token.DefTypeSeparator && (len(tk.PkScript) < 21 || bytes.Compare(tk.PkScript[1:21], zeroaddr[:]) == 0) {
		return omega.ScriptError(omega.ErrInternal, "Address is invalid.")
	}

	me := contract.self.Address()
	if isContract(tk.PkScript[0]) {
		if bytes.Compare(tk.PkScript[1:21], me[:]) != 0 {
			return omega.ScriptError(omega.ErrInternal, "Contract may not add a txout outside scope")
		}
	} else if tk.TokenType != token.DefTypeSeparator {
		// check address is valid type & net
		netID := tk.PkScript[0]
		isP2PKH := evm.chainConfig.PubKeyHashAddrID == netID
		isP2SH := evm.chainConfig.ScriptHashAddrID == netID
		isMSig := evm.chainConfig.MultiSigAddrID == netID

		if !isP2PKH && !isP2SH && !isMSig {
			e := omega.ScriptError(omega.ErrInternal, btcutil.ErrUnknownAddressType.Error())
			return e
		}
	}

	seq := evm.AddTxOutput(tk)

	if seq < 0 {
		return omega.ScriptError(omega.ErrInternal, "Malformed expression")
	}

	if isContract(tk.PkScript[0]) {
		op := evm.GetCurrentOutput()
		op.Index = uint32(seq)
		evm.StateDB[me].spendables[op] = struct{}{}
	}

	if dest != 0 && top == 2 {
		stack.saveInt32(&dest, int32(seq))
	}

	if (tk.TokenType & 1) == 0 {
		log.Debugf("Text out added as %d: type = %d value = %d to %x", seq, tk.TokenType, tk.Token.Value.(*token.NumToken).Val, tk.PkScript[1:21])
	} else {
		log.Debugf("Text out added as %d: type = %d value = %s to %x", seq, tk.TokenType, tk.Token.Value.(*token.HashToken).Hash.String(), tk.PkScript[1:21])
	}

	return nil
}

func opGetDefinition(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	var num int64
	var hash chainhash.Hash
	var dest pointer
	defType := uint8(0)
	var tl int
	var err error

	dataType := []byte{0xFF, 0x68, 0x42}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '@':
			dataType[top] = 0xFF

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] == 0x68 {
				hash, tl, err = stack.getHash(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			}
			if err != nil {
				e := omega.ScriptError(omega.ErrInternal, err.Error())
				return e
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)
			case 1:

			case 2:
				defType = byte(num)
			}
			top++

		default:
			return omega.ScriptError(omega.ErrInternal, "Malformed expression")
		}
	}

	tx := evm.GetTx()

	if tx != nil {
		for _, def := range tx.MsgTx().TxDef {
			if def.IsSeparator() {
				continue
			}
			h := def.Hash()
			if h.IsEqual(&hash) {
				var w bytes.Buffer
				def.MemWrite(&w, 0)
				stack.saveBytes(&dest, w.Bytes())
				return nil
			}
		}
	}

	var t token.Definition

	switch defType {
	case token.DefTypeBorder:
		b, err := evm.views.FetchBorderEntry(&hash)
		if err != nil {
			t = token.NewBorderDef(token.VertexDef{}, token.VertexDef{}, chainhash.Hash{})
		} else {
			t = token.Definition(b.ToToken())
		}

	case token.DefTypePolygon:
		b, err := evm.views.FetchPolygonEntry(&hash)
		if err != nil {
			t = token.NewPolygonDef(make([]token.LoopDef, 0))
		} else {
			t = token.Definition(b.ToToken())
		}

	case token.DefTypeRight:
		b, err := evm.views.FetchRightEntry(&hash)
		if err != nil {
			t = token.NewRightDef(chainhash.Hash{}, []byte{}, 0)
		} else {
			t = token.Definition(b.(*viewpoint.RightEntry).ToToken())
		}

	case token.DefTypeRightSet:
		b, err := evm.views.FetchRightEntry(&hash)
		if err != nil {
			t = token.NewRightSetDef([]chainhash.Hash{})
		} else {
			t = token.Definition(b.(*viewpoint.RightSetEntry).ToToken())
		}

	default:
		return omega.ScriptError(omega.ErrInternal, "Unknown definition type")
	}

	var w bytes.Buffer
	t.MemWrite(&w, 0)
	return stack.saveBytes(&dest, w.Bytes())
}

func opGetUtxo(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	// dest, hash, [index type], index, [scriptlen]

	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	num := int64(0)
	var dest pointer
	var tx chainhash.Hash
	var seq int32
	var tl int
	var err omega.Err

	doscript := false

	dataType := []byte{0xFF, 0x68, 0x44, 'B'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'B', 'W', 'D':
			dataType[2] = param[j]

		case 'H', 'Q':
			dataType[2] = 'D'

		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] != 0x68 {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			} else {
				tx, tl, err = stack.getHash(param[j:])
			}
			if err != nil {
				e := omega.ScriptError(omega.ErrInternal, err.Error())
				return e
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)
			case 1:

			case 2:
				seq = int32(num)

			case 3:
				doscript = num != 0
			}
			top++
		}
	}

	t := evm.GetUtxo(tx, uint64(seq))

	if t == nil {
		if err := stack.saveInt64(&dest, int64(-1)); err != nil {
			return err
		}
		return nil
	}

	coin := t.Token

	var w bytes.Buffer
	if err := coin.Write(&w, 0, 0); err != nil {
		e := omega.ScriptError(omega.ErrInternal, err.Error())
		return e
	}
	if err := stack.saveBytes(&dest, w.Bytes()); err != nil {
		return err
	}

	dest += pointer(w.Len())

	if t.PkScript != nil {
		var pkl = int32(len(t.PkScript))
		if err := stack.saveInt32(&dest, pkl); err != nil {
			return err
		}

		if !doscript {
			return nil
		}

		dest += 4
		if len(t.PkScript) <= int(num) {
			return stack.saveBytes(&dest, t.PkScript)
		}
		return stack.saveBytes(&dest, t.PkScript[:num])
	} else {
		if err := stack.saveInt32(&dest, 0); err != nil {
			return err
		}
		return nil
	}
}

func opGetCoin(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	num := int64(0)
	var dest pointer
	var err omega.Err

	num, _, err = stack.getNum(param[:], 0xFF)
	if err != nil {
		return err
	}
	dest = pointer(num)

	tx := evm.GetTx()

	if tx == nil {
		return omega.ScriptError(omega.ErrInternal, "No transaction exists. Running in call mode instead of transaction mode?")
	}

	op := evm.GetCurrentOutput()
	coin := tx.MsgTx().TxOut[op.Index].Token

	if err := stack.saveInt64(&dest, int64(coin.TokenType)); err != nil {
		return err
	}
	dest += 8
	if coin.TokenType&1 == 0 {
		if err := stack.saveInt64(&dest, coin.Value.(*token.NumToken).Val); err != nil {
			return err
		}
		dest += 8
	} else {
		if err := stack.saveHash(&dest, coin.Value.(*token.HashToken).Hash); err != nil {
			return err
		}
		dest += 32
	}
	if coin.TokenType&2 == 2 {
		if coin.Rights != nil {
			if err := stack.saveHash(&dest, *coin.Rights); err != nil {
				return err
			}
		} else {
			if err := stack.saveHash(&dest, chainhash.Hash{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func opNul(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	// this instruction is for debugging purpose, so we can insert a nul op in contract
	// and set a break point here
	if !debugging {
		return nil
	}

	if dbgcontract == nil {
		c := stack.data[stack.callTop].gbase
		setdbgcontract(contract, Address(stack.data[c].inlib), stack)
		log.Info("contract going")
	}

	if breakpoints[(*pc)-dbgcodebase] || stepping {
		var buf [4]byte

		log.Infof("opNul: break at %d", *pc)

		common.LittleEndian.PutUint32(buf[:], uint32((*pc)-dbgcodebase))
		Control <- &DebugCmd{Reply: nil, Data: buf[:], Cmd: Breaked}

		log.Infof("opNul: waiting inspector")

		select {
		case <-inspector:
		case <-time.After(5 * time.Minute):
			// if no activity in 5 min., cancel debugging
			debugging = false
		}
		log.Infof("opNul: continue")
	}
	return nil
}

var (
	errWriteProtection       = omega.ScriptError(omega.ErrInternal, "evm: write protection")
	errReturnDataOutOfBounds = omega.ScriptError(omega.ErrInternal, "evm: return Data out of bounds")
	errExecutionReverted     = omega.ScriptError(omega.ErrInternal, "evm: execution reverted")
	errMaxCodeSizeExceeded   = omega.ScriptError(omega.ErrInternal, "evm: max code size exceeded")
)

const (
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
)

var tt256 = new(big.Int).Lsh(big.NewInt(2), 256)
var tt256m1 = new(big.Int).Sub(tt256, big.NewInt(1))

func U256(y *big.Int) *big.Int {
	y.And(y, tt256m1)
	return y
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

func opMint(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	if stack.data[stack.callTop].pure&NOMINT != 0 || stack.data[stack.callTop].gbase != 0 {
		return omega.ScriptError(omega.ErrInternal, "Unauthorized minting.")
	}
	//	{addrOperand, 0xFFFFFFFF}, - return Data place holder
	//	{patOperand, 0}, - tokentype
	//	{patOperand, 0}, - amount / hash
	//	{patOperand, 0}, - right
	// mint coins.
	param := contract.GetBytes(*pc)
	address := contract.self.Address()

	ln := len(param)

	top := 0
	num := int64(0)
	var dest pointer
	var tl int
	var md uint64 // numeric value
	var err omega.Err
	var h chainhash.Hash // hash token's hash
	var r chainhash.Hash // right hash
	var tokentype uint64

	dataType := []byte{0xFF, 'Q', 'Q', 'h'}

	if ovm.BlockVersion() < wire.Version2 {
		dataType[2] = 'D'
	}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] == 'h' {
				r, tl, err = stack.getHash(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			}
			if err != nil {
				e := omega.ScriptError(omega.ErrInternal, err.Error())
				return e
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				tokentype = uint64(num)
				if tokentype&1 == 1 {
					dataType[top+1] = 'h'
				}

			case 2:
				if tokentype&1 == 1 {
					h = r
					md = 1
				} else {
					md = uint64(num)
				}

			case 3:
			}
			top++
		}
	}

	if tokentype >= (0x1 << 40) { // 5 bytes for tokentype. 3 bytes reserved as chain id in chain family
		return omega.ScriptError(omega.ErrInternal, fmt.Sprintf("The tokentype %d exceeds the max limit.", tokentype))
	}

	if mtype, _ := ovm.StateDB[address].GetMint(); mtype == -1 {
		var mtk [8]byte
		binary.LittleEndian.PutUint64(mtk[:], tokentype)
		// mint for the first time. fail if the tokentype has been issued.
		ovm.StateDB[address].DB.View(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
			adr := bucket.Get(mtk[:])
			if adr != nil {
				var addr [20]byte
				copy(addr[:], adr)
				ovm.TokenTypes[tokentype] = addr
				ovm.ExistingTokenTypes[tokentype] = addr
			} else {
				ovm.TokenTypes[tokentype] = address
			}
			return nil
		})

		if adr := ovm.TokenTypes[tokentype]; adr != address {
			if t, ok := ovm.StateDB[adr]; ok && t.transferrable {
				_, issue := t.GetMint()
				ovm.TokenTypes[tokentype] = address
				t.transferrable = false
				c := make([]byte, 16)

				binary.LittleEndian.PutUint64(c, tokentype)
				binary.LittleEndian.PutUint64(c[8:], issue)

				ovm.setMeta(address, "mint", c[:])
				return nil
			}
			return omega.ScriptError(omega.ErrInternal, "The tokentype %d has already been used by another smart contract.")
		}
	}

	if !ovm.setMint(address, tokentype, md) {
		return omega.ScriptError(omega.ErrInternal, "Unable to mint.")
	}

	issued := token.Token{
		TokenType: tokentype,
	}

	toissue := true
	if tokentype&1 == 0 {
		issued.Value = &token.NumToken{int64(md)}
		toissue = (md != 0)
	} else {
		issued.Value = &token.HashToken{h}
		zeroHash := chainhash.Hash{}
		toissue = (!h.IsEqual(&zeroHash))
	}
	if (tokentype & 2) == 2 {
		if top != 4 {
			return omega.ScriptError(omega.ErrInternal, "Incorrect number of parameters for mint inst.")
		}
		zeroHash := chainhash.Hash{}
		if zeroHash.IsEqual(&r) {
			if toissue {
				return omega.ScriptError(omega.ErrInternal, "Zero hash as right set in mint inst.")
			}
		} else {
			/*
				h, err := ovm.views.FetchRightEntry(&r)
				if err != nil || h == nil {
					toissue = true
				}
			*/
			toissue = true

			issued.Rights = &r
		}
	}

	if err = stack.saveInt64(&dest, int64(tokentype)); err != nil {
		return err
	}
	dest += 8

	// add a tx out in coinbase
	if toissue {
		txo := wire.TxOut{}
		txo.Token = issued
		txo.PkScript = make([]byte, 21)
		txo.PkScript[0] = 0x88
		copy(txo.PkScript[1:], address[:])

		outpoint := ovm.AddCoinBase(txo)

		if err = stack.saveHash(&dest, outpoint.Hash); err != nil {
			return err
		}
		dest += 32
		return stack.saveInt32(&dest, int32(outpoint.Index))
	}
	return nil
}

func opMeta(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)
	address := contract.self.Address()

	ln := len(param)

	top := 0
	num := int64(0)
	slen := int64(0)
	var dest pointer
	var tl int
	var err omega.Err
	var key string
	var r []byte

	dataType := []byte{0xFF, 'B', 'h'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] == 'h' {
				r, tl, err = stack.getBytes(param[j:], 'h', 0)
			} else {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				slen = num

			case 2:
				key = string(r[:slen])
			}
			top++
		}
	}

	m := ovm.GetMeta(address, key)

	if err = stack.saveInt32(&dest, int32(len(m))); err != nil {
		return err
	}
	dest += 4
	return stack.saveBytes(&dest, m)
}

func opTime(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err := stack.getNum(param[j:], 0xFF)
			if err != nil {
				return err
			}
			j += tl

			dest = pointer(num)
		}
	}

	m := ovm.BlockTime()
	return stack.saveInt32(&dest, int32(m))
}

func opHeight(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err := stack.getNum(param[j:], 0xFF)
			if err != nil {
				return err
			}
			j += tl

			dest = pointer(num)

		}
	}

	m := ovm.BlockNumber()
	return stack.saveInt32(&dest, int32(m))
}

func opVersion(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err := stack.getNum(param[j:], 0xFF)
			if err != nil {
				return err
			}
			j += tl

			dest = pointer(num)

		}
	}

	tx := ovm.GetTx()
	m := int32(1) // default version
	if tx != nil {
		m = tx.MsgTx().Version
	}
	return stack.saveInt32(&dest, m)
}

func opTokenContract(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	num := int64(0)
	var dest pointer
	var tl int
	var err omega.Err
	var addr []byte

	dataType := []byte{0xFF, 'Q'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err = stack.getNum(param[j:], dataType[top])
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)
			}
			top++
		}
	}

	ovm.DB.View(func(dbTx database.Tx) error {
		var mtk [8]byte
		common.LittleEndian.PutUint64(mtk[:], uint64(num))

		var IssuedTokenTypes = []byte("issuedTokens")

		bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
		addr = bucket.Get(mtk[:])
		return nil
	})
	if addr == nil {
		addr = make([]byte, 20)
	}

	return stack.saveBytes(&dest, addr)
}

func opLog(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	num := int64(0)
	var header pointer
	var src pointer
	var tl int
	var err omega.Err
	var dtype byte

	dataType := []byte{'Q', 'Q', 'D'}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err = stack.getNum(param[j:], dataType[top])
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				header = pointer(num)

			case 1:
				src = pointer(num)
			}
			top++

		case 'B', 'C', 'W', 'D', 'Q', 'H', 'h':
			dtype = param[j]
		}
	}

	// print header - 0-terminated string
	fmt.Printf("\n")
	for loop := true; loop; header++ {
		c, _ := stack.toByte(&header)
		if c == 0 {
			loop = false
			continue
		}
		fmt.Printf("%c", c)
	}

	// print data
	for i := int64(0); i < num; i++ {
		switch dtype {
		case 'C':
			c, _ := stack.toByte(&src)
			fmt.Printf("%c", c)
			src++

		case 'B':
			c, _ := stack.toByte(&src)
			fmt.Printf("%d ", c)
			src++

		case 'W':
			c, _ := stack.toInt16(&src)
			fmt.Printf("%d ", c)
			src += 2

		case 'D':
			c, _ := stack.toInt32(&src)
			fmt.Printf("%d ", c)
			src += 4

		case 'Q':
			c, _ := stack.toInt64(&src)
			fmt.Printf("%d (0x%x) ", c, c)
			src += 8

		case 'h':
			c, _ := stack.toHash(&src)
			fmt.Printf("%s ", c.String())
			src += 32

		case 'H':
			c, _ := stack.toHash(&src)
			i := 31
			for ; i >= 0 && c[i] == 0; i-- {
			}
			n := i + 1
			for i = 0; i < n/2; i++ {
				s, t := c[i], c[n-1-i]
				c[i], c[n-1-i] = t, s
			}
			b := big.Int{}
			b.SetBytes(c[:n])

			fmt.Printf("%s ", b.String())
			src += 32
		}
	}
	fmt.Printf("\n\n")

	return nil
}

/*
func opSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var dest pointer
	var tl int
	var err error
	var hash []byte
	dataType := []byte{0xFF, 'B', 'L'}
	var wbuf bytes.Buffer

parser:
	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)
				top++

			case 1:
				it := num
				t := ovm.GetTx()

				switch it { // text encoding
				case 1, 2: // transaction (BaseEncoding), all outputs
					if err := encodeText(byte(it), &wbuf, t.MsgTx(), nil, 0); err != nil {
						return err
					}

				case 3: // specific matching outputs
					if num, tl, err = stack.getNum(param[j:], 'D'); err != nil {
						return err
					}
					j += tl

					if hash, tl, err = stack.getBytesLen(param[j:], uint32(num)); err != nil {
						return err
					}
					j += tl

					if err := encodeText(byte(it), &wbuf, t.MsgTx(), hash, 0); err != nil {
						return err
					}

					break parser

				default:
					return omega.ScriptError(omega.ErrInternal,"Unknown text coding")
				}
			}
		}
	}

	f := wbuf.Bytes()

	// ensure enough space
	if (dest >> 32) == 0 {
		stack.malloc(len(f) + 4)
	} else {
		stack.alloc(len(f) + 4)
	}
	p := dest + 4

	if err := stack.saveInt32(&dest, int32(len(f))); err != nil {
		return err
	}
	if err := stack.saveBytes(&p, f); err != nil {
		return err
	}

	return nil
}
*/

// Below are signature VM engine insts. They are in binary formats.
func opPush(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.Code[0].param

	var sz int
	offset := 1
	if param[0] == 0 {
		sz = int(param[1]) + ((int(param[2])) << 8)
		offset = 3
	} else {
		sz = int(param[0])
	}

	dest, unused := stack.malloc(sz)

	if err := stack.saveBytes(&dest, param[offset:offset+sz]); err != nil {
		return err
	}
	unused -= sz
	if unused > 0 {
		stack.shrink(unused)
	}

	u := sz + offset

	m := binary.LittleEndian.Uint32(stack.data[0].space)
	m += uint32(sz)
	binary.LittleEndian.PutUint32(stack.data[0].space, m)

	nextop(contract, u)
	*pc--

	return nil
}

func nextop(contract *Contract, u int) {
	if len(contract.Code[0].param) <= u {
		contract.Code[0] = inst{'z', nil}
	} else {
		contract.Code[0] = inst{OpCode(contract.Code[0].param[u]), contract.Code[0].param[u+1:]}
	}
}

func opAddSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) omega.Err {
	param := contract.Code[0].param

	it := param[0]
	tx := ovm.GetTx()

	if tx == nil {
		return omega.ScriptError(omega.ErrInternal, "Missing tx")
	}

	t := tx.MsgTx().Stripped() // deep copy w/o contract added items

	// no definition. all definition would be ultimately
	// referenced by an output. if the output is in, definition
	// can not be changed w/o affecting signature. if we don't
	// care about an output, why do we care about definition it
	// references? Thus no definition is required for sig.
	t.TxDef = []token.Definition{}
	u := 1

	inidx := binary.LittleEndian.Uint32(contract.Args)
	start := inidx

	switch SigHashType(it) & SigHashMask {
	case 0: // no text generated. used where there is no sig and SIGNTEXT only servers as a marker
		nextop(contract, u)
		*pc--
		return nil

	case SigMultiSigMark:
		nextop(contract, u)
		*pc--
		return nil

	case SigHashNone:
		t.TxOut = t.TxOut[0:0]
		for i := range t.TxIn {
			if uint32(i) != inidx {
				t.TxIn[i].Sequence = 0
			}
		}

	case SigHashSingle, SigHashDouble, SigHashTriple, SigHashQuardruple:
		if inidx < uint32(SigHashType(it)&SigHashMask)-uint32(SigHashSingle) ||
			int(inidx) >= len(t.TxOut) || int(inidx) >= len(t.TxIn) {
			return omega.ScriptError(omega.ErrInternal, "Insufficient data for line signature")
		}

		start = inidx + uint32(SigHashSingle) - uint32(SigHashType(it)&SigHashMask)
		t.TxOut = t.TxOut[start : inidx+1]
		t.TxIn = t.TxIn[start : inidx+1]

		if ovm.Context.BlockVersion() >= wire.Version3 {
			for i := 0; i < len(t.TxIn); i++ {
				t.TxIn[i].SignatureIndex = 0
			}
		}

		it = it &^ byte(SigHashAnyOneCanPay) // to skip SigHashAnyOneCanPay check below

	default:
		// Consensus treats undefined hashtypes like normal SigHashAll
		// for purposes of hash generation.
		fallthrough
	case SigHashAll:
		// Nothing special here.
	}

	if SigHashType(it)&SigHashAnyOneCanPay != 0 {
		t.TxIn = t.TxIn[start : inidx+1]
	}

	wbuf := bytes.NewBuffer(make([]byte, 0, t.SerializeSizeStripped()+4))
	t.SerializeNoSignature(wbuf)

	f := wbuf.Bytes()

	dest, unused := stack.malloc(len(f) + 4)
	p := dest + 4

	if err := stack.saveInt32(&dest, int32(len(f))); err != nil {
		return err
	}
	if err := stack.saveBytes(&p, f); err != nil {
		return err
	}
	unused -= len(f) + 4

	m := binary.LittleEndian.Uint32(stack.data[0].space)
	m += uint32(len(f)) + 4
	binary.LittleEndian.PutUint32(stack.data[0].space, m)

	stack.shrink(unused)
	nextop(contract, u)

	*pc--

	return nil
}
