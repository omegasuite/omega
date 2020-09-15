// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"errors"
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/viewpoint"
	"math"
	"math/big"

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

var checkTop = map[uint8]int{'+':1, '-':1, '*':1, '/':1, '%':1, '#':1,
	'[':1, ']':1, '|':1, '^':1, '>':1, '<':1, '=':1, ')':1, '(':1, '!':1, '?':2}
var sizeOfType = map[byte]uint32 {'R':21, 'r':20,
	'B':1, 'W':2, 'D':4, 'Q':8, 'H':32, 'h': 32,
	'k': 33, 'K': 65}

func (stack * Stack) getNum(param []byte, dataType byte) (int64, int, error) {
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

		case 'n':	// n
			sign = -1

		case 'i':	// i
			indirect++
			if indirect > 6 {
				return 0, ln, fmt.Errorf("Malformed operand")
			}

		case 'g':	// g
			global = 1

		case 'l':	// l
			global = 2

		case '\'':	// " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0

		case '"':	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0

		case ',':	// ,
			t := int64(0)
			num := int64(0)
			if global == 0 {
				t = int64(len(stack.data) - 1)
			} else if global == 2 {
				nums[0] += int64(stack.data[len(stack.data) - 1].gbase)
			}

			if indirect > 0 {	// || dataType == 0xFF {
				p := pointer((t << 32) | nums[0])
				if indirect > 0 {
					var err error
					p, err = stack.addressing(indirect, global, hasoffset, nums[:], dataType != 0xFF)
					if err != nil {
						return 0, 0, err
					}
				}

				switch dataType {
				case 'B':	// byte
					b, err := stack.toByte(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b) * sign)
				case 'W':	// word
					b, err := stack.toInt16(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b)* sign)
				case 'D':	// dword
					b, err := stack.toInt32(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b)* sign)
				case 'Q':	// qword
					b, err := stack.toInt64(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(b* int64(sign))
				case 0xFF:	// pointer
					num = int64(p)
				}
				indirect = 0
			} else {
				num = nums[0]
				num *= int64(sign)
			}
			return num, j, nil

		default:
			return 0, j - 1, fmt.Errorf("Malformed operand")
		}
	}
	return 0, ln, fmt.Errorf("Malformed operand")
}

func opEval8(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
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
	var err error

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return fmt.Errorf("Malformed expression. Evaluation stack underflow.")
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

		case 'u':	// u
			unsigned = true

		case '+':	// +
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) + uint8(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-':	// -
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) - uint8(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*':	// *
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) * uint8(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/':	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) / uint8(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%':	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) % uint8(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#':	// # - exp
			if unsigned {
				scratch[top-1] = int8(math.Pow(float64(uint8(scratch[top-1])), float64(uint8(scratch[top]))))
			} else {
				scratch[top-1] = int8(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[':	// <<
			scratch[top-1] <<= scratch[top]

		case ']':	// >>
			scratch[top-1] >>= scratch[top]

		case '|':	// |
			scratch[top-1] |= scratch[top]

		case '&':	// &
			scratch[top-1] &= scratch[top]

		case '^':	// &^
			scratch[top-1] ^= scratch[top]

		case '~':	// ~
			scratch[top-1] = ^scratch[top-1]

		case '>':	// >
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

		case '<':	// <
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

		case '=':	// =
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

		case ')':	// >=
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

		case '(':	// <=
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

		case '!':	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?':	// ?
			if scratch[top + 1] == 0 {
				scratch[top-1] = scratch[top]
			}
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveByte(&store, byte(scratch[0]))
}

func opEval16(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
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
	var err error

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return fmt.Errorf("Malformed expression. Evaluation stack underflow.")
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

		case 'u':	// u
			unsigned = true

		case '+':	// +
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) + uint16(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-':	// -
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) - uint16(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*':	// *
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) * uint16(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/':	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) / uint16(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%':	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) % uint16(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#':	// # - exp
			if unsigned {
				scratch[top-1] = int16(math.Pow(float64(uint16(scratch[top-1])), float64(uint16(scratch[top]))))
			} else {
				scratch[top-1] = int16(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[':	// <<
			scratch[top-1] <<= scratch[top]

		case ']':	// >>
			scratch[top-1] >>= scratch[top]

		case '|':	// |
			scratch[top-1] |= scratch[top]

		case '&':	// &
			scratch[top-1] &= scratch[top]

		case '^':	// &^
			scratch[top-1] ^= scratch[top]

		case '~':	// ~
			scratch[top-1] = ^ scratch[top-1]

		case '>':	// >
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

		case '<':	// <
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

		case '=':	// =
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

		case ')':	// >=
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

		case '(':	// <=
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

		case '!':	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?':	// ?
			if scratch[top + 1] == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return fmt.Errorf("Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveInt16(&store, scratch[0])
}

func opEval32(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int32, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var store pointer
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return fmt.Errorf("Malformed expression. Evaluation stack underflow.")
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

		case 'u':	// u
			unsigned = true

		case '+':	// +
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) + uint32(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-':	// -
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) - uint32(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*':	// *
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) * uint32(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/':	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) / uint32(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%':	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) % uint32(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#':	// # - exp
			if unsigned {
				scratch[top-1] = int32(math.Pow(float64(uint32(scratch[top-1])), float64(uint32(scratch[top]))))
			} else {
				scratch[top-1] = int32(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[':	// <<
			scratch[top-1] <<= scratch[top]

		case ']':	// >>
			scratch[top-1] >>= scratch[top]

		case '|':	// |
			scratch[top-1] |= scratch[top]

		case '&':	// &
			scratch[top-1] &= scratch[top]

		case '^':	// &^
			scratch[top-1] ^= scratch[top]

		case '~':	// ~
			scratch[top-1] = ^ scratch[top-1]

		case '>':	// >
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

		case '<':	// <
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

		case '=':	// =
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

		case ')':	// >=
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

		case '(':	// <=
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

		case '!':	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?':	// ?
			if scratch[top + 1] == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return fmt.Errorf("Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	return stack.saveInt32(&store, scratch[0])
}

func opEval64(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int64, lim)

	top := 0
	dataType := byte(0xFF)
	unsigned := false
	num := int64(0)
	var r bool
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return fmt.Errorf("Malformed expression. Evaluation stack underflow.")
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

		case '@':	// @
			dataType = 0xFF

		case 'u':	// u
			unsigned = true

		case '+':	// +
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) + uint64(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case '-':	// -
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) - uint64(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case '*':	// *
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) * uint64(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case '/':	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) / uint64(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case '%':	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) % uint64(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case '#':	// # - exp
			if unsigned {
				scratch[top-1] = int64(math.Pow(float64(uint64(scratch[top-1])), float64(uint64(scratch[top]))))
			} else {
				scratch[top-1] = int64(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case '[':	// <<
			scratch[top-1] <<= scratch[top]

		case ']':	// >>
			scratch[top-1] >>= scratch[top]

		case '|':	// |
			scratch[top-1] |= scratch[top]

		case '&':	// &
			scratch[top-1] &= scratch[top]

		case '^':	// &^
			scratch[top-1] ^= scratch[top]

		case '~':	// ~
			scratch[top-1] = ^ scratch[top-1]

		case '>':	// >
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

		case '<':	// <
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

		case '=':	// =
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

		case ')':	// >=
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

		case '(':	// <=
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

		case '!':	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case '?':	// ?
			if scratch[top + 1] == 0 {
				scratch[top - 1] = scratch[top]
			}

		default:
			return fmt.Errorf("Malformed expression")
		}
		if param[j] != 0x75 {
			unsigned = false
		}
	}

	store := pointer(scratch[0])

	return stack.saveInt64(&store, scratch[1])
}

var (
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
	bigNegOne = big.NewInt(-1)
)

func (stack * Stack) addressing(indirect int, global byte, hasoffset int, offsets []int64, notaddr bool) (pointer, error) {
	if indirect <= 0 {
		return 0, nil
	}

	t := int64(0)

	if global == 0 {
		t = int64(len(stack.data) - 1)
	} else if global == 2 {
		offsets[0] += int64(stack.data[len(stack.data) - 1].gbase)
	}

	p := pointer((t << 32) | offsets[0])
	var err error

	for ; indirect > 1; indirect-- {
		if p,err = stack.toPointer(&p); err != nil {
			return 0, err
		}
		p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(offsets[1])) & 0xFFFFFFFF))	// head offset is added to the first indirection
		offsets[1] = 0
	}
	if (hasoffset & 2) != 0 {
		p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(offsets[2])) & 0xFFFFFFFF))
	}

	if notaddr && int(p & 0xFFFFFFFF) >= len(stack.data[(p &^ 0xFFFFFFFF) >> 32].space) {
		return 0, fmt.Errorf("Memory address fault")
	}

	return p, nil
}

func (stack * Stack) getBig(param []byte) (*big.Int, int, error) {
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
			num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j] - 0x30)))
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp

		case 'x': // x
			hex = true

		case 'n':	// n
			sign = *bigNegOne

		case 'i':	// i
			indirect++
			if indirect > 6 {
				return bigZero, ln, fmt.Errorf("Malformed operand")
			}

		case 'g':	// g
			global = 1

		case 'l':	// l
			global = 2

		case '\'':	// ' - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case '"':	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case ',':	// ,
			if indirect > 0 {
				p, err := stack.addressing(indirect, global, hasoffset, nums[:], true)
				if err != nil {
					return nil, 0, err
				}
				if h, err := stack.toHash(&p); err != nil {
						return nil, 0, err
					} else {
					num.SetBytes(h[:])
					num = *num.Mul(&num, &sign)
				}
				indirect = 0
			} else {
				num = *num.Mul(&num, &sign)
			}
			return &num, j, nil

		default:
			return nil, j - 1, fmt.Errorf("Malformed operand")
		}
	}
	return nil, ln, fmt.Errorf("Malformed operand")
}

func (stack * Stack) getHash(param []byte) (chainhash.Hash, int, error) {
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

		case 'i':	// i
			indirect++
			if indirect > 6 {
				return chainhash.Hash{}, ln, fmt.Errorf("Malformed operand")
			}

		case 'g':	// g
			global = 1

		case 'l':	// l
			global = 2

		case '\'':	// " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case '"':	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case ',':	// ,
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
					if i & 1 == 0 {
						h[i / 2] = num[d - i - 1]
					} else {
						h[i / 2] |= num[d - i - 1] << 4
					}
				}
				return h, j, nil
			}

		default:
			return chainhash.Hash{}, j - 1, fmt.Errorf("Malformed hash operand")
		}
	}
	return chainhash.Hash{}, ln, fmt.Errorf("Malformed hash operand")
}

func (stack * Stack) getBytesLen(param []byte, dlen uint32) ([]byte, int, error) {
	ln := len(param)
	tmp := make([]byte, 0, 66)		// byte buffer
	t := byte(0)					// current byte
	even := false
	hex := false
	indirect := 0
	global := byte(0)
	offset := 0
	hasoffset := 0
	tnum := int64(0)				// current number
	nums := [3]int64{0, 0, 0}		// offsets

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

		case 'i':	// i
			indirect++
			if indirect > 6 {
				return nil, ln, fmt.Errorf("Malformed operand")
			}

		case 'g':	// g
			global = 1

		case 'l':	// l
			global = 2

		case '\'':	// " - head offset
			hasoffset |= 1
			offset = 1
			tnum = 0
			hex = false

		case '"':	// " - tail offset
			hasoffset |= 2
			offset = 2
			tnum = 0
			hex = false

		case ',':	// ,
			if indirect > 0 {
				p, err := stack.addressing(indirect, global, hasoffset, nums[:], true)
				if err != nil {
					return nil, 0, err
				}
				s := uint32(p & 0xFFFFFFFF)
				tmp = stack.data[p >> 32].space[s : s + dlen]
			}
			return tmp, j, nil

		default:
			return nil, j - 1, fmt.Errorf("Malformed operand")
		}
	}
	return nil, ln, fmt.Errorf("Malformed operand")
}

func (stack * Stack) getBytes(param []byte, dataType byte, dln uint32) ([]byte, int, error) {
	return stack.getBytesLen(param, sizeOfType[dataType] + dln)
}

func opEval256(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]*big.Int, lim)

	top := 0
	var num * big.Int
	var store pointer
	var err error
	var tl int
	dataType := byte(0xFF)

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d {
				return fmt.Errorf("Malformed expression. Evaluation stack underflow.")
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
					store = pointer(p)
					j += tl
				}
			} else {
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
			}
			dataType = 0x48

		case '+':	// +
			scratch[top-1] = scratch[top-1].Add(scratch[top-1], scratch[top])

		case '-':	// -
			scratch[top-1] = scratch[top-1].Sub(scratch[top-1], scratch[top])

		case '*':	// *
			scratch[top-1] = scratch[top-1].Mul(scratch[top-1], scratch[top])

		case '/':	// /
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Div(scratch[top-1], scratch[top])

		case '%':	// %
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Mod(scratch[top-1], scratch[top])

		case '#':	// # - exp
			scratch[top-1] = Exp(scratch[top-1], scratch[top])

		case '|':	// logical |
			if scratch[top-1].Cmp(bigZero) == 0 || scratch[top].Cmp(bigZero) == 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case '&':	// logical &
			if scratch[top-1].Cmp(bigZero) != 0 && scratch[top].Cmp(bigZero) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '^':	// logical &^
			b1 := scratch[top-1].Cmp(bigZero) != 0
			b2 := scratch[top].Cmp(bigZero) != 0
			if b1 != b2 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '~':	// logical ~
			if scratch[top-1].Cmp(bigZero) != 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case '>':	// >
			if scratch[top-1].Cmp(scratch[top]) > 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '<':	// <
			if scratch[top-1].Cmp(scratch[top]) < 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '=':	// =
			if scratch[top-1].Cmp(scratch[top]) == 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case ')':	// >=
			if scratch[top-1].Cmp(scratch[top]) >= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '(':	// <=
			if scratch[top-1].Cmp(scratch[top]) <= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '!':	// !=
			if scratch[top-1].Cmp(scratch[top]) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case '?':	// ?
			if scratch[top + 1].Cmp(bigZero) == 0 {
				scratch[top-1] = scratch[top]
			}

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	var h chainhash.Hash
	copy(h[:], scratch[0].Bytes())
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
	p pointer
}

func opConv(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	var scratch [2]convOperand

	ln := len(param)

	top := 0
	dtype := byte(0)
	num := int64(0)
	unsigned := false
	var err error
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
			scratch[top] = convOperand{dtype, pointer(num) }
			dtype = 0
			top++

		case 'B', 'W', 'D', 'Q', 'H':	// b
			// BWDQH - byte, word, dword, qword, big int
			dtype = param[j]

		case 'u':	// u
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
	if srcType == destType {
		n := sizeOfType[destType]
		copy(stack.data[scratch[1].p >> 32].space[uint32(scratch[1].p):],
			stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p):uint32(scratch[0].p) + n])
	} else if m > n {
		copy(stack.data[scratch[1].p >> 32].space[uint32(scratch[1].p):],
			stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p):uint32(scratch[0].p) + n])
		if unsigned || stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p) + n - 1] & 0x80 == 0 {
			copy(stack.data[scratch[1].p >> 32].space[uint32(scratch[1].p) + n:],
				make([]byte, m-n))
		} else {
			for ; n < m; n++ {
				stack.data[scratch[1].p >> 32].space[uint32(scratch[1].p) + n] = 0xFF
			}
		}
	} else {
		if unsigned || stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p) + m - 1] & 0x80 == 0 {
			for i := m; i < n; i++ {
				if stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p) + i] != 0 {
					return fmt.Errorf("Numeric overflow in conversion.")
				}
			}
		} else {
			for i := m; i < n; i++ {
				if stack.data[scratch[0].p>>32].space[uint32(scratch[0].p)+i] != 0xFF {
					return fmt.Errorf("Numeric overflow in conversion.")
				}
			}
		}
		copy(stack.data[scratch[1].p >> 32].space[uint32(scratch[1].p):],
			stack.data[scratch[0].p >> 32].space[uint32(scratch[0].p):uint32(scratch[0].p) + m])
	}

	return nil
}

func opHash(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	// dest, src, len

	var scratch [3]pointer
	ln := len(param)

	top := 0
	num := int64(0)
	var err error
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

	hash := chainhash.HashB(stack.data[t >> 32].space[a:b])

	return stack.saveBytes(&scratch[0], hash)
}

func opHash160(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	// dest, src, len

	var scratch [3]pointer
	ln := len(param)

	top := 0
	num := int64(0)
	var err error
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

	hash := hash160(stack.data[t >> 32].space[a:b])

	return stack.saveBytes(&scratch[0], hash)
}

func opSigCheck(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
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
	var err error
	var tl int

	ln := len(param)

	top := 0
	num := int64(0)

	paramTypes := []byte{0xFF, 'h', 'K', 0xFF }

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
				if format != btcec.PubKeyBytesLenCompressed  && format != btcec.PubKeyBytesLenHybrid {
					return fmt.Errorf("invalid magic in pubkey str: %d", format)
				}
				pubKey = pubKey[1:format + 1]

			case 3:
				tp = pointer(num)
				tp2 := tp + 1
				sl2,err := stack.toByte(&tp2)
				if err != nil {
					return err
				}
				sig,err = stack.toBytesLen(&tp, int(sl2 + 2))
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

func opIf(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var scratch [2]int32

	top := 0
	num := int64(0)
	var err error
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

	inlib := stack.data[len(stack.data) - 1].inlib
	if target < int(contract.libs[inlib].address) || target >= int(contract.libs[inlib].end) {
		return fmt.Errorf("Out of range jump")
	}
	*pc = target
	log.Debugf("If %d, pc=", scratch[0], *pc)

	return nil
}

func opCall(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	// base, entry, params
	// if address == 0, entry is relative to pc, target must be in current code seg
	// if address != 0, lib address, entry is func abi, target is lib entry (0)

	ln := len(param)

	top := 0
	num := int64(0)
	var bnum []byte
	var libAddr Address
	var err error
	var tl int

	offset := 0

	f := newFrame()
	f.space = append(f.space, []byte{0,0,0,0,0,0,0,0}...)
	binary.LittleEndian.PutUint32(f.space[4:], uint32(len(stack.data)))
	inlen := 0

	paramTypes := []byte{'L', 'D', 'Q', 0xFF }

	isself := true
	sign := 1

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 'n':
			sign = -1

		case '@':
			top++

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

			switch top {
			case 0:
				copy(libAddr[:], bnum)
				if _, ok := contract.libs[libAddr]; !ok {
					return fmt.Errorf("Lib not loaded")
				}
				isself = allZero(libAddr[:])
				top++

			case 1:
				offset = int(num) * sign			// entry point
				sign = 1
				if !isself {
					var bn [4]byte
					binary.LittleEndian.PutUint32(bn[:], uint32(offset))
					f.space = append(f.space, bn[:]...)
					inlen += 4
				}
				top++

			case 3:
				top--
				fallthrough

			case 2:
				var bn [8]byte
				for i := 0; i < 8; i++ {
					bn[i] = byte((num >> (i * 8)) & 0xFF)
				}
				f.space = append(f.space, bn[:]...)
				inlen += 8
			}
		}
	}
	binary.LittleEndian.PutUint32(f.space[:], uint32(inlen))

	if top >= 2 {
		f.pc = *pc
		f.pure = contract.pure
		if isself {
			libAddr = stack.data[len(stack.data)-1].inlib
		}
		f.inlib = libAddr
		f.gbase = contract.libs[libAddr].base
		contract.pure = contract.libs[libAddr].pure

		var target int32
		if isself {
			target = int32(*pc + offset)
			if target < contract.libs[libAddr].address || target >= contract.libs[libAddr].end {
				return fmt.Errorf("Out of range func call")
			}
		} else {
			target = contract.libs[libAddr].address
		}
		*pc = int(target)
		stack.data = append(stack.data, f)
		return nil
	}

	return fmt.Errorf("Malformed function call")
}

func opLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	if stack.data[len(stack.data) - 1].pure & 0x8 != 0 {
		return fmt.Errorf("Load forbidden in lib %x", stack.data[len(stack.data) - 1].inlib)
	}

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	dataType := []byte{0xFF, 'Q'}
	var err error
	var tl int
	var h []byte
	var store pointer
	top := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			if dataType[top] == 'Q' {
				if num >= 0 && num < (1 << 32) {
					h = make([]byte, 4)
					binary.LittleEndian.PutUint32(h, uint32(num))
				} else {
					h = make([]byte, 8)
					binary.LittleEndian.PutUint64(h, uint64(num))
				}
			} else {
				store = pointer(num)
			}
			top++
			j += tl
		}
	}

	d := evm.GetState(contract.self.Address(), string(h))

	var n uint32
	n = uint32(len(d))

	stack.saveInt32(&store, int32(n))
	store += 4
	for i := uint32(0); i < n; i++ {
		if err := stack.saveByte(&store, d[i]); err != nil {
			return err
		}
		store++
	}

	log.Debugf("loading %x = %x (%d)", h, d, n)

	return nil
}

func opStore(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
//	{patOperand, 0}, - key
//	{dataType, 0}, - data type/length
//	{patOperand, 0}, - data
	if stack.data[len(stack.data) - 1].pure & 0x1 != 0 {
		return fmt.Errorf("Store forbidden in lib %x", stack.data[len(stack.data) - 1].inlib)
	}

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := chainhash.Hash{}
	var tl int
	var err error
	var scratch [2][]byte
	top := 0
	idx := 0

	dataType := []byte{'Q', 'L', 'B'}
	dt := byte('Q')
	var dlen uint32
	dlen = sizeOfType[dt]
	fdlen := dlen

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			switch dt {
			case 'k', 'K', 'r', 'R':
				var num []byte
				if num, tl, err = stack.getBytes(param[j:], dt, 0); err != nil {
						return err
					}
				scratch[top] = num
			case 'H', 'h':
				if num, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
				scratch[top] = num[:]
			case 'L':
				var num []byte
				if num, tl, err = stack.getBytesLen(param[j:], dlen); err != nil {
					return err
				}
				scratch[top] = num
			default:
				num := int64(0)
				if num, tl, err = stack.getNum(param[j:], dt); err != nil {
					return err
				}
				var d [8]byte
				binary.LittleEndian.PutUint64(d[:], uint64(num))
				if top == 0 && num >= 0 && num < (1 << 32) {
					scratch[top] = d[:4]
				} else {
					scratch[top] = d[:sizeOfType[dt]]
				}
			}
			fdlen = dlen
			top++
			dt = dataType[top]
			dlen = sizeOfType[dt]
			idx++
			j += tl

		case 'R', 'r', 'B', 'W', 'D', 'Q', 'H', 'h', 'k', 'K':	// b
			// BWDQHA - byte, word, dword, qword, big int, hash, address
			dt = param[j]
			dlen = sizeOfType[dt]

		case 'L':	// long data
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

	log.Debugf("storing %x = %x (%d)", scratch[0], scratch[1][:fdlen], fdlen)

	return nil
}

func opDel(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var tl int

	var err error
	var d [8]byte
	var k []byte

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num := int64(0)
			if num, tl, err = stack.getNum(param[j:], 'D'); err != nil {
				return err
			}
			binary.LittleEndian.PutUint64(d[:], uint64(num))
			if num >= 0 && num < (1 << 32) {
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

func opReceived(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	outpoint := ovm.GetCurrentOutput()

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	var tl int
	var err error

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

func opExec(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	var bnum *big.Int
	top := 0

	var toAddr Address
	var value * token.Token
	var retspace pointer
	var data pointer
	var datalen int32
	var tl int
	var err error

	paramTypes := []byte{0xFF, 0x48, 0xFF, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 0x48 {
				bnum, tl, err = stack.getBig(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil { return err }
			j += tl

			switch top {
			case 0:
				retspace = pointer(num)

			case 1:	// address
				toAddr = BigToAddress(bnum)

			case 2:
				if num != 0 {
					value = &token.Token{}
					var r bytes.Reader
					r.Reset(stack.data[num>>32].space[num&0xFFFFFFFF:])
					value.Read(&r, 0, 0)

					if value.TokenType & 1 == 0 && value.Value.(*token.NumToken).Val == 0 {
						value = nil
					}
				}

			case 3:
				data = pointer(num)

			case 4:
				datalen = int32(num)

				args := stack.data[data >> 32].space[data & 0xFFFFFFFF:int32(int64(data) & 0xFFFFFFFF) + datalen]

				pks := make([]byte, 25 + len(args))
				pks[0] = 1
				copy(pks[1:], toAddr[:])
				copy(pks[21:], args)

				tx := evm.GetTx()
				msg := tx.MsgTx()
				if !tx.HasOuts {
					// this servers as a separater. only TokenType is serialized
					to := wire.TxOut{}
					to.Token = token.Token{TokenType:token.DefTypeSeparator}
					msg.AddTxOut(&to)
					tx.HasOuts = true
				}
				msg.AddTxOut(&wire.TxOut{PkScript:pks, Token:*value})

				for _,d := range evm.contractStack {
					if d == toAddr {
						return fmt.Errorf("Circular contract calls.")
					}
				}
				evm.contractStack = append(evm.contractStack, toAddr)

				ret, err := evm.Call(toAddr, args[:4], value, args)		// nil=>value

				evm.contractStack = evm.contractStack[:len(evm.contractStack) - 1]

				if err != nil {
					return err
				}

				m := len(ret)
				if retspace != 0 && m > 0 {
					var p pointer
					if int64(retspace) >> 32 == int64(len(stack.data)) - 1 {
						p,_ = stack.alloc(m)
					} else {
						p,_ = stack.malloc(m)
					}
					copy(stack.data[p >> 32].space[p & 0xFFFFFFFF:], ret)
					if err := stack.saveInt64(&retspace, int64(p)); err != nil {
						return err
					}
					retspace += 8
					if err := stack.saveInt32(&retspace, int32(m)); err != nil {
						return err
					}
				}

//				if err == nil && value != nil {
//					outp,_ := evm.GetCurrentOutput()
//					evm.StateDB[toAddr].credit(outp, *value)
//				}

				return err
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}

func opLibLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var bnum []byte
	top := 0

	pure := byte(0)
	var tl int
	var err error

	paramTypes := []byte{'B', 'L', 'Q'}
	f := newFrame()

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType == 'L' {
				bnum, tl, err = stack.getBytes(param[j:], 'r', 0)
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil { return err }
			j += tl

			switch top {
			case 0:
				pure = byte(num) | stack.data[len(stack.data)-1].pure
				top++

			case 1:
				var d [20]byte

				copy(d[:], bnum[:20])
				if _, ok := contract.libs[d]; ok {
					*pc++
					return nil
				}

				sd := NewStateDB(evm.views.Db, d)

				existence := sd.Exists(true)
				if !existence {
					return fmt.Errorf("The library does not exist")
				}

				evm.StateDB[d] = sd

				ccode := ByteCodeParser(evm.GetCode(d))
				contract.libs[d] = lib{
					address: int32(len(contract.Code)),
					end: int32(len(contract.Code) + len(ccode)),
					base: int32(len(stack.data[0].space)),
					pure: pure,
				}
				contract.Code = append(contract.Code, ccode...)

				// execute init call
				f.space = append(f.space, []byte{4,0,0,0,0,0,0,0}...)
				binary.LittleEndian.PutUint32(f.space[4:], uint32(len(stack.data)))

				var bn [4]byte
				binary.LittleEndian.PutUint32(bn[:], uint32(1))	// entry point for init()
				f.space = append(f.space, bn[:]...)
				f.pc = *pc
				f.pure = pure
				f.inlib = d
				f.gbase = contract.libs[d].base
				contract.pure = pure

				*pc = int(contract.libs[d].address)
				stack.data = append(stack.data, f)
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
	return fmt.Errorf("Malformed parameters")
}

func opMalloc(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opMAalloc(pc, evm, contract, stack, true)
}

func opMAalloc(pc *int, evm *OVM, contract *Contract, stack *Stack, glob bool) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	top := 0
	var tl int
	var err error

	var retspace pointer
	paramType := []byte{0xFF, 'D'}

	for j := 0; j < ln; j++ {
		switch param[j] {
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
				p,_ := stack.alloc(int(num))

				if retspace != 0 {
					return stack.saveInt64(&retspace, int64(p))
				}

				return nil
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}

func opAlloc(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opMAalloc(pc, evm, contract, stack, false)
}

func opCopy(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var src pointer
	var dest pointer
	var tl int
	var err error

	var dtype = []byte{0xFF, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
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
//				copy(stack.data[dest >> 32].space[dest & 0xFFFFFFFF:], stack.data[src >> 32].space[src & 0xFFFFFFFF:num])
				return nil
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}

func opCopyImm(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)

	var dest pointer
	var tl int
	var err error
	var h []byte
	var hash chainhash.Hash

	dataType := byte(0xFF)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 'R', 'r', 'B', 'W', 'D', 'Q', 'H', 'h', 'k', 'K':	// b
			dataType = param[j]

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
			}
		}
	}

	return nil
}

func opTxFee(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var dest pointer
	var tl int
	var err error
	dataType := []byte{0xFF, 'B'}

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
				tx := evm.GetTx();
				msgTx := tx.MsgTx()
				serializedSize := int64(msgTx.SerializeSize())

				if num & 1 != 0 {
					serializedSize += 44	// add an input
				}
				if num & 2 != 0 {
					serializedSize += 35	// add an output
				}

				minFee := (serializedSize * int64(evm.chainConfig.MinRelayTxFee)) / 1000

				if minFee == 0 && evm.chainConfig.MinRelayTxFee > 0 {
					minFee = int64(evm.chainConfig.MinRelayTxFee)
				}

				if minFee < 0 || minFee > btcutil.MaxSatoshi {
					minFee = btcutil.MaxSatoshi
				}

				if err := stack.saveInt64(&dest, minFee); err != nil {
					return err
				}

				return nil
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}

/*
func opCodeCopy(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
//	{patOperand, 0xFFFFFFFF},
//	{addrOperand, 0xFFFFFFFF},
//	{patOperand, 0xFFFFFFFF},
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var dest pointer
	var offset int32
	var tl int
	var err error
	dataType := []byte{0xFF, 0x44, 0x44}

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
				offset = int32(num) + int32(*pc)

			case 2:
				d0 := (dest & 0xFFFFFFFF)
				d := d0 + 4
				s := dest >> 32
				ln := uint32(0)
				for ; num > 0; num-- {
					stack.data[s].space[d] = byte(contract.Code[offset].op)
					d++
					copy(stack.data[s].space[d:], contract.Code[offset].param)
					d += pointer(int32(len(contract.Code[offset].param)))
					stack.data[s].space[d] = 10
					d++
					ln += 2 + uint32(len(contract.Code[offset].param))
					offset++
				}
				binary.LittleEndian.PutUint32(stack.data[s].space[d0:], ln)
				return nil
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}
 */

func opSuicide(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	evm.StateDB[contract.Address()].Suicide()
	return nil
}

func opRevert(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return nil
}

func opStop(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return nil
}

func opReturn(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	n := len(stack.data) - 1
	if n <= 0 {
		return fmt.Errorf("Return not from a Call.")
	}
	*pc = stack.data[n].pc
	contract.pure = stack.data[n].pure
	stack.data = stack.data[:n]
	return nil
}

/*
func opTxIOCount(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	var scratch [3]pointer

	ln := len(param)

	top := 0
	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			scratch[top] = pointer(num)
			num = 0
			top++

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	tx := evm.GetTx()
	if err := stack.saveInt32(&scratch[0], int32(len(tx.MsgTx().TxIn))); err != nil {
		return err
	}
	if err := stack.saveInt32(&scratch[1], int32(len(tx.MsgTx().TxOut))); err != nil {
		return err
	}
	return stack.saveInt32(&scratch[2], int32(len(tx.MsgTx().TxDef)))
}

func opGetTxIn(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opGetTxIO(pc, evm, contract, stack, true)
}

func opGetTxIO(pc *int, evm *OVM, contract *Contract, stack *Stack, in bool) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	num := int64(0)
	inid := int32(0)
	var dest pointer
	var tl int
	var err error
	dataType := byte(0xFF)

	var op wire.OutPoint

	tx := evm.GetTx()

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			dataType = 0x44
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				inid = int32(num)
			}
			top++

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	var tue * wire.TxOut

	if in {
		op = tx.MsgTx().TxIn[inid].PreviousOutPoint
		evm.views.Utxo.FetchUtxosMain(evm.views.Db, map[wire.OutPoint]struct{}{op: {}})
		ue := evm.views.Utxo.LookupEntry(op)
		tue = ue.ToTxOut()
	} else {
		tue = tx.MsgTx().TxOut[inid]
	}

	var w bytes.Buffer
	tue.Write(&w, 0, 0, wire.SignatureEncoding)
	return stack.saveBytes(&dest, w.Bytes())
}

func opGetTxOut(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opGetTxIO(pc, evm, contract, stack, false)
}
 */

var negHash = chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }

func opSpend(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var dtype = []byte{0x68, 0x44}
	top := 0
	p := wire.OutPoint{}

	for j := 0; j < ln; j++ {
		switch param[j] {
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
			} else if dtype[top] == 0x44 {
				if num, _, err := stack.getNum(param[j:], 0x44); err != nil {
					return err
				} else {
					p.Index = uint32(num)
				}

				// validate outpoint: it belongs to this contract
				u := evm.GetUtxo(p.Hash, uint64(p.Index))
				var pks []byte
				if u == nil {
					cb := evm.GetCoinBase()
					cbh := cb.Hash()
					if bytes.Compare(p.Hash[:], negHash[:]) == 0 || bytes.Compare(p.Hash[:], (*cbh)[:]) == 0 {
						pks = cb.MsgTx().TxOut[p.Index].PkScript
					} else {
						return fmt.Errorf("Contract try to spend what does not exist.")
					}
				} else {
					pks = u.PkScript
				}

				adr := contract.self.Address()
				lib := stack.data[len(stack.data) - 1].inlib
				if !isContract(pks[0]) {
					return fmt.Errorf("Contract try to spend what does not belong to it.")
				}

				usr := bytes.Compare(pks[1:21], adr[:]) == 0
				libusr := bytes.Compare(pks[1:21], lib[:]) == 0
				if !usr && !libusr {
					return fmt.Errorf("Unauthorized spending.")
				} else if libusr && bytes.Compare(stack.data[len(stack.data) - 1].inlib[:], lib[:]) != 0 {
					return fmt.Errorf("Unauthorized spending.")
				} else if usr && stack.data[len(stack.data) - 1].pure & 0x2 != 0 {
					return fmt.Errorf("Unauthorized spending.")
				}

				if evm.Spend(p) {
					return nil
				}

				return fmt.Errorf("Spend failed")
			}
		}
	}

	return fmt.Errorf("Spend failed")
}

func opAddRight(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err error
	dest := pointer(0)

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

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	tk := token.RightDef{}
	var r bytes.Reader

	r.Reset(stack.data[num >> 32].space[num & 0xFFFFFFFF:])
	if err := tk.MemRead(&r, 0); err != nil {
		return err
	}

	hash := evm.AddRight(&tk)

	if dest != pointer(0) {
		stack.saveHash(&dest, hash)
	}

	return nil
}

func opAddTxOut(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	if stack.data[len(stack.data) - 1].pure & 0x4 != 0 {
		return fmt.Errorf("Load forbidden in lib %x", stack.data[len(stack.data) - 1].inlib)
	}

	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err error
	top := 0
	var dest pointer
	var src pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
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
				return fmt.Errorf("Malformed expression")
			}

			src = pointer(num)
			top++

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	tk := wire.TxOut{}
	num = int64(src)

	var r bytes.Reader

	r.Reset(stack.data[num>>32].space[num&0xFFFFFFFF : (num&0xFFFFFFFF)+100])
	if err := tk.Read(&r, 0, 0, wire.SignatureEncoding); err != nil {
		return err
	}

	var zeroaddr [20]byte
	if bytes.Compare(tk.PkScript[1:21], zeroaddr[:]) == 0 {
		return fmt.Errorf("Address is all zero.")
	}

	if isContract(tk.PkScript[0]) {
		me := contract.self.Address()
		allowed := bytes.Compare(tk.PkScript[1:21], me[:]) == 0
		for lib, _ := range contract.libs {
			if !allowed {
				allowed = bytes.Compare(tk.PkScript[1:21], lib[:]) == 0
			}
		}
		if !allowed {
			return fmt.Errorf("Contract may not add a txout outside scope")
		}
	} else {
		// check address is valid type & net
		netID := tk.PkScript[0]
		isP2PKH := evm.chainConfig.PubKeyHashAddrID == netID
		isP2SH := evm.chainConfig.ScriptHashAddrID == netID

		if isP2PKH && isP2SH {
			return btcutil.ErrAddressCollision
		} else if !isP2PKH && !isP2PKH {
			return btcutil.ErrUnknownAddressType
		}
	}

	seq := evm.AddTxOutput(tk)

	if seq < 0 {
		return fmt.Errorf("Malformed expression")
	}

	if dest != 0 && top == 2 {
		stack.saveInt32(&dest, int32(seq))
	}

	log.Debugf("Text out added as %d: value = %d to %x", seq, tk.Token.Value.(*token.NumToken).Val, tk.PkScript[1:21])

	return nil
}

func opGetDefinition(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	var num int64
	var hash chainhash.Hash
	var dest pointer
	defType := uint8(0)
	var tl int
	var err error

	dataType := []byte{0xFF, 0x68, 0x42 }

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] == 0x68 {
				hash, tl, err = stack.getHash(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			}
			if err != nil { return err }
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
			return fmt.Errorf("Malformed expression")
		}
	}

	tx := evm.GetTx()

	for _, def := range tx.MsgTx().TxDef {
		h := def.Hash()
		if h.IsEqual(&hash) {
			var w bytes.Buffer
			def.MemWrite(&w, 0)
			stack.saveBytes(&dest, w.Bytes())
			return nil
		}
	}

	var t token.Definition

	switch defType {
	case token.DefTypeBorder:
		b, err := evm.views.FetchBorderEntry(&hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.ToToken())

	case token.DefTypePolygon:
		b, err := evm.views.FetchPolygonEntry(&hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.ToToken())

	case token.DefTypeRight:
		b, err := evm.views.FetchRightEntry(&hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.(*viewpoint.RightEntry).ToToken())

	case token.DefTypeRightSet:
		b, err := evm.views.FetchRightEntry(&hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.(*viewpoint.RightSetEntry).ToToken())

	default:
		return fmt.Errorf("Unknown definition type")
	}

	var w bytes.Buffer
	t.MemWrite(&w, 0)
	return stack.saveBytes(&dest, w.Bytes())
}

func opGetUtxo(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	top := 0
	num := int64(0)
	var dest pointer
	var tx chainhash.Hash
	var seq int32
	var tl int
	var err error

	dataType := []byte{0xFF, 0x68, 0x44 }

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			if dataType[top] != 0x68 {
				num, tl, err = stack.getNum(param[j:], dataType[top])
			} else {
				tx, tl, err = stack.getHash(param[j:])
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				dest = pointer(num)
			case 1:

			case 2:
				seq = int32(num)
			}
			top++
		}
	}

	t := evm.GetUtxo(tx, uint64(seq))

	if t == nil {
		stack.saveInt64(&dest, 0)
		return nil
	}

	var w bytes.Buffer
	t.Write(&w, 0, 1, wire.SignatureEncoding)
	buf := w.Bytes()

	var p pointer
	if int64(dest >> 32) == int64(len(stack.data) - 1) {
		p,_ = stack.alloc(len(buf))
	} else {
		p,_ = stack.malloc(len(buf))
	}
	if err := stack.saveInt64(&dest, int64(p)); err != nil {
		return err
	}
	return stack.saveBytes(&p, buf)
}

func opGetCoin(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	num := int64(0)
	var dest pointer
	var err error

	num, _, err = stack.getNum(param[:], 0xFF)
	if err != nil {
		return err
	}
	dest = pointer(num)

	tx := evm.GetTx()

	if tx == nil {
		return fmt.Errorf("No transaction exists. Running in call mode instead of transaction mode?")
	}

	op := evm.GetCurrentOutput()
	coin := tx.MsgTx().TxOut[op.Index].Token

	if err := stack.saveInt64(&dest, int64(coin.TokenType)); err != nil {
		return err
	}
	dest += 8
	if coin.TokenType & 1 == 0 {
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
	if coin.TokenType & 2 == 2 {
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

func opNul(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	// this instruction is for debugging purpose, so we can insert a nul op in contract
	// and set a break point here
	return nil
}

var (
	errWriteProtection       = errors.New("evm: write protection")
	errReturnDataOutOfBounds = errors.New("evm: return data out of bounds")
	errExecutionReverted     = errors.New("evm: execution reverted")
	errMaxCodeSizeExceeded   = errors.New("evm: max code size exceeded")
)

const (
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
)
var tt256    = new(big.Int).Lsh(big.NewInt(2), 256)
var tt256m1	 = new(big.Int).Sub(tt256, big.NewInt(1))

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

func opMint(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	if stack.data[len(stack.data) - 1].pure & 0x10 != 0 {
		return fmt.Errorf("Unauthorized spending.")
	}
//	{addrOperand, 0xFFFFFFFF}, - return data place holder
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
	var md uint64				// numeric value
	var err error
	var h chainhash.Hash		// hash token's hash
	var r chainhash.Hash		// right hash
	var tokentype uint64

	dataType := []byte{0xFF, 'Q', 'D', 'h'}

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
			if err != nil { return err }
			j += tl

			switch top {
			case 0:
				dest = pointer(num)

			case 1:
				tokentype = uint64(num)
				if tokentype & 1 == 1 {
					dataType[top+1] = 'h'
				}

			case 2:
				if tokentype & 1 == 1 {
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

	mtype, _ := ovm.StateDB[address].GetMint()

	if mtype == 0 {
		if adr,ok := ovm.TokenTypes[tokentype]; ok {
			if adr != address {
				return fmt.Errorf("The tokentype %d has already been used by another smart contract.")
			}
		} else {
			var mtk [8]byte
			binary.LittleEndian.PutUint64(mtk[:], tokentype)
			// mint for the first time. fail if the tokentype has been issued.
			if err := ovm.StateDB[address].DB.View(func(dbTx database.Tx) error {
				bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
				adr := bucket.Get(mtk[:])
				if adr != nil && bytes.Compare(adr, address[:]) != 0 {
					return fmt.Errorf("The tokentype %d has already been used by another smart contract.")
				}
				if adr == nil {
					ovm.TokenTypes[tokentype] = address
				}

				return nil
			}); err != nil {
				return err
			}
		}
	}

	if !ovm.SetMint(address, tokentype, md) {
		return fmt.Errorf("Unable to mint.")
	}

	issued := token.Token{
		TokenType: tokentype,
	}

	toissue := true
	if tokentype & 1 == 0 {
		issued.Value = &token.NumToken{int64(md) }
		toissue = (md != 0)
	} else {
		issued.Value = &token.HashToken{h }
		zeroHash := chainhash.Hash{}
		toissue = (!h.IsEqual(&zeroHash))
	}
	if tokentype & 2 == 2 {
		issued.Rights = &r
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

func opMeta(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	address := contract.self.Address()

	ln := len(param)

	top := 0
	num := int64(0)
	slen := int64(0)
	var dest pointer
	var tl int
	var err error
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
			if err != nil { return err }
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

	m := ovm.getMeta(address, key)

	if err = stack.saveInt32(&dest, int32(len(m))); err != nil {
		return err
	}
	dest += 4
	return stack.saveBytes(&dest, m)
}

func opTime(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err := stack.getNum(param[j:], 0xFF)
			if err != nil { return err }
			j += tl

			dest = pointer(num)
		}
	}

	m := ovm.BlockTime()
	return stack.saveInt32(&dest, int32(m))
}

func opHeight(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	var dest pointer

	for j := 0; j < ln; j++ {
		switch param[j] {
		case '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9', 'a', 'b', 'c',
			'd', 'e', 'f', 'x', 'i', 'g':
			num, tl, err := stack.getNum(param[j:], 0xFF)
			if err != nil { return err }
			j += tl

			dest = pointer(num)

		}
	}

	m := ovm.Block().Height()
	return stack.saveInt32(&dest, int32(m))
}

/*
func opSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
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
					return fmt.Errorf("Unknown text coding")
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
func opPush(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.Code[0].param
	dest, unused := stack.malloc(int(param[0]))

	if err := stack.saveBytes(&dest, param[1 : 1 + param[0]]); err != nil {
		return err
	}
	unused -= int(param[0])
	if unused > 0 {
		stack.shrink(unused)
	}

	u := int(param[0]) + 1

	m := binary.LittleEndian.Uint32(stack.data[0].space)
	m += uint32(param[0])
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

func opAddSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.Code[0].param

	it := param[0]
	tx := ovm.GetTx()
	
	if tx == nil {
		return fmt.Errorf("Missing tx")
	}

	t := tx.MsgTx().Stripped()		// deep copy w/o contract added items

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
	case SigHashNone:
		t.TxOut = t.TxOut[0:0]
		for i := range t.TxIn {
			if uint32(i) != inidx {
				t.TxIn[i].Sequence = 0
			}
		}

	case SigHashSingle, SigHashDouble, SigHashTriple, SigHashQuardruple:
		if inidx < uint32(SigHashType(it) & SigHashMask) - uint32(SigHashSingle) {
			start = 0
		} else {
			start = inidx + uint32(SigHashSingle) - uint32(SigHashType(it)&SigHashMask)
		}
		zo := int(start)
		// Resize output array to up to and including requested index.
		if int(inidx) >= len(t.TxOut) {
			zo = len(t.TxOut)
			t.TxOut = t.TxOut[:inidx+1]
			t.TxOut[inidx].Token.Value = &token.NumToken{0}
			t.TxOut[inidx].Token.TokenType = 0
			t.TxOut[inidx].Token.Rights = nil
			t.TxOut[inidx].PkScript = nil
		} else {
			t.TxOut = t.TxOut[:inidx+1]
		}

		// All but current output get zeroed out.
		for i := 0; i < zo; i++ {
			t.TxOut[i].Token.Value = &token.NumToken{0}
			t.TxOut[i].Token.TokenType = 0
			t.TxOut[i].Token.Rights = nil
			t.TxOut[i].PkScript = nil
		}

		// Sequence on all other inputs is 0, too.
		for i := range t.TxIn {
			if i < int(start) || i > int(inidx) {
				t.TxIn[i].Sequence = 0
			}
		}

	default:
		// Consensus treats undefined hashtypes like normal SigHashAll
		// for purposes of hash generation.
		fallthrough
	case SigHashAll:
		// Nothing special here.
	}
	
	if SigHashType(it) & SigHashAnyOneCanPay != 0 {
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
