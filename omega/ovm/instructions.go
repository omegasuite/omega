// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcd/database"
	//	"io"
	"math"
	"math/big"

	"bytes"
	"encoding/binary"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	//	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/omega/token"
)

// TBD: big endian math
// memoery range check in copies

// blockIndexBucketName is the next token type number that can be used.
// all token type under 256 are reserved. curently are used as:
// 0 - main currency (OMC)
// 3 - polygon with rights
// 0xFF - separator
var IssuableTokenType = []byte("issuableTokenType")

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
// i: indirect
// x: hex number
// ,: end of operand
// BWDQH - byte, word, dword, qword, big int

// first operand is a pointer

var checkTop = map[uint8]int{0x2b:1, 0x2d:1, 0x2a:1, 0x2f:1, 0x25:1, 0x23:1,
	0x5b:1, 0x5d:1, 0x7c:1,	0x5e:1, 0x3e:1, 0x3c:1, 0x3d:1, 242:1, 243:1, 216:1, 0x3f:2}

func (stack * Stack) getNum(param []byte, dataType byte) (int64, int, error) {
	ln := len(param)
	hex := false
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	global := false
	sign := 1
	offset := 0
	hasoffset := 0
	indirect := 0
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
			if hex {
				tmp = tmp*16 + int64(param[j]-0x30)
			} else {
				tmp = tmp*10 + int64(param[j]-0x30)
			}
			nums[offset] = tmp

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp

		case 0x78: // x
			hex = true

		case 0x6e:	// n
			sign = -1

		case 0x69:	// i
			indirect++
			if indirect > 6 {
				return 0, ln, fmt.Errorf("Malformed operand")
			}

		case 0x67:	// g
			global = true

		case 0x22:	// " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0

		case 0x27:	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0

		case 0x2c:	// ,
			t := int64(0)
			num := nums[0]
			if !global {
				t = int64(len(stack.data) - 1)
			} else if indirect > 0 {
				num += int64(stack.data[len(stack.data) - 1].gbase)
			}

			if (hasoffset & 1) != 0 {
				num += nums[1]
			}

			if indirect > 0 || dataType == 0xFF {
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return 0, 0, err
					}
				}
				if (hasoffset & 2) != 0 {
					p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(nums[2])) & 0xFFFFFFFF))
				}
				switch dataType {
				case 0x42:	// byte
					b, err := stack.toByte(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b) * sign)
				case 0x57:	// word
					b, err := stack.toInt16(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b)* sign)
				case 0x44:	// dword
					b, err := stack.toInt32(&p)
					if err != nil {
						return 0,0,err
					}
					num = int64(int(b)* sign)
				case 0x51:	// qword
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
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

		case 0x75:	// u
			unsigned = true

		case 0x2b:	// +
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) + uint8(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case 0x2d:	// -
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) - uint8(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case 0x2a:	// *
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) * uint8(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case 0x2f:	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) / uint8(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case 0x25:	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int8(uint8(scratch[top-1]) % uint8(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case 0x23:	// # - exp
			if unsigned {
				scratch[top-1] = int8(math.Pow(float64(uint8(scratch[top-1])), float64(uint8(scratch[top]))))
			} else {
				scratch[top-1] = int8(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case 0x5b:	// <<
			scratch[top-1] <<= scratch[top]

		case 0x5d:	// >>
			scratch[top-1] >>= scratch[top]

		case 0x7c:	// |
			scratch[top-1] |= scratch[top]

		case 0x26:	// &
			scratch[top-1] &= scratch[top]

		case 0x5e:	// &^
			scratch[top-1] ^= scratch[top]

		case 0x7e:	// ~
			scratch[top-1] = ^scratch[top-1]

		case 0x3e:	// >
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

		case 0x3c:	// <
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

		case 0x3d:	// =
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

		case 0x29:	// >=
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

		case 0x28:	// <=
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

		case 0x21:	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case 0x3f:	// ?
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
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

		case 0x75:	// u
			unsigned = true

		case 0x2b:	// +
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) + uint16(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case 0x2d:	// -
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) - uint16(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case 0x2a:	// *
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) * uint16(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case 0x2f:	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) / uint16(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case 0x25:	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int16(uint16(scratch[top-1]) % uint16(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case 0x23:	// # - exp
			if unsigned {
				scratch[top-1] = int16(math.Pow(float64(uint16(scratch[top-1])), float64(uint16(scratch[top]))))
			} else {
				scratch[top-1] = int16(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case 0x5b:	// <<
			scratch[top-1] <<= scratch[top]

		case 0x5d:	// >>
			scratch[top-1] >>= scratch[top]

		case 0x7c:	// |
			scratch[top-1] |= scratch[top]

		case 0x26:	// &
			scratch[top-1] &= scratch[top]

		case 0x5e:	// &^
			scratch[top-1] ^= scratch[top]

		case 0x7e:	// ~
			scratch[top-1] = ^ scratch[top-1]

		case 0x3e:	// >
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

		case 0x3c:	// <
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

		case 0x3d:	// =
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

		case 0x29:	// >=
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

		case 0x28:	// <=
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

		case 0x21:	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case 0x3f:	// ?
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
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

		case 0x75:	// u
			unsigned = true

		case 0x2b:	// +
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) + uint32(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case 0x2d:	// -
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) - uint32(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case 0x2a:	// *
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) * uint32(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case 0x2f:	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) / uint32(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case 0x25:	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int32(uint32(scratch[top-1]) % uint32(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case 0x23:	// # - exp
			if unsigned {
				scratch[top-1] = int32(math.Pow(float64(uint32(scratch[top-1])), float64(uint32(scratch[top]))))
			} else {
				scratch[top-1] = int32(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case 0x5b:	// <<
			scratch[top-1] <<= scratch[top]

		case 0x5d:	// >>
			scratch[top-1] >>= scratch[top]

		case 0x7c:	// |
			scratch[top-1] |= scratch[top]

		case 0x26:	// &
			scratch[top-1] &= scratch[top]

		case 0x5e:	// &^
			scratch[top-1] ^= scratch[top]

		case 0x7e:	// ~
			scratch[top-1] = ^ scratch[top-1]

		case 0x3e:	// >
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

		case 0x3c:	// <
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

		case 0x3d:	// =
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

		case 0x29:	// >=
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

		case 0x28:	// <=
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

		case 0x21:	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case 0x3f:	// ?
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
	var store pointer
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
				return err
			}
			j += tl
			if dataType == 0xFF {
				store = pointer(num)
			} else {
				scratch[top] = num
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			dataType = 0x51

		case 0x40:	// @
			t := int64(len(stack.data)) - 1
			scratch[top] = (scratch[top] & 0xFFFFFFFF) | (t << 32)

		case 0x75:	// u
			unsigned = true

		case 0x2b:	// +
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) + uint64(scratch[top]))
			} else {
				scratch[top-1] += scratch[top]
			}

		case 0x2d:	// -
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) - uint64(scratch[top]))
			} else {
				scratch[top-1] -= scratch[top]
			}

		case 0x2a:	// *
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) * uint64(scratch[top]))
			} else {
				scratch[top-1] *= scratch[top]
			}

		case 0x2f:	// /
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) / uint64(scratch[top]))
			} else {
				scratch[top-1] /= scratch[top]
			}

		case 0x25:	// %
			if scratch[top] == 0 {
				return fmt.Errorf("Divided by 0")
			}
			if unsigned {
				scratch[top-1] = int64(uint64(scratch[top-1]) % uint64(scratch[top]))
			} else {
				scratch[top-1] %= scratch[top]
			}

		case 0x23:	// # - exp
			if unsigned {
				scratch[top-1] = int64(math.Pow(float64(uint64(scratch[top-1])), float64(uint64(scratch[top]))))
			} else {
				scratch[top-1] = int64(math.Pow(float64(scratch[top-1]), float64(scratch[top])))
			}

		case 0x5b:	// <<
			scratch[top-1] <<= scratch[top]

		case 0x5d:	// >>
			scratch[top-1] >>= scratch[top]

		case 0x7c:	// |
			scratch[top-1] |= scratch[top]

		case 0x26:	// &
			scratch[top-1] &= scratch[top]

		case 0x5e:	// &^
			scratch[top-1] ^= scratch[top]

		case 0x7e:	// ~
			scratch[top-1] = ^ scratch[top-1]

		case 0x3e:	// >
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

		case 0x3c:	// <
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

		case 0x3d:	// =
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

		case 0x29:	// >=
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

		case 0x28:	// <=
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

		case 0x21:	// !=
			if scratch[top-1] != scratch[top] {
				scratch[top-1] = 1
			} else {
				scratch[top-1] = 0
			}

		case 0x3f:	// ?
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

	return stack.saveInt64(&store, scratch[0])
}

var (
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
	bigNegOne = big.NewInt(-1)
)

func (stack * Stack) getBig(param []byte) (*big.Int, int, error) {
	ln := len(param)
	hex := false
	num := *bigZero
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	global := false
	sign := *bigOne
	offset := 0
	hasoffset := 0
	indirect := 0
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
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

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j] - 0x30)))
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp

		case 0x78: // x
			hex = true

		case 0x6e:	// n
			sign = *bigNegOne

		case 0x69:	// i
			indirect++
			if indirect > 6 {
				return bigZero, ln, fmt.Errorf("Malformed operand")
			}

		case 0x67:	// g
			global = true

		case 0x22:	// " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			t := int64(0)

			if !global {
				t = int64(len(stack.data) - 1)
			} else if indirect > 0 {
				nums[0] += int64(stack.data[len(stack.data) - 1].gbase)
			}

			if (hasoffset & 1) != 0 {
				nums[0] += nums[1]
			}

			if indirect > 0 {
				p := pointer((t << 32) | nums[0])
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return nil, 0, err
					}
				}
				if (hasoffset & 2) != 0 {
					p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(nums[2])) & 0xFFFFFFFF))
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
	global := false
	offset := 0
	hasoffset := 0
	indirect := 0
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
			if hex {
				tmp = tmp*16 + int64(param[j]-0x30)
			} else {
				tmp = tmp*10 + int64(param[j]-0x30)
			}
			nums[offset] = tmp
			if offset == 0 {
				if !hex {
					return chainhash.Hash{}, j - 1, fmt.Errorf("Malformed hash operand")
				}
				num[d] = param[j] - 0x30
				d++
			}

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			tmp = tmp*16 + int64(param[j]-0x61) + 10
			nums[offset] = tmp
			if offset == 0 {
				num[d] = param[j] - 0x61 + 10
				d++
			}

		case 0x78: // x
			hex = true

		case 0x69:	// i
			indirect++
			if indirect > 6 {
				return chainhash.Hash{}, ln, fmt.Errorf("Malformed operand")
			}

		case 0x67:	// g
			global = true

		case 0x22:	// " - head offset
			hasoffset |= 1
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			hasoffset |= 2
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			t := int64(0)

			if !global {
				t = int64(len(stack.data) - 1)
			} else if indirect > 0 {
				nums[0] += int64(stack.data[len(stack.data) - 1].gbase)
			}

			if (hasoffset & 1) != 0 {
				nums[0] += nums[1]
			}

			if indirect > 0 {
				p := pointer((t << 32) | nums[0])
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return chainhash.Hash{}, 0, err
					}
				}
				if (hasoffset & 2) != 0 {
					p = pointer((p &^ 0xFFFFFFFF) | ((p + pointer(nums[2])) & 0xFFFFFFFF))
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
						h[i / 2] = num[d - i - 1] << 4
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
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

		case 0x2b:	// +
			scratch[top-1] = scratch[top-1].Add(scratch[top-1], scratch[top])

		case 0x2d:	// -
			scratch[top-1] = scratch[top-1].Sub(scratch[top-1], scratch[top])

		case 0x2a:	// *
			scratch[top-1] = scratch[top-1].Mul(scratch[top-1], scratch[top])

		case 0x2f:	// /
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Div(scratch[top-1], scratch[top])

		case 0x25:	// %
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = scratch[top-1].Mod(scratch[top-1], scratch[top])

		case 0x23:	// # - exp
			scratch[top-1] = Exp(scratch[top-1], scratch[top])

		case 0x7c:	// logical |
			if scratch[top-1].Cmp(bigZero) == 0 || scratch[top].Cmp(bigZero) == 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case 0x26:	// logical &
			if scratch[top-1].Cmp(bigZero) != 0 && scratch[top].Cmp(bigZero) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x5e:	// logical &^
			b1 := scratch[top-1].Cmp(bigZero) != 0
			b2 := scratch[top].Cmp(bigZero) != 0
			if b1 != b2 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x7e:	// logical ~
			if scratch[top-1].Cmp(bigZero) != 0 {
				scratch[top-1] = bigZero
			} else {
				scratch[top-1] = bigOne
			}

		case 0x3e:	// >
			if scratch[top-1].Cmp(scratch[top]) > 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x3c:	// <
			if scratch[top-1].Cmp(scratch[top]) < 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x3d:	// =
			if scratch[top-1].Cmp(scratch[top]) == 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x29:	// >=
			if scratch[top-1].Cmp(scratch[top]) >= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x28:	// <=
			if scratch[top-1].Cmp(scratch[top]) <= 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x21:	// !=
			if scratch[top-1].Cmp(scratch[top]) != 0 {
				scratch[top-1] = bigOne
			} else {
				scratch[top-1] = bigZero
			}

		case 0x3f:	// ?
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

var sizeOfType = map[byte]uint32 {0x42:1, 0x57:2, 0x44:4, 0x51:8, 0x48:32 }
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl
			scratch[top] = convOperand{dtype, pointer(num) }
			dtype = 0
			top++

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQH - byte, word, dword, qword, big int
			dtype = param[j]

		case 0x75:	// u
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
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
	param := contract.GetBytes(*pc)
	// dest, src, len

	var tp pointer
	var retVal pointer
	var hash chainhash.Hash
	var pubKey [btcec.PubKeyBytesLenCompressed]byte
	var sig []byte
	var err error
	var tl int

	ln := len(param)

	top := 0
	num := int64(0)
	var bnum *big.Int

	paramTypes := []byte{0xFF, 0x48, 0xFF, 0xFF, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl, err = stack.getBig(param[j:])
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
				hash = BigToHash(bnum)

			case 2:
				tp = pointer(num)
				b,_ := stack.toBytes(&tp)
				copy(pubKey[:], b)

			case 3:
				tp = pointer(num)

			case 4:
				sig = make([]byte, num)
				b,_ := stack.toBytes(&tp)
				copy(sig, b)
			}

			top++
			num = 0
			bnum = bigZero
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

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			scratch[top] = int32(num)
			top++
		}
	}

	if scratch[0] == 0 {
		*pc++
	} else {
		inlib := stack.data[len(stack.data) - 1].inlib
		target := int32(*pc + int(scratch[1]))
		if target < contract.libs[inlib].address || target >= contract.libs[inlib].end {
			return fmt.Errorf("Out of range jump")
		}
		*pc = int(target)
	}

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
	var bnum *big.Int
	var libAddr Address
	var err error
	var tl int

	offset := 0

	f := newFrame()
	paramTypes := []byte{0x48, 0x44, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl, _ = stack.getBig(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				libAddr = BigToAddress(bnum)
				if _, ok := contract.libs[libAddr]; !ok {
					return fmt.Errorf("Lib not loaded")
				}
				top++

			case 1:
				if allZero(libAddr[:]) {
					offset = int(num)
				} else {
					var bn [4]byte
					for i := 0; i < 4; i++ {
						bn[i] = byte((num >> (i * 8)) & 0xFF)
					}
					f.space = append(f.space, bn[:]...)
				}
				top++

			default:
				var bn [8]byte
				for i := 0; i < 8; i++ {
					bn[i] = byte((num >> (i * 8)) & 0xFF)
				}
				f.space = append(f.space, bn[:]...)
			}
		}
	}

	if top >= 2 {
		f.pc = *pc
		f.pure = contract.pure
		f.inlib = libAddr
		f.gbase = contract.libs[libAddr].base
		contract.pure = contract.libs[libAddr].pure
		if allZero(libAddr[:]) {
			inlib := stack.data[len(stack.data) - 1].inlib
			target := int32(*pc + offset)
			if target < contract.libs[inlib].address || target >= contract.libs[inlib].end {
				return fmt.Errorf("Out of range func call")
			}
			*pc = int(target)
		} else {
			*pc = int(contract.libs[libAddr].address)
		}
		stack.data = append(stack.data, f)
		return nil
	}

	return fmt.Errorf("Malformed function call")
}

func opLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	slen := int64(0)
	dataType := []byte{0xFF, 0x42, 0x68}
	var err error
	var tl int
	var h chainhash.Hash
	var store pointer
	var dt byte
	top := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if dataType[top] == 0x68 {
				if h, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
			} else {
				if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
					return err
				}
				if top == 0 {
					store = pointer(num)
				} else {
					slen = num
				}
			}
			top++
			j += tl

		case 0x41, 0x42, 0x57, 0x44, 0x51, 0x48, 0x68:	// b
			// BWDQHA - byte, word, dword, qword, big int
			dt = param[j]
		}
	}

	hash := evm.GetState(contract.self.Address(), string(h[:slen]))

	n := sizeOfType[dt]
	for i := uint32(0); i < n; i++ {
		if err := stack.saveByte(&store, hash[i]); err != nil {
			return err
		}
		store++
	}

	return nil
}

func opStore(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := chainhash.Hash{}
	var tl int
	var err error
	var scratch [2]chainhash.Hash
	top := 0
	slen := int64(0)
	var dt byte

	dataType := []byte{0x42, 0x68, 0x68}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if dataType[top] == 0x68 {
				if num, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
				scratch[top] = num
			} else {
				num := int64(0)
				if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
					return err
				}
				slen = num
			}
			top++
			j += tl

		case 0x41, 0x42, 0x57, 0x44, 0x51, 0x48, 0x68:	// b
			// BWDQHA - byte, word, dword, qword, big int
			dt = param[j]
		}
	}

	evm.SetState(contract.self.Address(), string(scratch[0][:slen]), scratch[1][:sizeOfType[dt]])

	return nil
}

func opDel(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	num := chainhash.Hash{}
	top := 0
	slen := int64(0)
	var tl int

	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if top == 0 {
				if slen, tl, err = stack.getNum(param[j:], 0x42); err != nil {
					return err
				}
			} else {
				if num, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
			}
			j += tl
			top++
		}
	}
	evm.DeleteState(contract.self.Address(), string(num[:slen]))

	return nil
}

func opReceived(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	_, txout := ovm.GetCurrentOutput()

	param := contract.GetBytes(*pc)
	ln := len(param)

	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			var w bytes.Buffer
			if err := txout.Write(&w, 0, 0, wire.SignatureEncoding); err != nil {
				return err
			}

			var p pointer
			p = pointer(num)

			return stack.saveBytes(&p, w.Bytes())
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
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

				ret, err := evm.Call(toAddr, args[:4], value, args)		// nil=>value

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
	var bnum chainhash.Hash
	top := 0

	pure := true
	var tl int
	var err error

	paramTypes := []byte{0x42, 0x48}

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl, err = stack.getHash(param[j:])
			} else {
				num, tl, err = stack.getNum(param[j:], dataType)
			}
			if err != nil { return err }
			j += tl

			switch top {
			case 0:
				if num == 0 {
					pure = false
				}

			case 1:
				var d [20]byte
				copy(d[:], bnum[:20])
				if _, ok := contract.libs[d]; ok {
					return nil
				}

				sd := NewStateDB(evm.views.Db, d)

				existence := sd.Exists(true)
				if !existence {
					return fmt.Errorf("The library does not exist")
				}
				ccode := ByteCodeParser(evm.GetCode(d))
				contract.libs[d] = lib{
					address: int32(len(contract.Code)),
					end: int32(len(contract.Code) + len(ccode)),
					base: int32(len(stack.data[0].space)),
					pure: pure,
				}
				contract.Code = append(contract.Code, ccode...)
				return nil
			}
			top++
		}
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
	paramType := []byte{0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], paramType[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				retspace = pointer(num)

			case 1:
				var p pointer
				if glob {
					p,_ = stack.malloc(int(num))
				} else {
					p,_ = stack.alloc(int(num))
				}
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

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				src = pointer(num)

			case 1:
				dest = pointer(num)

			case 2:
				num += int64(src) & 0xFFFFFFFF
				copy(stack.data[dest >> 32].space[dest & 0xFFFFFFFF:], stack.data[src >> 32].space[src & 0xFFFFFFFF:num])
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
	var h chainhash.Hash
	
	dataType := byte(0xFF)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x42, 0x44, 0x51, 0x57, 0x68:
			dataType = param[j]

		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			switch dataType {
			case 0xFF, 0x42, 0x44, 0x51, 0x57:
				if num, tl, err = stack.getNum(param[j:], dataType); err != nil {
					return err
				}
			case 0x68:
				if h, tl, err = stack.getHash(param[j:]); err != nil {
					return err
				}
			}
			j += tl

			switch dataType {
				case 0xFF:
					dest = pointer(num)
					
				case 0x42:
					if err := stack.saveByte(&dest, byte(num)); err != nil {
						return err
					}
					dest++
					
				case 0x44:
					if err := stack.saveInt32(&dest, int32(num)); err != nil {
						return err
					}
					dest += 4
					
				case 0x51:
					if err := stack.saveInt64(&dest, num); err != nil {
						return err
					}
					dest += 8

				case 0x57:
					if err := stack.saveInt16(&dest, int16(num)); err != nil {
						return err
					}
					dest += 2

				case 0x68:
					if err := stack.saveHash(&dest, h); err != nil {
						return err
					}
					dest += 32
			}
		}
	}

	return nil
}

func opCodeCopy(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	top := 0

	var dest pointer
	var offset int32
	var tl int
	var err error
	dataType := []byte{0x44, 0xFF, 0x44}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if num, tl, err = stack.getNum(param[j:], dataType[top]); err != nil {
				return err
			}
			j += tl

			switch top {
			case 0:
				offset = int32(num)

			case 1:
				dest = pointer(num)

			case 2:
				d := dest & 0xFFFFFFFF
				s := dest >> 32
				for ; num > 0; num-- {
					stack.data[s].space[d] = byte(contract.Code[offset].op)
					d++
					copy(stack.data[s].space[d:], contract.Code[offset].param)
					d += pointer(int32(len(contract.Code[offset].param)))
					stack.data[s].space[d] = 10
					d++
					offset++
				}
				return nil
			}
			top++
		}
	}
	return fmt.Errorf("Malformed parameters")
}

func opSuicide(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
/*
	param := contract.GetBytes(*pc)

	ln := len(param)

	if ln == 0 {
		evm.StateDB[contract.Address()].Suicide()
		return nil
	}

	var hash chainhash.Hash
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if hash, tl, err = stack.getHash(param[j:]); err != nil {
				return err
			}
			j += tl
		}
	}

	pkScript := make([]byte, 25)
	pkScript[0] = 1		// regular account
	t := hash[:20]
	copy(pkScript[1:], t[:])
	copy(pkScript[21:], []byte{2, 0, 0, 0})	// pay2pkh: pay to public key hash
	for p, w := range evm.StateDB[contract.Address()].wallet.Tokens {
		evm.Spend(p)
		evm.AddTxOutput(wire.TxOut{
			w,
			pkScript,
		})
	}
 */

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
	*pc = stack.data[len(stack.data) - 1].pc
	contract.pure = stack.data[len(stack.data) - 1].pure
	stack.data = stack.data[:len(stack.data) - 1]
	return nil
}

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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
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

func opSpend(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0x44); err != nil {
				return err
			}
			j += tl
/*
			if num < 0 || num >= int64(len(evm.StateDB[contract.Address()].wallet.Tokens)) {
				return fmt.Errorf("Spend failed")
			}
 */

			p := wire.OutPoint{Index: uint32(num) }
			c := contract.Address()
			copy(p.Hash[:], c[:])

			if evm.Spend(p) {
				return nil
			}

			return fmt.Errorf("Spend failed")
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

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			tk := token.RightDef{}
			var r bytes.Reader
			r.Reset(stack.data[num >> 32].space[num & 0xFFFFFFFF:])
			if err := tk.MemRead(&r, 0); err != nil {
				return err
			}

			if evm.AddRight(&tk) {
				return nil
			}

			return fmt.Errorf("Malformed expression")

		default:
			return fmt.Errorf("Malformed expression")
		}
	}
	return fmt.Errorf("Malformed expression")
}

func opAddTxOut(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xFF); err != nil {
				return err
			}
			j += tl

			tk := wire.TxOut{}
			var r bytes.Reader

			r.Reset(stack.data[num >> 32].space[num & 0xFFFFFFFF:])
			if err := tk.Read(&r, 0, 0, wire.SignatureEncoding); err != nil {
				return err
			}

			if isContract(tk.PkScript[0]) {
				return fmt.Errorf("Contract may not add a txout paybale to contract address")
			}

			if evm.AddTxOutput(tk) {
				return nil
			}

			return fmt.Errorf("Malformed expression")

		default:
			return fmt.Errorf("Malformed expression")
		}
	}
	return fmt.Errorf("Malformed expression")
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
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
		b, err := evm.views.Border.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.ToToken())

	case token.DefTypePolygon:
		b, err := evm.views.Polygon.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.ToToken())

	case token.DefTypeRight:
		b, err := evm.views.Rights.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.(*viewpoint.RightEntry).ToToken())

	case token.DefTypeRightSet:
		b, err := evm.views.Rights.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(b.(*viewpoint.RightSetEntry).ToToken())
/*
	case token.DefTypeVertex:
		v, err := evm.views.Vertex.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(v.ToToken())
 */

	default:
		return fmt.Errorf("Unknown definition type")
	}

	var w bytes.Buffer
	t.MemWrite(&w, 0)
	return stack.saveBytes(&dest, w.Bytes())
}

/*
func opGetCoin(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	num := int64(0)
	var dest pointer
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if num, tl, err = stack.getNum(param[j:], 0xff); err != nil { return err }
			j += tl
			dest = pointer(num)
		}
	}

	c := evm.StateDB[contract.Address()].GetCoins()

	if err := stack.saveInt32(&dest, int32(len(c))); err != nil {
		return err
	}
	dest += 4

	if c == nil || len(c) == 0 {
		if err := stack.saveInt64(&dest, int64(0)); err != nil {
			return err
		}
		return nil
	}

	var p pointer
	if int64(dest >> 32) == int64(len(stack.data) - 1) {
		p,_ = stack.alloc(len(c) * 8)
	} else {
		p,_ = stack.malloc(len(c) * 8)
	}
	if err := stack.saveInt64(&dest, int64(p)); err != nil {
		return err
	}

	for _, w := range c {
		var wb bytes.Buffer
		w.Write(&wb, 0, 0)
		b := wb.Bytes()
		var q pointer
		if int64(dest >> 32) == int64(len(stack.data) - 1) {
			q,_ = stack.alloc(len(b))
		} else {
			q,_ = stack.malloc(len(b))
		}
		if err := stack.saveInt64(&p, int64(q)); err != nil {
			return err
		}
		p += 8
		if err := stack.saveBytes(&q, b); err != nil {
			return err
		}
	}

	return nil
}
 */

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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
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
	t.Write(&w, 0, 0, wire.SignatureEncoding)
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
	// mint coins.
	param := contract.GetBytes(*pc)
	address := contract.self.Address()

	ln := len(param)

	top := 0
	num := int64(0)
	var bnum *big.Int
	var dest pointer
	var tl int
	var md uint64				// numeric value
	var err error
	var h chainhash.Hash		// hash token's hash
	var r chainhash.Hash		// right hash
	var tokentype uint64

	dataType := []byte{0xFF, 0x42, 0x48, 0x68}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if dataType[top] == 0x48 {
				bnum, tl, err = stack.getBig(param[j:])
			} else if dataType[top] == 0x68 {
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

			case 2:
				if tokentype & 1 == 1 {
					copy(h[:], bnum.Bytes())
					md = 1
				} else {
					md = uint64(bnum.Int64())
				}

			case 3:
			}
			top++
		}
	}

	mtype, issue := ovm.StateDB[address].GetMint()

	if mtype == 0 {
		// mint for the first time, assign a new tokentype. This is instant, does not defer to
		// commitment even the call fails eventually. In that case, we waste a tokentype code.

		err := ovm.StateDB[address].DB.Update(func(dbTx database.Tx) error {
			// the tokentype value for numtoken available
			version := DbFetchNextTokenType(dbTx)

			mtype, issue = version[tokentype & 3] | (tokentype & 3), 0

			return DbPutNextTokenType(dbTx, mtype + 4)
		})
		if err != nil {
			return err
		}
	}

	if !ovm.SetMint(address, mtype, md) {
		return fmt.Errorf("Unable to mint.")
	}

	issued := token.Token{
		TokenType: mtype,
	}
	if mtype & 1 == 0 {
		issued.Value = &token.NumToken{int64(md) }
	} else {
		issued.Value = &token.HashToken{h }
	}
	if mtype & 2 == 2 {
		issued.Rights = &r
	}

	// add a tx out in coinbase
	txo := wire.TxOut {}
	txo.Token = issued
	txo.PkScript = make([]byte, 21)
	txo.PkScript[0] = 1
	copy(txo.PkScript[1:], address[:])

	outpoint := ovm.AddCoinBase(txo)
//	ovm.StateDB[address].credit(outpoint, issued)

	if err = stack.saveInt64(&dest, int64(mtype)); err != nil {
		return err
	}
	dest += 8
	if err = stack.saveHash(&dest, outpoint.Hash); err != nil {
		return err
	}
	dest += 32
	return stack.saveInt32(&dest, int32(outpoint.Index))
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
	var r chainhash.Hash

	dataType := []byte{0xFF, 0x42, 0x68}

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67: // 0 - 9
			if dataType[top] == 0x68 {
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

	if len(contract.Code[0].param) <= u {
		contract.Code[0] = inst{'z', nil}
	} else {
		contract.Code[0] = inst{OpCode(contract.Code[0].param[u]), contract.Code[0].param[u+1:]}
	}
	*pc--
	return nil
}

func opAddSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.Code[0].param

	it := param[0]

	t := ovm.GetTx()
	
	u := 1

	if t == nil {
		dest, unsed := stack.malloc(4)
		stack.saveInt32(&dest, 0)
		unsed -= 4
		stack.shrink(unsed)
		return nil
	}

	inidx := binary.LittleEndian.Uint32(contract.Args)

	var wbuf bytes.Buffer
	var buf [4]byte

	switch it {	// text encoding
	case 0:		// current outpoint
		wbuf.Write(t.MsgTx().TxIn[inidx].PreviousOutPoint.Hash[:])
		binary.LittleEndian.PutUint32(buf[:], t.MsgTx().TxIn[inidx].PreviousOutPoint.Index)
		wbuf.Write(buf[:4])

	case 1:		// transaction (BaseEncoding)
		err := t.MsgTx().BtcEncode(&wbuf, 0, wire.BaseEncoding)
		if err != nil {
			return err
		}

	case 2:		// all output
		for _, txo := range t.MsgTx().TxOut {
			if txo.IsSeparator() {
				break
			}
			err := txo.WriteTxOut(&wbuf, 0, t.MsgTx().Version, wire.BaseEncoding)
			if err != nil {
				return err
			}
		}

	case 3:		// specific matching outputs
		lb := int(param[1])
		u += 1 + lb
		hash := param[2:2+lb]
		for i, txo := range t.MsgTx().TxOut {
			if i < lb * 8 && hash[i >> 3] & (1 << (i & 7)) != 0 && !txo.IsSeparator() {
				err := txo.WriteTxOut(&wbuf, 0, t.MsgTx().Version, wire.BaseEncoding)
				if err != nil {
					return err
				}
			}
		}

	default:
		return fmt.Errorf("Unknown text coding")
	}

	f := wbuf.Bytes()

	dest, unused := stack.malloc(len(f) + 4)
	p := dest + 4

	if err := stack.saveInt32(&dest, int32(len(f))); err != nil {
		return err
	}
	err := stack.saveBytes(&p, f)
	unused -= len(f) + 4

	m := binary.LittleEndian.Uint32(stack.data[0].space)
	m += uint32(len(f)) + 4
	binary.LittleEndian.PutUint32(stack.data[0].space, m)

	stack.shrink(unused)

	if len(contract.Code[0].param) <= u {
		contract.Code[0] = inst{'z', nil}
	} else {
		contract.Code[0] = inst{OpCode(contract.Code[0].param[u]), contract.Code[0].param[u+1:]}
	}
	*pc--
	
	return err
}
