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

// operators: u+-*/><=?|*^~%[](>=)(<=)(!=)
// u: unsigned
// +-*/%#: +-*/%#(exp)
// ><=!(): compare: >, <, ==, !=, <=, >=
// ?: select
// |&~^: bitwise/logical: |&~^
// []: shift: <<, >>

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

func getNum(param []byte) (int64, int) {
	ln := len(param)
	hex := false
	num := int64(0)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
			if hex {
				num = num*16 + int64(param[j]-0x30)
			} else {
				num = num*10 + int64(param[j]-0x30)
			}

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			num = num*16 + int64(param[j]-0x61) + 10

		case 0x78: // x
			hex = true

		default:
			return num, j - 1
		}
	}
	return num, ln
}

func opEval8(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int8, lim)

	top := 0
	indirect := 0
	ispointer := true
	global := false
	unsigned := false
	num := int64(0)
	sign := int64(1)
	var store pointer
	var r bool
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x6e:	// n
			sign = -1

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if !ispointer {
					b, err := stack.toByte(&p)
					if err != nil {
						return err
					}
					num = int64(b)
				} else {
					store = p
				}
				indirect = 0
			}
			if !ispointer {
				scratch[top] = int8(num * sign)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			sign = 1
			num = 0
			global = false
			ispointer = false

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

	stack.saveByte(&store, byte(scratch[0]))

	return nil
}

func opEval16(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int16, lim)

	top := 0
	indirect := 0
	ispointer := true
	global := false
	unsigned := false
	num := int64(0)
	sign := int64(1)
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x6e:	// n
			sign = -1

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if !ispointer {
					b, err := stack.toInt16(&p)
					if err != nil {
						return err
					}
					num = int64(b)
				} else {
					store = p
				}
				indirect = 0
			}
			if !ispointer {
				scratch[top] = int16(num * sign)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			sign = 1
			num = 0
			global = false
			ispointer = false

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

	stack.saveInt16(&store, scratch[0])

	return nil
}

func opEval32(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int32, lim)

	top := 0
	indirect := 0
	ispointer := true
	global := false
	unsigned := false
	num := int64(0)
	sign := int64(1)
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x6e:	// n
			sign = -1

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if !ispointer {
					b, err := stack.toInt32(&p)
					if err != nil {
						return err
					}
					num = int64(b)
				} else {
					store = p
				}
				indirect = 0
			}
			if !ispointer {
				scratch[top] = int32(num * sign)
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			sign = 1
			num = 0
			global = false
			ispointer = false

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

	stack.saveInt32(&store, scratch[0])

	return nil
}

func opEval64(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]int64, lim)

	top := 0
	indirect := 0
	ispointer := true
	global := false
	unsigned := false
	num := int64(0)
	sign := int64(1)
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x6e:	// n
			sign = -1

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x40:	// @
			t := int64(0)
			if !global {
				t = int64(len(stack.data)) - 1
			}
			indirect = 0
			scratch[top] = (scratch[top] & 0xFFFFFFFF) | (t << 32)
			sign = 1
			num = 0
			global = false
			ispointer = false

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if !ispointer {
					if num, err = stack.toInt64(&p); err != nil {
						return err
					}
				} else {
					store = p
				}
				indirect = 0
			}
			if !ispointer {
				scratch[top] = num * sign
				top++
				if top == lim {
					scratch = append(scratch, 0)
					lim++
				}
			}
			sign = 1
			num = 0
			global = false
			ispointer = false

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

	stack.saveInt64(&store, scratch[0])

	return nil
}

var (
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
	bigNegOne = big.NewInt(-1)
)

func getBig(param []byte) (*big.Int, int) {
	ln := len(param)
	hex := false
	num := *bigZero

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
			if hex {
				num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j] - 0x30)))
			} else {
				num = *num.Add(num.Mul(&num, big.NewInt(10)), big.NewInt(int64(param[j] - 0x30)))
			}

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			num = *num.Add(num.Mul(&num, big.NewInt(16)), big.NewInt(int64(param[j] - 0x30)))

		case 0x78: // x
			hex = true

		default:
			return &num, j - 1
		}
	}
	return &num, ln
}

func opEval256(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)
	lim := (ln + 7) / 4

	scratch := make([]big.Int, lim)

	top := 0
	indirect := 0
	ispointer := true
	global := false
	var num * big.Int
	sign := *bigOne
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getBig(param[j:])
			j += tl

		case 0x6e:	// n
			sign = *bigNegOne

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}

				p := pointer((t << 32) | num.Int64())
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if !ispointer {
					if h, err := stack.toHash(&p); err != nil {
						return err
					} else {
						num.SetBytes(h[:])
					}
				} else {
					store = p
				}
				indirect = 0
			}
			if !ispointer {
				scratch[top] = *num.Mul(num, &sign)
				top++
				if top == lim {
					scratch = append(scratch, *bigZero)
					lim++
				}
			}
			sign = *bigOne
			num = bigZero
			global = false
			ispointer = false

		case 0x2b:	// +
			scratch[top-1] = *scratch[top-1].Add(&scratch[top-1], &scratch[top])

		case 0x2d:	// -
			scratch[top-1] = *scratch[top-1].Sub(&scratch[top-1], &scratch[top])

		case 0x2a:	// *
			scratch[top-1] = *scratch[top-1].Mul(&scratch[top-1], &scratch[top])

		case 0x2f:	// /
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = *scratch[top-1].Div(&scratch[top-1], &scratch[top])

		case 0x25:	// %
			if scratch[top].Cmp(bigZero) == 0 {
				return fmt.Errorf("Divided by 0")
			}
			scratch[top-1] = *scratch[top-1].Mod(&scratch[top-1], &scratch[top])

		case 0x23:	// # - exp
			scratch[top-1] = * Exp(&scratch[top-1], &scratch[top])

		case 0x7c:	// logical |
			if scratch[top-1].Cmp(bigZero) == 0 || scratch[top].Cmp(bigZero) == 0 {
				scratch[top-1] = * bigZero
			} else {
				scratch[top-1] = * bigOne
			}

		case 0x26:	// logical &
			if scratch[top-1].Cmp(bigZero) != 0 && scratch[top].Cmp(bigZero) != 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x5e:	// logical &^
			b1 := scratch[top-1].Cmp(bigZero) != 0
			b2 := scratch[top].Cmp(bigZero) != 0
			if b1 != b2 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x7e:	// logical ~
			if scratch[top-1].Cmp(bigZero) != 0 {
				scratch[top-1] = * bigZero
			} else {
				scratch[top-1] = * bigOne
			}

		case 0x3e:	// >
			if scratch[top-1].Cmp(&scratch[top]) > 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x3c:	// <
			if scratch[top-1].Cmp(&scratch[top]) < 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x3d:	// =
			if scratch[top-1].Cmp(&scratch[top]) == 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x29:	// >=
			if scratch[top-1].Cmp(&scratch[top]) >= 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x28:	// <=
			if scratch[top-1].Cmp(&scratch[top]) <= 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
			}

		case 0x21:	// !=
			if scratch[top-1].Cmp(&scratch[top]) != 0 {
				scratch[top-1] = * bigOne
			} else {
				scratch[top-1] = * bigZero
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
	h.SetBytes(scratch[0].Bytes())
	stack.saveHash(&store, h)

	return nil
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

	indirect := 0
	top := 0
	dtype := byte(0)
	global := false
	num := int64(0)
	unsigned := false
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQH - byte, word, dword, qword, big int
			dtype = param[j]

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Direct number not allowed.")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			scratch[top] = convOperand{dtype, p}
			indirect = 0
			num = 0
			dtype = 0
			global = false
			top++

		case 0x75:	// u
			unsigned = true

		default:
			return fmt.Errorf("Malformed expression")
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
	indirect := 0
	global := false
	num := int64(0)
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data)) - 1
			}

			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			scratch[top] = p
			top++
			indirect = 0
			num = 0
			global = false
		}
	}

	t := scratch[1]
	a := t & 0xFFFFFFFF
	b := a + (scratch[2] & 0xFFFFFFFF)

	hash := chainhash.HashB(stack.data[t >> 32].space[a:b])

	stack.saveBytes(&scratch[0], hash)

	return nil
}

func opHash160(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	// dest, src, len

	var scratch [3]pointer
	ln := len(param)

	top := 0
	indirect := 0
	global := false
	num := int64(0)
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data)) - 1
			}

			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			scratch[top] = p
			top++
			indirect = 0
			num = 0
			global = false
		}
	}

	t := scratch[1]
	a := t & 0xFFFFFFFF
	b := a + (scratch[2] & 0xFFFFFFFF)

	hash := hash160(stack.data[t >> 32].space[a:b])

	stack.saveBytes(&scratch[0], hash)

	return nil
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
	indirect := 0
	global := false
	num := int64(0)
	var bnum *big.Int

	paramTypes := []byte{0x51, 0x48, 0x51, 0x51, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl = getBig(param[j:])
			} else {
				num, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data)) - 1
			}

			if dataType == 0x48 {
				num = bnum.Int64()
			}

			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			switch top {
			case 0:
				retVal = p

			case 1:
				if indirect > 0 {
					hash,_ = stack.toHash(&p)
				} else {
					hash = BigToHash(bnum)
				}

			case 2:
				b,_ := stack.toBytes(&tp)
				copy(pubKey[:], b)

			case 3:
				tp = p
			case 4:
				sig = make([]byte, num)
				b,_ := stack.toBytes(&tp)
				copy(sig, b)
			}

			top++
			indirect = 0
			num = 0
			bnum = bigZero
			global = false
		}
	}

	result := byte(0)

	err = btcutil.VerifySigScript2(sig, hash[:], pubKey[:], evm.chainConfig)

	if err == nil {
		result = 1
	}

	stack.saveByte(&retVal, result)

	return nil
}

func opIf(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var scratch [2]int32

	top := 0
	indirect := 0
	global := false
	num := int64(0)
	var err error
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}

			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			if top == 0 && indirect > 0 {
				v,_ := stack.toByte(&p)
				num = int64(v)
			} else if indirect > 0 {
				v,_ := stack.toInt32(&p)
				num = int64(v)
			}

			scratch[top] = int32(num)
			top++
			indirect = 0
			num = 0
			global = false
		}
	}

	if scratch[0] == 0 {
		*pc++
	} else {
		*pc += int(scratch[1])
	}

	return nil
}

func opCall(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	// base, entry, params
	// if address == 0, entry is relative to pc
	// if address != 0, lib address, entry is relative to lib

	ln := len(param)

	top := 0
	indirect := 0
	global := false
	num := int64(0)
	var bnum *big.Int
	var libAddr Address
	var err error
	var tl int

	offset := 0

	f := newFrame()
	paramTypes := []byte{0x48, 0x44, 0x51, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl = getBig(param[j:])
			} else {
				num, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect > 0 {
				t := int64(0)
				if !global {
					t = int64(len(stack.data) - 1)
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p,err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				if num, err = stack.toInt64(&p); err != nil {
					return err
				}
				indirect = 0
			}

			switch top {
			case 0:
				libAddr = BigToAddress(bnum)
				if _,ok := evm.libs[libAddr]; !ok {
					return fmt.Errorf("Lib not loaded")
				}

			case 1:
				offset = int(num)

			default:
				var bn [8]byte
				for i := 0; i < 8; i++ {
					bn[i] = byte((num >> (i * 8)) & 0xFF)
				}
				f.space = append(f.space, bn[:]...)
			}
			num = 0
		}
		top++
	}

	if top >= 2 {
		f.pc = *pc
		f.pure = contract.pure
		contract.pure = evm.libs[libAddr].pure
		stack.data = append(stack.data, f)
		if allZero(libAddr[:]) {
			*pc += offset
		} else {
			*pc = int(evm.libs[libAddr].address) + offset
		}
		return nil
	}

	return fmt.Errorf("Malformed function call")
}

func opLoad(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	dataType := byte(0x68)
	var err error
	var tl int

	var h chainhash.Hash
	h.SetBytes(param[:chainhash.HashSize])
	hash := evm.StateDB[contract.self.Address()].GetState(&h)

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQHA - byte, word, dword, qword, big int
			dataType = param[j]

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			n := sizeOfType[dataType]
			for i := uint32(0); i < n; i++ {
				stack.saveByte(&p, hash[i])
				p++
			}
			return nil
		}
	}

	return nil
}

func opStore(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	dataType := byte(0x68)
	var tl int
	var err error

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQHA - byte, word, dword, qword, big int
			dataType = param[j]

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			result := chainhash.Hash{}
			n := sizeOfType[dataType]
			for i := uint32(0); i < n; i++ {
				result[i],_ = stack.toByte(&p)
				p++
			}

			var h chainhash.Hash
			h.SetBytes(param[:chainhash.HashSize])

			evm.StateDB[contract.self.Address()].SetState(&h, result)

			return nil
		}
	}

	return nil
}

func opReceived(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	txout := ovm.GetCurrentOutput()

	param := contract.GetBytes(*pc)
	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	var tl int
	var err error

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			var w bytes.Buffer
			if err := txout.Write(&w, 0, 0, wire.SignatureEncoding); err != nil {
				return err
			}

			stack.saveBytes(&p, w.Bytes())

			return nil
		}
	}

	return nil
}

func opExec(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)
	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	var bnum *big.Int
	top := 0

	var toAddr Address
	var value * token.Token
	var pm pointer
	var retspace pointer
	var retlen int32
	var tl int
	var err error

	paramTypes := []byte{0x51, 0x44, 0x48, 0x51, 0x51, 0x44}

	for j := chainhash.HashSize; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl = getBig(param[j:])
			} else {
				num, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			switch top {
			case 0:
				retspace = p

			case 1:
				retlen = int32(num)

			case 2:	// address
				toAddr = BigToAddress(bnum)

			case 3:
				if num != 0 {
					value = &token.Token{}
					var r bytes.Reader
					r.Reset(stack.data[num>>32].space[num&0xFFFFFFFF:])
					value.Read(&r, 0, 0)
				}

			case 4:
				pm = p

			case 5:
				if value != nil {
					if err := evm.StateDB[contract.Address()].Debt(*value); err != nil {
						return err
					}
				}

				args := stack.data[pm >> 32].space[pm & 0xFFFFFFFF:(int64(pm) & 0xFFFFFFFF) + num]
				ret, err := evm.Call(toAddr, args[:4], value, args)		// nil=>value

				if (err == nil || err == errExecutionReverted) && retspace != 0 {
					retlen += int32(retspace & 0xFFFFFFFF)
					copy(stack.data[retspace >> 32].space[retspace & 0xFFFFFFFF:retlen], ret)
				}

				if err == nil && value != nil {
					evm.StateDB[toAddr].Credit(*value)
				}

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

	indirect := 0
	global := false
	num := int64(0)
	var bnum *big.Int
	top := 0

	pure := true
	var tl int
	var err error

	paramTypes := []byte{0x42, 0x48}

	for j := chainhash.HashSize; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				bnum, tl = getBig(param[j:])
			} else {
				num, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			switch top {
			case 0:
				if num == 0 {
					pure = false
				}

			case 1:
				d := BigToAddress(bnum)
				if _, ok := evm.libs[d]; ok {
					return nil
				}

				sd := &stateDB{
					DB:       evm.views.Db,
					contract: d,
					data:     make(map[chainhash.Hash]entry),
					wallet:   make([]WalletItem, 0),
					meta: make(map[string]struct {
						data []byte
						back []byte
						flag status
					}),
				}
				existence := sd.Exists()
				if !existence {
					return fmt.Errorf("The library does not exist")
				}
				evm.libs[d] = lib{
					int32(len(contract.Code)),
					pure,
				}
				contract.Code = append(contract.Code, ByteCodeParser(sd.GetCode())...)
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

	indirect := 0
	global := false
	num := int64(0)
	top := 0
	var tl int
	var err error

	var retspace pointer

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			switch top {
			case 0:
				retspace = p

			case 1:
				var p pointer
				if glob {
					p = stack.malloc(int(num))
				} else {
					p = stack.alloc(int(num))
				}
				stack.saveInt64(&retspace, int64(p))

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

	indirect := 0
	global := false
	num := int64(0)
	top := 0

	var src pointer
	var dest pointer
	var tl int
	var err error

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			switch top {
			case 0:
				src = p

			case 1:
				dest = p

			case 2:
				if indirect > 0 {
					b,_ := stack.toInt32(&p)
					num = int64(b)
				}
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

	indirect := 0
	global := false
	num := int64(0)
	top := 0

	var dest pointer
	var tl int
	var err error

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			switch top {
			case 0:
				dest = p
				top++

			case 1:
				if indirect > 0 {
					b,_ := stack.toInt32(&p)
					num = int64(b)
				}
				stack.saveByte(&dest, byte(num))
				dest++
			}
		}
	}
	return nil
}

func opCodeCopy(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	top := 0

	var dest pointer
	var offset int32
	var tl int
	var err error

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			if indirect == 0 {
				fmt.Errorf("Can not save expression result")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p,err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			switch top {
			case 0:
				if indirect > 0 {
					offset,_ = stack.toInt32(&p)
				}

			case 1:
				dest = p

			case 2:
				if indirect > 0 {
					b,_ := stack.toInt32(&p)
					num = int64(b)
				}
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
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	global := false
	top := 0
	num := int64(0)
	var hash chainhash.Hash
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g
			global = true

		case 0x2c:	// ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			if indirect > 0 {
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				hash, _ = stack.toHash(&p)
			}

			top++
		}
	}

	pkScript := make([]byte, 25)
	pkScript[0] = 1		// regular account
	t := hash[:20]
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
	return nil
}

func opRevert(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return nil
}

func opStop(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return nil
}

func opReturn(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	*pc = stack.data[len(stack.data) - 1].pc + 1
	contract.pure = stack.data[len(stack.data) - 1].pure
	stack.data = stack.data[:len(stack.data) - 1]
	return nil
}

func opTxIOCount(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	var scratch [3]pointer

	ln := len(param)

	indirect := 0
	top := 0
	global := false
	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			if indirect == 0 {
				fmt.Errorf("Direct number not allowed.")
			}

			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p, err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			scratch[top] = p
			indirect = 0
			num = 0
			global = false
			top++

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	tx := evm.GetTx()
	stack.saveInt32(&scratch[0], int32(len(tx.TxIn)))
	stack.saveInt32(&scratch[1], int32(len(tx.TxOut)))
	stack.saveInt32(&scratch[2], int32(len(tx.TxDef)))
	return nil
}

func opGetTxIn(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opGetTxIO(pc, evm, contract, stack, true)
}

func opGetTxIO(pc *int, evm *OVM, contract *Contract, stack *Stack, in bool) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	top := 0
	global := false
	num := int64(0)
	var bnum * big.Int
	inid := int32(0)
	var dest pointer
	var hash chainhash.Hash
	var tl int
	var err error

	var op wire.OutPoint

	tx := evm.GetTx()

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 1 {
				bnum,tl = getBig(param[j:])
				j += tl
			} else {
				num, tl = getNum(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			if indirect > 0 {
				if top == 1 {
					num = bnum.Int64()
				}
				p := pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				switch top {
				case 0:
					dest = p
				case 1:
					if in {
						inid,_ = stack.toInt32(&p)
						op = tx.TxIn[inid].PreviousOutPoint
					} else {
						hash,_ = stack.toHash(&p)
					}
				case 2:
					inid,_ = stack.toInt32(&p)
					op = wire.OutPoint{hash, uint32(inid) }
				}
			} else {
				switch top {
				case 1:
					if in {
						op = tx.TxIn[bnum.Int64()].PreviousOutPoint
					} else {
						copy(hash[:], bnum.Bytes())
					}
				case 2:
					op = wire.OutPoint{hash, uint32(num) }
				}
			}
			indirect = 0
			num = 0
			global = false
			top++

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	evm.views.Utxo.FetchUtxosMain(evm.views.Db, map[wire.OutPoint]struct{}{op: {}})
	ue := evm.views.Utxo.LookupEntry(op)
	tue := ue.ToTxOut()

	var w bytes.Buffer
	tue.Write(&w, 0, 0, wire.SignatureEncoding)
	stack.saveBytes(&dest, w.Bytes())

	return nil
}

func opGetTxOut(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	return opGetTxIO(pc, evm, contract, stack, false)
}

func opSpend(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p, err = stack.toPointer(&p); err != nil {
					return err
				}
			}
			if indirect > 0 {
				v,_ := stack.toInt32(&p)
				num = int64(v)
			}

			c := evm.StateDB[contract.Address()].wallet[num]
			if evm.Spend(c.Token) {
				return nil
			}

			return fmt.Errorf("Spend failed")

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	return fmt.Errorf("Spend failed")
}

func opAddRight(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	global := false
	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p, err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			tk := token.RightDef{}
			var r bytes.Reader
			r.Reset(stack.data[p >> 32].space[p & 0xFFFFFFFF:])
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

	indirect := 0
	global := false
	num := int64(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			num, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			p := pointer((t << 32) | num)
			for ; indirect > 1; indirect-- {
				if p, err = stack.toPointer(&p); err != nil {
					return err
				}
			}

			tk := wire.TxOut{}
			var r bytes.Reader

			r.Reset(stack.data[p >> 32].space[p & 0xFFFFFFFF:])
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

	indirect := 0
	top := 0
	global := false
	var num * big.Int
	var hash chainhash.Hash
	var dest pointer
	defType := uint8(0)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			num, tl = getBig(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}
			if indirect > 0 {
				p := pointer((t << 32) | num.Int64())
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				switch top {
				case 0:
					dest = p
				case 1:
					hash, _ = stack.toHash(&p)
				case 2:
					defType,_ = stack.toByte(&p)
				}
			} else {
				switch top {
				case 1:
					copy(hash[:], num.Bytes())
				case 2:
					defType = uint8(num.Int64())
				}
			}
			indirect = 0
			top++
			global = false
			num = bigZero

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	tx := evm.GetTx()

	for _, def := range tx.TxDef {
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

	case token.DefTypeVertex:
		v, err := evm.views.Vertex.FetchEntry(evm.views.Db, &hash)
		if err != nil {
			return err
		}
		t = token.Definition(v.ToToken())

	default:
		return fmt.Errorf("Unknown definition type")
	}

	var w bytes.Buffer
	t.MemWrite(&w, 0)
	stack.saveBytes(&dest, w.Bytes())

	return nil
}

func opGetCoin(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	var scratch [2]chainhash.Hash

	indirect := 0
	top := 0
	global := false
	num := int64(0)
	var bnum * big.Int
	var dest pointer
	var tokentype int64
	var criteria int64
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top < 2 {
				num, tl = getNum(param[j:])
				j += tl
			} else {
				bnum, tl = getBig(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}

			var p pointer
			if indirect > 0 {
				if top < 2 {
					p = pointer((t << 32) | num)
				} else {
					p = pointer((t << 32) | bnum.Int64())
				}
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
			}

			switch top {
			case 0:
				dest = p
			case 1:
				if indirect > 0 {
					tokentype, _ = stack.toInt64(&p)
				} else {
					tokentype = bnum.Int64()
				}
			case 2:
				if indirect > 0 {
					criteria, _ = stack.toInt64(&p)
				} else {
					criteria = bnum.Int64()
				}
			case 3, 4:
				if indirect > 0 {
					scratch[top-3], _ = stack.toHash(&p)
				} else {
					copy(scratch[top-3][:], bnum.Bytes())
				}
			}
			indirect = 0
			top++
			global = false
			bnum = bigZero
			num = 0

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	c := evm.StateDB[contract.Address()].GetCoins(uint64(tokentype), uint64(criteria), scratch[0], scratch[1])

	stack.saveInt32(&dest, int32(len(c)))
	dest += 4

	if c == nil || len(c) == 0 {
		return nil
	}

	var p pointer
	if int64(dest >> 32) == int64(len(stack.data) - 1) {
		p = stack.alloc(len(c) * 8)
	} else {
		p = stack.malloc(len(c) * 8)
	}
	stack.saveInt64(&dest, int64(p))

	for _, w := range c {
		var q pointer
		if int64(dest >> 32) == int64(len(stack.data) - 1) {
			q = stack.alloc(len(w))
		} else {
			q = stack.malloc(len(w))
		}
		stack.saveInt64(&p, int64(q))
		p += 8
		stack.saveBytes(&q, w)
	}

	return nil
}

func opGetUtxo(pc *int, evm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	top := 0
	global := false
	num := int64(0)
	var bnum * big.Int
	var dest pointer
	var tx chainhash.Hash
	var seq int32
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 0 || top == 2 {
				num, tl = getNum(param[j:])
				j += tl
			} else {
				bnum, tl = getBig(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}

			var p pointer

			if indirect > 0 {
				if top != 0 && top != 2 {
					num = bnum.Int64()
				}
				p = pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
			}

			switch top {
			case 0:
				dest = p
			case 1:
				if indirect > 0 {
					tx, _ = stack.toHash(&p)
				} else {
					copy(tx[:], bnum.Bytes())
				}
			case 2:
				if indirect > 0 {
					seq, _ = stack.toInt32(&p)
				} else {
					seq = int32(num)
				}
			}
			indirect = 0
			top++
			global = false
			bnum = bigZero
			num = 0

		default:
			return fmt.Errorf("Malformed expression")
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
		p = stack.alloc(len(buf))
	} else {
		p = stack.malloc(len(buf))
	}
	stack.saveInt64(&dest, int64(p))
	stack.saveBytes(&p, buf)

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

func opAddSignText(pc *int, ovm *OVM, contract *Contract, stack *Stack) error {
	param := contract.GetBytes(*pc)

	ln := len(param)

	indirect := 0
	top := 0
	global := false
	num := int64(0)
	var bnum *big.Int
	var hash []byte
	it := byte(1)
	var tl int
	var err error

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 2 {
				bnum, tl = getBig(param[j:])
				j += tl
			} else {
				num, tl = getNum(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g
			global = true

		case 0x2c: // ,
			t := int64(0)
			if !global {
				t = int64(len(stack.data) - 1)
			}

			var p pointer

			if indirect > 0 {
				p = pointer((t << 32) | num)
				for ; indirect > 1; indirect-- {
					if p, err = stack.toPointer(&p); err != nil {
						return err
					}
				}
				b,_ := stack.toByte(&p)
				num = int64(b)
			}

			switch top {
			case 0:
				it = byte(num)
			case 1:
				hash = bnum.Bytes()
			}
			indirect = 0
			top++
			global = false
			bnum = bigZero
			num = 0

		default:
			return fmt.Errorf("Malformed expression")
		}
	}

	t := ovm.GetTx()

	dest := stack.malloc(4)

	if t == nil {
		stack.saveInt64(&dest, 0)
		return nil
	}

	inidx := binary.LittleEndian.Uint32(contract.Args)

	var wbuf bytes.Buffer
	var buf [4]byte

	switch it {	// text encoding
	case 0:		// current outpoint
		wbuf.Write(t.TxIn[inidx].PreviousOutPoint.Hash[:])
		binary.LittleEndian.PutUint32(buf[:], t.TxIn[inidx].PreviousOutPoint.Index)
		wbuf.Write(buf[:4])

	case 1:		// transaction (BaseEncoding)
		err := t.BtcEncode(&wbuf, 0, wire.BaseEncoding)
		if err != nil {
			return err
		}

	case 2:		// all output
		for _, txo := range t.TxOut {
			if txo.TokenType == 0xFFFFFFFFFFFFFFFF {
				break
			}
			err := txo.WriteTxOut(&wbuf, 0, t.Version, wire.BaseEncoding)
			if err != nil {
				return err
			}
		}

	case 3:		// specific matching outputs
		for i, txo := range t.TxOut {
			if hash[i >> 3] & (1 << (i & 7)) != 0 {
				err := txo.WriteTxOut(&wbuf, 0, t.Version, wire.BaseEncoding)
				if err != nil {
					return err
				}
			}
		}

	default:
		return fmt.Errorf("Unknown text coding")
	}

	f := wbuf.Bytes()

	var p pointer
	if int64(dest >> 32) == int64(len(stack.data) - 1) {
		p = stack.alloc(len(f))
	} else {
		p = stack.malloc(len(f))
	}

	stack.saveInt32(&dest, int32(len(f)))
	stack.saveBytes(&p, f)

	return nil
}
