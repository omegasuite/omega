/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"bytes"
	"encoding/binary"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/omega"
	"github.com/omegasuite/famofchains/omega/token"
	"math/big"
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

	SigHashMask = 0x1f
)

var IssuedTokenTypes = []byte("issuedTokens")

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

func opStop(pc *int, evm *OVM, contract *Contract, stack *Stack) omega.Err {
	return nil
}

var (
	errWriteProtection   = omega.ScriptError(omega.ErrInternal, "evm: write protection")
	errExecutionReverted = omega.ScriptError(omega.ErrInternal, "evm: execution reverted")
)

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
