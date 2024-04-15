// Copyright 2020 The omega suite Authors. All rights reserved.
// This file is part of the omega library.
//

package main

import (
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/omega/ovm"
	//	"io"
	"math/big"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

const (
	BCOperand		= 0x80
	BCGlobal		= 0x40
	BCNegative		= 0x08
	BCHeadOffset	= 0x20
	BCTailOffset	= 0x10
)

func getNums(param []byte, dataType byte) ([]byte, int) {
	ln := len(param)
	hex := false
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	sign := int64(1)
	offset := 0

	indirects := 0

	head := byte(BCOperand)
	result := make([]byte, 1, 20)

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
			head |= BCNegative
			sign = -1

		case 0x69:	// i
			head++
			indirects++
			if indirects > 6 {
				return nil, j
			}

		case 0x67:	// g
			head |= BCGlobal

		case 0x22:	// " - head offset
			head |= BCHeadOffset
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			head |= BCTailOffset
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			if head & 0x7 != 0 {
				result[0] = head
				// is indirect, the next number is an 32-bit address
				var d [4]byte
				common.LittleEndian.PutUint32(d[:], uint32(nums[0]))
				result = append(result, d[:]...)
				if head & BCHeadOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[1]))
					result = append(result, d[:]...)
				}
				if head & BCTailOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[2]))
					result = append(result, d[:]...)
				}
				return result, j
			}
			head &^= BCNegative
			result[0] = head
			tmp = nums[0] * sign

			var d [8]byte

			switch dataType {
			case 0x42:	// byte
				result = append(result, byte(tmp))

			case 0x57:	// word
				common.LittleEndian.PutUint16(d[:], uint16(tmp))
				result = append(result, d[:2]...)

			case 0x44:	// dword
				common.LittleEndian.PutUint32(d[:], uint32(tmp))
				result = append(result, d[:4]...)

			case 0x51:	// qword
				common.LittleEndian.PutUint64(d[:], uint64(tmp))
				result = append(result, d[:]...)
			}
			return result, j
		}
	}
	return nil, ln
}

func getBigs(param []byte) ([]byte, int) {
	ln := len(param)
	hex := false
	num := *bigZero
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	sign := *bigOne
	offset := 0

	indirects := 0

	head := byte(BCOperand)
	result := make([]byte, 1, 20)

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
			head |= BCNegative
			sign = *bigNegOne

		case 0x69:	// i
			head++
			indirects++
			if indirects > 6 {
				return nil, j
			}

		case 0x67:	// g
			head |= BCGlobal

		case 0x22:	// " - head offset
			head |= BCHeadOffset
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			head |= BCTailOffset
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			if head & 0x7 != 0 {
				result[0] = head
				// is indirect, the next number is an 32-bit address
				var d [4]byte
				common.LittleEndian.PutUint32(d[:], uint32(nums[0]))
				result = append(result, d[:]...)
				if head & BCHeadOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[1]))
					result = append(result, d[:]...)
				}
				if head & BCTailOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[2]))
					result = append(result, d[:]...)
				}
				return result, j
			}
			head &^= BCNegative
			result[0] = head
			num = *num.Mul(&num, &sign)
			h := ovm.BigToHash(&num)
			result = append(result, h[:]...)
			return result, j
		}
	}
	return nil, ln
}

func getHash(param []byte) ([]byte, int) {
	ln := len(param)
	hex := false
	var num [64]byte
	d := 0
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	offset := 0
	indirects := 0

	head := byte(BCOperand)
	result := make([]byte, 1, 40)

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
					return nil, j - 1
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
			head++
			indirects++
			if indirects > 6 {
				return nil, j
			}

		case 0x67:	// g
			head |= BCGlobal

		case 0x22:	// " - head offset
			head |= BCHeadOffset
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			head |= BCTailOffset
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			if head & 0x7 != 0 {
				result[0] = head
				// is indirect, the next number is an 32-bit address
				var d [4]byte
				common.LittleEndian.PutUint32(d[:], uint32(nums[0]))
				result = append(result, d[:]...)
				if head & BCHeadOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[1]))
					result = append(result, d[:]...)
				}
				if head & BCTailOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[2]))
					result = append(result, d[:]...)
				}
				return result, j
			}
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
			result = append(result, h[:]...)
			return result, j
		}
	}
	return nil, ln
}

func getAddress(param []byte) ([]byte, int) {
	ln := len(param)
	hex := false
	var num [40]byte
	d := 0
	nums := [3]int64{0, 0, 0}
	tmp := int64(0)
	offset := 0
	indirects := 0

	head := byte(BCOperand)
	result := make([]byte, 1, 40)

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
					return nil, j - 1
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
			head++
			indirects++
			if indirects > 6 {
				return nil, j
			}

		case 0x67:	// g
			head |= BCGlobal

		case 0x22:	// " - head offset
			head |= BCHeadOffset
			offset = 1
			tmp = 0
			hex = false

		case 0x27:	// " - tail offset
			head |= BCTailOffset
			offset = 2
			tmp = 0
			hex = false

		case 0x2c:	// ,
			if head & 0x7 != 0 {
				result[0] = head
				// is indirect, the next number is an 32-bit address
				var d [4]byte
				common.LittleEndian.PutUint32(d[:], uint32(nums[0]))
				result = append(result, d[:]...)
				if head & BCHeadOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[1]))
					result = append(result, d[:]...)
				}
				if head & BCTailOffset != 0 {
					common.LittleEndian.PutUint32(d[:], uint32(nums[2]))
					result = append(result, d[:]...)
				}
				return result, j
			}
			var h Address
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
			result = append(result, h[:]...)
			return result, j
		}
	}
	return nil, ln
}

func opEval(param []byte, opType byte) []byte {
	ln := len(param)
	dataType := byte(0xFF)
	result := make([]byte, 0, 20)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
			t, tl := getNums(param[j:], dataType)
			result = append(result, t...)
			dataType = opType
			j += tl

		default:
			result = append(result, param[j])
		}
	}

	return result
}

func opEval8(param []byte) []byte {
	return opEval(param, 0x42)
}

func opEval16(param []byte) []byte {
	return opEval(param, 0x57)
}

func opEval32(param []byte) []byte {
	return opEval(param, 0x44)
}

func opEval64(param []byte) []byte {
	return opEval(param, 0x51)
}

var (
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
	bigNegOne = big.NewInt(-1)
)

func opEval256(param []byte) []byte {
	ln := len(param)
	dataType := byte(0xFF)
	result := make([]byte, 0, 20)

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
			0x63, 0x64, 0x65, 0x66, 0x78, 0x6e,
			0x69, 0x67, 0x2c:	// 0 - 9
			if dataType == 0xFF {
				p, tl := getNums(param[j:], 0xFF)
				result = append(result, p...)
				j += tl
			} else {
				h, tl := getBigs(param[j:])
				result = append(result, h...)
				j += tl
			}
			dataType = 0x48

		case 0x2b, 0x2d, 0x2a, 0x2f, 0x25, 0x23,
			0x7c, 0x26, 0x5e, 0x7e, 0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:	// ?
			result = append(result, param[j])
		}
	}
	return result
}

func opGeneric(param []byte, dataType []byte) []byte {
	ln := len(param)
	result := make([]byte, 0, 20)

	top := 0

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78, 0x69, 0x67:	// 0 - 9
			if dataType[top] == 0x41 {
				h, tl := getAddress(param[j:])
				result = append(result, h...)
				j += tl
			} else if dataType[top] == 0x48 {
				h, tl := getBigs(param[j:])
				result = append(result, h...)
				j += tl
			} else if dataType[top] == 0x68 {
				h, tl := getHash(param[j:])
				result = append(result, h...)
				j += tl
			} else {
				t, tl := getNums(param[j:], dataType[top])
				j += tl
				result = append(result, t...)
			}
			if top < len(dataType) - 1 {
				top++
			}

		default:
			result = append(result, param[j])
		}
	}
	return result
}

func opConv(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0xFF, 0x42, 0xFF})
}

func opHash(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0xFF, 0x44})
}

func opHash160(param []byte) []byte {
	return opHash(param)
}

func opSigCheck(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x68, 0xFF, 0xFF, 0x44})
}

func opIf(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0x44})
}

func opCall(param []byte) []byte {
	return opGeneric(param, []byte{0x41, 0x44, 0x42})
}

func opLoad(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x42, 0x68})
}

func opStore(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0x68, 0x68})
}

func opDel(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0x68})
}

func opReceived(param []byte) []byte {
	return opGeneric(param, []byte{0xFF})
}

func opExec(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x41, 0xFF, 0xFF, 0x44})
}

func opLibLoad(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0x48})
}

func opMalloc(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x44})
}

func opAlloc(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x44})
}

func opCopy(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0xFF, 0x44})
}

func opCopyImm(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x42})
}

func opCodeCopy(param []byte) []byte {
	return opGeneric(param, []byte{0x44, 0xFF, 0x44})
}

func opSuicide(param []byte) []byte {
	if len(param) != 0 {
		return opGeneric(param, []byte{0x41})
	}
	return []byte{}
}

func opRevert(param []byte) []byte {
	return []byte{}
}

func opStop(param []byte) []byte {
	return []byte{}
}

func opReturn(param []byte) []byte {
	return []byte{}
}

func opTxIOCount(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0xFF, 0xFF})
}

func opGetTxIn(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x44})
}

func opGetTxOut(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x44})
}

func opSpend(param []byte) []byte {
	return opGeneric(param, []byte{0x44})
}

func opAddRight(param []byte) []byte {
	return opGeneric(param, []byte{0xFF})
}

func opAddTxOut(param []byte) []byte {
	return opGeneric(param, []byte{0xFF})
}

func opGetDefinition(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x68, 0x42})
}

func opGetCoin(param []byte) []byte {
	return opGeneric(param, []byte{0xFF})
}

func opGetUtxo(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x68, 0x44})
}

func opAddSignText(param []byte) []byte {
	return opGeneric(param, []byte{0x42, 0x68})
}

func opMint(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x42, 0x48, 0x68})
}

func opMeta(param []byte) []byte {
	return opGeneric(param, []byte{0xFF, 0x42, 0x68})
}