// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func opEval8Validator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	ispointer := true
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x2c:	// ,
			if !ispointer && indirect == 0 && num > 0xff {
				return -0xfffffff
			}
			if ispointer && indirect == 0 {
				return -0xfffffff
			}
			top++
			num = 0
			ispointer = false
			indirect = 0

		case 0x69:	// i
			indirect++

		case 0x6e, 0x67, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
			0x25, 0x23, 0x5b, 0x5d, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opEval16Validator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	ispointer := true
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x2c:	// ,
			if !ispointer && indirect == 0 && num > 0xffff {
				return -0xfffffff
			}
			if ispointer && indirect == 0 {
				return -0xfffffff
			}
			top++
			num = 0
			ispointer = false
			indirect = 0

		case 0x6e, 0x67, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
			0x25, 0x23, 0x5b, 0x5d, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opEval32Validator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	ispointer := true
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x2c:	// ,
			if !ispointer && indirect == 0 && num > 0xffffffff {
				return -0xfffffff
			}
			if ispointer && indirect == 0 {
				return -0xfffffff
			}
			top++
			num = 0
			ispointer = false
			indirect = 0

		case 0x6e, 0x67, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
			0x25, 0x23, 0x5b, 0x5d, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opEval64Validator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	ispointer := true

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl := getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x40:	// @
			ispointer = false

		case 0x2c:	// ,
			if ispointer && indirect == 0 {
				return -0xfffffff
			}
			top++
			ispointer = false
			indirect = 0

		case 0x6e, 0x67, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
			0x25, 0x23, 0x5b, 0x5d, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opEval256Validator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	ispointer := true

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl := getBig(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x2c:	// ,
			if ispointer && indirect == 0 {
				return -0xfffffff
			}
			top++
			ispointer = false
			indirect = 0

		case 0x6e, 0x67, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
			0x25, 0x23, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f:

		default:
			return -0xfffffff
		}
	}

	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opConvValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x75, 0x67, 0x42, 0x57, 0x44, 0x51, 0x48:	// b

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}

			indirect = 0
			num = 0
			top++

		default:
			return -0xfffffff
		}
	}

	if top != 2 {
		return -0xfffffff
	}
	return 1
}

func opHashValidator(param []byte) int {
	ln := len(param)

	top := 0
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69, 0x67:	// i

		case 0x2c:	// ,
			top++
			num = 0

		default:
			return -0xfffffff
		}
	}

	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opHash160Validator(param []byte) int {
	ln := len(param)

	top := 0
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69, 0x67:	// i

		case 0x2c:	// ,
			top++
			num = 0
		}
	}

	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opSigCheckValidator(param []byte) int {
	var tl int

	ln := len(param)

	top := 0
	num := int64(0)

	paramTypes := []byte{0x51, 0x48, 0x51, 0x51, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				_, tl = getBig(param[j:])
			} else {
				num, tl = getNum(param[j:])
				if num > 0xffffffff {
					return -0xfffffff
				}
			}
			j += tl

		case 0x69, 0x67:	// i

		case 0x2c:	// ,
			top++
			num = 0

		default:
			return -0xfffffff
		}
	}
	if top != 4 {
		return -0xfffffff
	}

	return 1
}

func opIfValidator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	num := int64(0)
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			num, tl = getNum(param[j:])
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			top++
			indirect = 0
			num = 0

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}

	return 1
}

func opCallValidator(param []byte) int {
	ln := len(param)

	top := 0
	indirect := 0
	var tl int

	paramTypes := []byte{0x48, 0x44, 0x51, 0x44 }

	for j := 0; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				_, tl = getBig(param[j:])
			} else {
				_, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,

		default:
			return -0xfffffff
		}
		top++
	}

	if top >= 2 {
		return 1
	}
	return -0xfffffff
}

func opLoadValidator(param []byte) int {
	ln := len(param)

	if ln < chainhash.HashSize {
		return -0xfffffff
	}

	indirect := 0
	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQHA - byte, word, dword, qword, big int

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			return 1

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opStoreValidator(param []byte) int {
	ln := len(param)

	if ln < chainhash.HashSize {
		return -0xfffffff
	}

	indirect := 0
	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x42, 0x57, 0x44, 0x51, 0x48:	// b
			// BWDQHA - byte, word, dword, qword, big int

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}

			return 1

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opReceivedValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			return 1
		}
	}
	return -0xfffffff
}

func opExecValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0

	var tl int

	paramTypes := []byte{0x51, 0x44, 0x48, 0x51, 0x51, 0x44}

	for j := chainhash.HashSize; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				_, tl = getBig(param[j:])
			} else {
				_, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			top++

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opLibLoadValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0

	var tl int

	paramTypes := []byte{0x42, 0x48}

	for j := chainhash.HashSize; j < ln; j++ {
		dataType := paramTypes[top]
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			if dataType == 0x48 {
				_, tl = getBig(param[j:])
			} else {
				_, tl = getNum(param[j:])
			}
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			top++
			return 1

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opMallocValidator(param []byte) int {
	return opMAallocValidator(param)
}

func opMAallocValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 2 {
		return -0xfffffff
	}
	return 1
}

func opAllocValidator(param []byte) int {
	return opMAallocValidator(param)
}

func opCopyValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0

	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opCopyImmValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0

	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			top++
		}
	}
	if top != 2 {
		return -0xfffffff
	}
	return 1
}

func opCodeCopyValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0

	var tl int

	for j := chainhash.HashSize; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			if indirect == 0 {
				return -0xfffffff
			}
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opSuicideValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78:	// 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69:	// i
			indirect++

		case 0x67:	// g

		case 0x2c:	// ,
			top++

		default:
			return -0xfffffff
		}
	}

	if top != 1 {
		return -0xfffffff
	}
	return 1
}

func opRevertValidator(param []byte) int {
	return 1
}

func opStopValidator(param []byte) int {
	return 1
}

func opReturnValidator(param []byte) int {
	return 1
}

func opTxIOCountValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opGetTxInValidator(param []byte) int {
	return opGetTxIOValidator(param)
}

func opGetTxIOValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 1 {
				_,tl = getBig(param[j:])
				j += tl
			} else {
				_, tl = getNum(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			indirect = 0
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opGetTxOutValidator(param []byte) int {
	return opGetTxIOValidator(param)
}

func opSpendValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			return 1

		default:
			return -0xfffffff
		}
	}

	return -0xfffffff
}

func opAddRightValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			return 1

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opAddTxOutValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			_, tl = getNum(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			return 1

		default:
			return -0xfffffff
		}
	}
	return -0xfffffff
}

func opGetDefinitionValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			_, tl = getBig(param[j:])
			j += tl

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			indirect = 0
			top++

		default:
			return -0xfffffff
		}
	}

	if top != 1 {
		return -0xfffffff
	}

	return 1
}

func opGetCoinValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top < 2 {
				_, tl = getNum(param[j:])
				j += tl
			} else {
				_, tl = getBig(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			indirect = 0
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opGetUtxoValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 0 || top == 2 {
				_, tl = getNum(param[j:])
				j += tl
			} else {
				_, tl = getBig(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			indirect = 0
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}

func opAddSignTextValidator(param []byte) int {
	ln := len(param)

	indirect := 0
	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x78: // 0 - 9
			if top == 2 {
				_, tl = getBig(param[j:])
				j += tl
			} else {
				_, tl = getNum(param[j:])
				j += tl
			}

		case 0x69: // i
			indirect++

		case 0x67: // g

		case 0x2c: // ,
			indirect = 0
			top++

		default:
			return -0xfffffff
		}
	}
	if top != 3 {
		return -0xfffffff
	}
	return 1
}
