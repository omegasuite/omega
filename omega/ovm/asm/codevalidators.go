// Copyright 2020 The omega suite Authors. All rights reserved.
// This file is part of the omega library.
//

package main

import (
	"regexp"
)

var patOperand = regexp.MustCompile(`^n?(g?i+)?(([xa-f][0-9a-f]+)|([0-9]+))(\"[0-9]+)?(\'[0-9]+)?,`)
var addrOperand = regexp.MustCompile(`^n?g?i+(([xa-f][0-9a-f]+)|([0-9]+))(\"[0-9]+)?(\'[0-9]+)?,`)
var numOperand = regexp.MustCompile(`^n?(([xa-f][0-9a-f]+)|([0-9]+)),`)
var patNum = regexp.MustCompile(`[0-9a-f]+`)
var patHex = regexp.MustCompile(`[xa-f]`)
var dataType = regexp.MustCompile(`^\x75|\x67|\x42|\x57|\x44|\x51|\x48|\x68|\x41`)

var checkTop = map[uint8]int{0x2b:1, 0x2d:1, 0x2a:1, 0x2f:1, 0x25:1, 0x23:1,
	0x5b:1, 0x5d:1, 0x7c:1,	0x5e:1, 0x3e:1, 0x3c:1, 0x3d:1, 242:1, 243:1, 216:1, 0x3f:2}

func getNum(param []byte) (int64, int) {
	s := patOperand.Find(param)
	if s == nil || len(s) == 0 {
		return 0, -1
	}

	isaddress, _ := regexp.Match(`i`, s)
	offset, _ := regexp.Match(`['"]`, s)
	if offset && !isaddress {
		return 0, -0xfffffff
	}

	ns := patNum.Find(s)
	ln := len(s)
	hex := patHex.Match(s)
	num := int64(0)

	for _, c := range ns {
		switch c {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39: // 0 - 9
			if hex {
				num = num*16 + int64(c-0x30)
			} else {
				num = num*10 + int64(c-0x30)
			}

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // 0 - 9
			hex = true
			num = num*16 + int64(c-0x61) + 10
		}
	}

	if isaddress && num > 0xffffffff {
		return 0, -1
	}
	return num, ln
}

func getBig(param []byte) int {
	s := patOperand.Find(param)
	if s == nil || len(s) == 0 {
		return -1
	}

	isaddress, _ := regexp.Match(`i`, s)
	offset, _ := regexp.Match(`['"]`, s)
	if !offset && !isaddress {
		return -0xfffffff
	}

	return len(param)
}

func opEval8Validator(param []byte) int {
	if m,_ := regexp.Match(`^g?i`, param); !m {
		return -0xfffffff
	}

	ln := len(param)

	top := 0
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
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x78, 0x6e, 0x69, 0x67:	// 0 - 9, a-f, xngi
			if num, tl = getNum(param[j:]); tl < 0 {
				return -0xfffffff
			}
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl - 1
			top++

		case 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
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
	return opEval8Validator(param)
}

func opEval32Validator(param []byte) int {
	return opEval8Validator(param)
}

func opEval64Validator(param []byte) int {
	if m,_ := regexp.Match(`^g?i`, param); !m {
		return -0xfffffff
	}

	ln := len(param)

	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x78, 0x6e, 0x69, 0x67:	// 0 - 9, a-f, xngi
			if _, tl = getNum(param[j:]); tl < 0 {
				return -0xfffffff
			}
			j += tl  - 1
			top++

		case 0x40, 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
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
	if m, _ := regexp.Match(`^g?i`, param); !m {
		return -0xfffffff
	}

	ln := len(param)

	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top <= d + 1 {
				return -0xfffffff
			}
			top -= d
		}
		switch param[j] {
		case 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
			0x78, 0x6e, 0x69, 0x67:	// 0 - 9, a-f, xngi
			if _, tl = getNum(param[j:]); tl < 0 {
				return -0xfffffff
			}
			j += tl - 1
			top++

		case 0x75, 0x2b, 0x2d, 0x2a, 0x2f,
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

type formatDesc struct {
	desc *regexp.Regexp
	limit int64
}

func formatParser(f []formatDesc, param []byte) int {
	ln := len(param)

	num := int64(0)
	var sl int
	j := 0

	for _, fm := range f {
		s := fm.desc.Find(param[j:])
		if s == nil || len(s) == 0 {
			return -0xfffffff
		}
		if fm.limit != 0 {
			if ind,_ := regexp.Match(`i`, s); !ind {
				if num, sl = getNum(s); sl < 0 {
					return -0xfffffff
				}
				if num > fm.limit {
					return -0xfffffff
				}
			}
		}
		j += len(s)
	}
	if ln != j {
		return -0xfffffff
	}
	return 1
}

var formatConv = []formatDesc{
	{dataType, 0}, {addrOperand, 0xFFFFFFFF},
	{dataType, 0}, {addrOperand, 0xFFFFFFFF},
}

func opConvValidator(param []byte) int {
	if param[len(param) - 1] == 0x75 {
		return formatParser(formatConv, param[:len(param) - 1])
	}
	return formatParser(formatConv, param)
}

var formatHash = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
}

func opHashValidator(param []byte) int {
	return formatParser(formatHash, param)
}

func opHash160Validator(param []byte) int {
	return formatParser(formatHash, param)
}

var formatSigCheck = []formatDesc{
	{addrOperand, 0xffffffff}, {patOperand, 0},
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
	{patOperand, 0xFFFFFFFF},
}

func opSigCheckValidator(param []byte) int {
	return formatParser(formatSigCheck, param)
}

var formatIf = []formatDesc{
	{patOperand, 0xffffffff}, {patOperand, 0xffffffff},
}

func opIfValidator(param []byte) int {
	return formatParser(formatIf, param)
}

var formatCall = []formatDesc{
	{patOperand, 0}, {patOperand, 0xffffffff},
}

func opCallValidator(param []byte) int {
	n := 0
	for i := 0; i < len(param); i++ {
		if param[i] == 0x2c {
			n++
		}
	}
	if n > 2 {
		fmt := make([]formatDesc, n)
		copy(fmt, formatCall)
		for i := 2; i < n; i++ {
			fmt[i] = formatDesc{patOperand, 0}
		}
		return formatParser(fmt, param)
	}
	return formatParser(formatCall, param)
}

var formatLoad = []formatDesc{
	{addrOperand, 0xffffffff}, {patOperand, 0xff}, {patOperand, 0},
	{dataType, 0},
}

func opLoadValidator(param []byte) int {
	return formatParser(formatLoad, param)
}

var formatStore = []formatDesc{
	{patOperand, 32}, {patOperand, 0}, {dataType, 0}, {patOperand, 0},
}

func opStoreValidator(param []byte) int {
	return formatParser(formatStore, param)
}

var formatDel = []formatDesc{
	{patOperand, 32},{patOperand, 0},
}

func opDelValidator(param []byte) int {
	return formatParser(formatDel, param)
}

var formatReceived = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opReceivedValidator(param []byte) int {
	return formatParser(formatReceived, param)
}

var formatExec = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, // return space (address:len)
	{patOperand, 0},			  // contract address (20B)
	{addrOperand, 0xFFFFFFFF}, // value passed to (token)
	{addrOperand, 0xFFFFFFFF},	// data address
	{patOperand, 0xFFFFFFFF},	// data len
}

func opExecValidator(param []byte) int {
	return formatParser(formatExec, param)
}

var formatLibload = []formatDesc{
	{patOperand, 0}, {patOperand, 0},
}

func opLibLoadValidator(param []byte) int {
	return formatParser(formatLibload, param)
}

var formatMalloc = []formatDesc{
	{patOperand, 0}, {patOperand, 0xFFFFFFFF},
}

func opMallocValidator(param []byte) int {
	return formatParser(formatMalloc, param)
}

func opAllocValidator(param []byte) int {
	return formatParser(formatMalloc, param)
}

var formatCopy = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
}

func opCopyValidator(param []byte) int {
	return formatParser(formatCopy, param)
}

var formatImm = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0xFF},
}

func opCopyImmValidator(param []byte) int {
	n := 0
	for i := 0; i < len(param); i++ {
		if param[i] == 0x2c {
			n++
		}
	}
	if n > 2 {
		fmt := make([]formatDesc, n)
		copy(fmt, formatImm)
		for i := 2; i < n; i++ {
			fmt[i] = formatDesc{patOperand, 0xFF}
		}
		return formatParser(fmt, param)
	}
	return formatParser(formatImm, param)
}

var formatCopyCode = []formatDesc{
	{patOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
	{patOperand, 0xFFFFFFFF},
}

func opCodeCopyValidator(param []byte) int {
	return formatParser(formatCopyCode, param)
}

var formatSuicide = []formatDesc{
	{patOperand, 0},
}

func opSuicideValidator(param []byte) int {
	if len(param) != 0 {
		return formatParser(formatSuicide, param)
	}
	return 1
}

func opRevertValidator(param []byte) int {
	if len(param) != 0 {
		return -0xfffffff
	}
	return 1
}

func opStopValidator(param []byte) int {
	if len(param) != 0 {
		return -0xfffffff
	}
	return 1
}

func opReturnValidator(param []byte) int {
	if len(param) != 0 {
		return -0xfffffff
	}
	return 1
}

var formatTxIOCount = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
}

func opTxIOCountValidator(param []byte) int {
	return formatParser(formatTxIOCount, param)
}

var formatTxIO = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
}

func opGetTxInValidator(param []byte) int {
	return formatParser(formatTxIO, param)
}

func opGetTxOutValidator(param []byte) int {
	return formatParser(formatTxIO, param)
}

var formatSpend = []formatDesc{
	{patOperand, 0xFFFFFFFF},
}

func opSpendValidator(param []byte) int {
	return formatParser(formatSpend, param)
}

var formatAddRight = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opAddRightValidator(param []byte) int {
	return formatParser(formatAddRight, param)
}

func opAddTxOutValidator(param []byte) int {
	return formatParser(formatAddRight, param)
}

var formatGetDef = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0}, {patOperand, 0},
}

func opGetDefinitionValidator(param []byte) int {
	return formatParser(formatGetDef, param)
}

var formatGetCoin = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opGetCoinValidator(param []byte) int {
	return formatParser(formatGetCoin, param)
}

var formatGetUTXO = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0}, {patOperand, 0xffffffff},
}

func opGetUtxoValidator(param []byte) int {
	return formatParser(formatGetUTXO, param)
}

var formatAddSign = []formatDesc{
	{patOperand, 4}, {patOperand, 0},
}

func opAddSignTextValidator(param []byte) int {
	n :=  formatParser(formatAddSign[:1], param)
	if n > 0 {
		return n
	}
	return formatParser(formatAddSign, param)
}

var formatMint = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0}, {patOperand, 0}, {patOperand, 0},
}

func opMintValidator(param []byte) int {
	return formatParser(formatMint, param)
}

var formatMeta = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 32}, {patOperand, 0},
}

func opMetaValidator(param []byte) int {
	return formatParser(formatMint, param)
}
