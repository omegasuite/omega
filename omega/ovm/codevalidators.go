/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"regexp"
)

var patOperand = regexp.MustCompile(`^@*[BWDQkKrR@ngi]*(([xa-f][0-9a-f]+)|([0-9]+))(\'[0-9]+)?(\"[0-9]+)?,`)
var addrOperand = regexp.MustCompile(`^@*[gi]*i(([xa-f][0-9a-f]+)|([0-9]+))(\'[0-9]+)?(\"[0-9]+)?,`)
var patNum = regexp.MustCompile(`[0-9a-f]+`)
var patHex = regexp.MustCompile(`[xa-f]`)
var dataType = regexp.MustCompile(`^[rRBWDQHhkK]|(L[0-9]+,)`)

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

		case 0x61, 0x62, 0x63, 0x64, 0x65, 0x66: // a - f
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
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f',
			'x', 'n', 'i', 'g':	// 0 - 9, a-f, xngi
			if num, tl = getNum(param[j:]); tl < 0 {
				return -0xfffffff
			}
			if num > 0xffffffff {
				return -0xfffffff
			}
			j += tl - 1
			top++

		case 'u', '+', '-', '*', '/', 'B', 'W', 'D', 'Q', 'H',
			'%', '#', '[', ']', '|', '&', '^', '~',
			'>', '<', '=', '(', ')', '!', '?', '"', '\'':

		case '@':
			if top != 0 {
				return -0xfffffff
			}

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
	ln := len(param)

	top := 0
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top < d + 1 {
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

		case '@', 0x75, 0x2b, 0x2d, 0x2a, 0x2f, 'P', 'B', 'W', 'D', 'Q', 'H',
			0x25, 0x23, 0x5b, 0x5d, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f, '"', '\'':

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
	var tl int

	for j := 0; j < ln; j++ {
		if d, ok := checkTop[param[j]]; ok {
			if top < d + 1 {
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

		case '@', 0x75, 0x2b, 0x2d, 0x2a, 0x2f, 'P', 'Z', 'B', 'W', 'D', 'Q', 'H',
			0x25, 0x23, 0x7c, 0x26, 0x5e, 0x7e,
			0x3e, 0x3c, 0x3d, 0x29, 0x28, 0x21, 0x3f, '"', '\'':

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

var formatHash160 = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF}, {patOperand, 1},
}

func opHash160Validator(param []byte) int {
	if r := formatParser(formatHash160, param); r < 0 {
		return formatParser(formatHash, param)
	} else {
		return r
	}
}

var formatSigCheck = []formatDesc{
	{addrOperand, 0xffffffff}, {patOperand, 0},
	{patOperand, 0}, {addrOperand, 0xFFFFFFFF},
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
	{addrOperand, 0xffffffff},
	{regexp.MustCompile(`^@*[zZBWDQkKrR@ngi]*(([xa-f][0-9a-f]+)|([0-9]+))(\'[0-9]+)?(\"[0-9]+)?,`), 0},
}

func opLoadValidator(param []byte) int {
	return formatParser(formatLoad, param)
}

var formatStore = []formatDesc{
	{regexp.MustCompile(`^@*[zZBWDQkKrR@ngi]*(([xa-f][0-9a-f]+)|([0-9]+))(\'[0-9]+)?(\"[0-9]+)?,`), 0},
	{regexp.MustCompile(`^[rRBWDQHhkK]|(L[0-9]+,)|(g?i*[0-9]+('[0-9]+)?("[0-9]+)?,)`), 0},
	{patOperand, 0},
}

func opStoreValidator(param []byte) int {
	return formatParser(formatStore, param)
}

var formatDel = []formatDesc{
	{patOperand, 0},
}

func opDelValidator(param []byte) int {
	if param[0] == 'D' || param[0] == 'Q' {
		return formatParser(formatDel, param[1:])
	}
	return formatParser(formatDel, param)
}

var formatReceived = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opReceivedValidator(param []byte) int {
	return formatParser(formatReceived, param)
}

var formatExec = []formatDesc{
	{patOperand, 0},			  // contract address (20B)
	{patOperand, 0},			  // purity
	{patOperand, 0xFFFFFFFF}, // return space (address:len)
	{patOperand, 0xFFFFFFFF}, // value passed to (token)
	{patOperand, 0xFFFFFFFF},	// Data len
//	{patOperand, 0xFFFFFFFF},	// parameter
}

func opExecValidator(param []byte) int {
	n := 0
	for i := 0; i < len(param); i++ {
		if param[i] == 0x2c {
			n++
		}
	}
	if n == 6 {
		p := make([]formatDesc, 6)
		copy(p[:], formatExec[:])
		p[5] = formatDesc{patOperand, 0xFFFFFFFF, }
		return formatParser(p, param)
	} else {
		return formatParser(formatExec, param)
	}
}

var formatLibload = []formatDesc{
	{patOperand, 0}, {patOperand, 0},
}

func opLibLoadValidator(param []byte) int {
	n := 0
	for i := 0; i < len(param); i++ {
		if param[i] == 0x2c {
			n++
		}
	}
	if n > 2 {
		fmt := make([]formatDesc, n)
		copy(fmt, formatLibload)
		for i := 2; i < n; i++ {
			fmt[i] = formatDesc{patOperand, 0}
		}
		return formatParser(fmt, param)
	}
	return formatParser(formatLibload, param)
}

var formatMalloc = []formatDesc{
	{patOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
}

func opMallocValidator(param []byte) int {
	return formatParser(formatMalloc, param)
}

func opAllocValidator(param []byte) int {
	return formatParser(formatMalloc, param)
}

var formatCopy = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0}, {patOperand, 0xFFFFFFFF},
}

func opCopyValidator(param []byte) int {
	return formatParser(formatCopy, param)
}

var formatImm = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {dataType, 0}, {regexp.MustCompile(`x?([0-9a-f]+),`), 0},
}

func opCopyImmValidator(param []byte) int {
	n := 0
	for i := 0; i < len(param); i++ {
		if param[i] == 0x2c {
			n++
		}
	}
	if n < 2 {
		return -0xfffffff
	}
/*
	if n > 2 {
		fmt := make([]formatDesc, 2 * n - 1)
		copy(fmt, formatImm)
		for i := 3; i < 2 * n - 1; i += 2 {
			fmt[i] = formatImm[1]
			fmt[i + 1] = formatImm[2]
		}
		return formatParser(formatImm, param)
	}
 */
	return formatParser(formatImm, param)
}

/*
var formatCopyCode = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
	{patOperand, 0xFFFFFFFF},
}

func opCodeCopyValidator(param []byte) int {
	return formatParser(formatCopyCode, param)
}
 */

var formatSuicide = []formatDesc{
	{patOperand, 0}, {patOperand, 0},
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

var formatTxFee = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 3},
}

func opTxFeeValidator(param []byte) int {
	return formatParser(formatTxFee, param)
}

var formatGetCoin = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opGetCoinValidator(param []byte) int {
	return formatParser(formatGetCoin, param)
}

var formatTxIOCount = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opTxIOCountValidator(param []byte) int {
	return formatParser(formatTxIOCount, param)
}

/*
var formatTxIO = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0xFFFFFFFF},
}

func opGetTxInValidator(param []byte) int {
	return formatParser(formatTxIO, param)
}

func opGetTxOutValidator(param []byte) int {
	return formatParser(formatTxIO, param)
}
 */

var formatSpend = []formatDesc{
	{patOperand, 0}, {patOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
}

func opSpendValidator(param []byte) int {
	if d := formatParser(formatSpend, param); d < 0 {
		return formatParser(formatSpend[:2], param)
	} else {
		return d
	}
}

var formatAddDef = []formatDesc{
	{patOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
}

func opAddDefValidator(param []byte) int {
	if param[len(param) - 1] == 'C' {
		return formatParser(formatAddDef, param[:len(param) - 1])
	}
	return formatParser(formatAddDef, param)
}

var formatAddTXO = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {addrOperand, 0xFFFFFFFF},
}

func opAddTxOutValidator(param []byte) int {
	r := formatParser(formatAddTXO, param)
	if r < 0 {
		r = formatParser(formatAddTXO[:1], param)
	}
	return r
}

var formatGetDef = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0}, {patOperand, 0},
}

func opGetDefinitionValidator(param []byte) int {
	return formatParser(formatGetDef, param)
}

/*
var formatGetCoin = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opGetCoinValidator(param []byte) int {
	return formatParser(formatGetCoin, param)
}

 */

var formatGetUTXO = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0},
	{patOperand, 0xffffffff}, {patOperand, 0xffffffff},
}

func opGetUtxoValidator(param []byte) int {
	r := formatParser(formatGetUTXO, param)
	if r < 0 {
		return formatParser(formatGetUTXO[:3], param)
	}
	return  r
}

var formatMint = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0},
	{patOperand, 0}, {patOperand, 0},
}

func opMintValidator(param []byte) int {
	d := formatParser(formatMint, param)
	if d < 0 {
		return formatParser(formatMint[:3], param)
	}
	return d
}


var formatMeta = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 32}, {patOperand, 0},
}

func opMetaValidator(param []byte) int {
	return formatParser(formatMeta, param)
}

var formatTime = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opTimeValidator(param []byte) int {
	return formatParser(formatTime, param)
}

var formatHeight = []formatDesc{
	{addrOperand, 0xFFFFFFFF},
}

func opHeightValidator(param []byte) int {
	return formatParser(formatHeight, param)
}

func opVersionValidator(param []byte) int {
	return formatParser(formatHeight, param)
}

var formatTokenContract = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {patOperand, 0},
}

func opTokenContractValidator(param []byte) int {
	return formatParser(formatTokenContract, param)
}

var formatLog = []formatDesc{
	{addrOperand, 0xFFFFFFFF}, {regexp.MustCompile(`[BCWDQHh]`), 0}, {patOperand, 0}, {patOperand, 0},
}

func opLogValidator(param []byte) int {
	return formatParser(formatLog, param)
}
