// Copyright 2020 The omega suite Authors. All rights reserved.
// This file is part of the omega library.
//

package main

import (
	"fmt"

	//	"fmt"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) < 1 {
		os.Exit(1)
	}
	fp,_ := os.Open(os.Args[1] + ".asm")
	if fp == nil {
		os.Exit(2)
	}
	var err error
	var s string
	var t [4096]byte
	var n int
	for err == nil {
		n, err = fp.Read(t[:])
		s += string(t[:n])
	}
	Code := ByteCodeParser([]byte(s))
	s, r := ByteCodeValidator(Code)
	if !r {
		fmt.Printf("Code Validate error for: %s", s)
		os.Exit(3)
	}

	if fp,_ = os.Create(os.Args[1] + ".ovm"); fp == nil {
		os.Exit(4)
	}

	for _,c := range Code {
		p := omegaInstructionSet[c.op].execute(c.param)
		fp.Write([]byte{byte(c.op)})
		fp.Write(p)
		fp.Write([]byte{0})
	}
	fp.Close()
}

type Address [20]byte

func (d Address) Big() * big.Int {
	z := big.NewInt(0)
	z.SetBytes(d[:])
	return z
}

type inst struct {
	op OpCode
	param []byte
}

func ByteCodeParser(code []byte) []inst {
	instructions := make([]inst, 0, len(code) / 32)
	var tmp inst
	empty := true
	for i := 0; i < len(code); i++ {
		switch {
		case empty:
			tmp.op = OpCode(code[i])
			empty = false
			tmp.param = make([]byte, 0, 32)

		case code[i] == 0x20 || code[i] == 0x9:		// skip space or tab

		case code[i] != 0x3b && code[i] != 10 && code[i] != 13:	// ";\n":
			tmp.param = append(tmp.param, code[i])

		default:	// ";\n":
			instructions = append(instructions, tmp)
			for ; i < len(code) && code[i] != 10; i++ {}
			empty = true
		}
	}
	if !empty {
		instructions = append(instructions, tmp)
	}

	return instructions
}

type codeValidator func ([]byte) int

var validators = map[OpCode]codeValidator {
	EVAL8:  opEval8Validator,
	EVAL16:  opEval16Validator,
	EVAL32:  opEval32Validator,
	EVAL64:  opEval64Validator,
	EVAL256:  opEval256Validator,
	CONV:   opConvValidator,
	HASH:   opHashValidator,
	HASH160:  opHash160Validator,
	SIGCHECK:   opSigCheckValidator,
	SIGNTEXT:  opAddSignTextValidator,
	IF:  opIfValidator,
	CALL:  opCallValidator,
	EXEC:  opExecValidator,
	LOAD:  opLoadValidator,
	STORE:   opStoreValidator,
	DEL: opDelValidator,
	LIBLOAD:   opLibLoadValidator,
	MALLOC:  opMallocValidator,
	ALLOC:  opAllocValidator,
	COPY: opCopyValidator,
	COPYIMM:  opCopyImmValidator,
	CODECOPY: opCodeCopyValidator,
	RECEIVED: opReceivedValidator,
	TXIOCOUNT:  opTxIOCountValidator,
	GETTXIN: opGetTxInValidator,
	GETTXOUT: opGetTxOutValidator,
	SPEND:  opSpendValidator,
	ADDRIGHTDEF:  opAddRightValidator,
	ADDTXOUT: opAddTxOutValidator,
	GETDEFINITION: opGetDefinitionValidator,
	GETCOIN:  opGetCoinValidator,
	GETUTXO:  opGetUtxoValidator,
	SELFDESTRUCT:  opSuicideValidator,
	REVERT: opRevertValidator,
	STOP: opStopValidator,
	RETURN: opReturnValidator,
	MINT: opMintValidator,
	META: opMetaValidator,
}

func ByteCodeValidator(code []inst) (string, bool) {
	for i, c := range code {
		if v, ok := validators[c.op]; ok {
			offset := v(c.param)
			if i+offset < 0 || i+offset > len(code) {
				return string([]byte{byte(c.op)}) + string(c.param), false
			}
		} else {
			return string([]byte{byte(c.op)}) + string(c.param), false
		}
	}

	return "", true
}