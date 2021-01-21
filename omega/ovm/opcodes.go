// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"fmt"
)

// OpCode is an OVM opcode
type OpCode byte

const (
	// 0x0 range - arithmetic ops
	EVAL8	 OpCode = 0x41 + iota  // byte Data evaluation "A"
	EVAL16	// word Data evaluation "B"
	EVAL32	// dword Data evaluation
	EVAL64  // 64-bit Data evaluation
	EVAL256 // 256-bit Data evaluation (as big.Int) "E"

	CONV	// Data conversion "F"
	HASH	// Hash
	HASH160	// Hash160
	SIGCHECK	// verify sig
	SIGNTEXT	// 0x4a K. prepare tx text for signature

	IF		// "K"
	CALL	// call function
	EXEC	// execute other contract
	LOAD	// load state Data
	STORE	// store state Data
	DEL		// 0x50 delete state Data
	LIBLOAD	// load lib

	MALLOC	// global mem alloc "R"
	ALLOC	// mem alloc in func

	COPY	// Data copy
	COPYIMM	// immediate Data copy
//	CODECOPY	// copy code
	PUSH	// 0x56 V

	SELFDESTRUCT
	REVERT
	RETURN
)

const (
	RECEIVED OpCode = 0x61 + iota	// "a". outpoint of the current call
	TXFEE		// TXIOCOUNT. min tx fee for current tx
	GETCOIN		// GETTXIN. coin received for the current call
	NOP
	SPEND		// add tx in
	ADDRIGHTDEF	// add def
	ADDTXOUT	// add tx out
	GETDEFINITION	// get def
	GETUTXO			// get any utxo
	MINT		// mint a coin
	META		// get contract meta Data
	TIME		// timestamp in block
	HEIGHT		// block height
	
	STOP	 OpCode = 0x7A	//  "z"
)

// Since the opcodes aren't all in order we can't use a regular slice
var opCodeToString = map[OpCode]string{
	// 0x0 range - arithmetic ops
	STOP:       "STOP",
	EVAL8:        "EVAL8",
	EVAL16:        "EVAL16",
	EVAL32:        "EVAL32",
	EVAL64:        "EVAL64",
	EVAL256:       "EVAL256",
	CONV:        "CONV",
	HASH:       "HASH",
	HASH160:       "HASH160",
	SIGCHECK:       "SIGCHECK",
	SIGNTEXT:       "SIGNTEXT",
	IF:        "IF",
	CALL:        "CALL",
	EXEC:       "EXEC",
	LOAD:         "LOAD",
	STORE:         "STORE",
	DEL:         "DEL",
	LIBLOAD:       "LIBLOAD",
	MALLOC:       "MALLOC",
	ALLOC:       "ALLOC",
	COPY:       "COPY",
	COPYIMM:       "COPYIMM",
	PUSH:       "PUSH",
//	CODECOPY:       "CODECOPY",
	RECEIVED:        "RECEIVED",
	TXFEE: "TXFEE",
//	TXIOCOUNT:        "TXIOCOUNT",
//	GETTXIN:        "GETTXIN",
//	GETTXOUT:        "GETTXOUT",
	SPEND:         "SPEND",
	ADDRIGHTDEF:     "ADDRIGHTDEF",
	ADDTXOUT: "ADDTXOUT",
	GETDEFINITION:    "GETDEFINITION",
	GETCOIN:     "GETCOIN",
	NOP: "NOP",
	GETUTXO:    "GETUTXO",
	SELFDESTRUCT:   "SELFDESTRUCT",
	REVERT:    "REVERT",
	RETURN:    "RETURN",
	MINT:    "MINT",
	TIME:    "TIME",
	HEIGHT:    "HEIGHT",
	META:    "META",
}

func (o OpCode) String() string {
	str := opCodeToString[o]
	if len(str) == 0 {
		return fmt.Sprintf("Missing opcode 0x%x", int(o))
	}

	return str
}

var stringToOp = map[string]OpCode{
	"STOP":           STOP,
	"EVAL8":            EVAL8,
	"EVAL16":            EVAL16,
	"EVAL32":            EVAL32,
	"EVAL64":            EVAL64,
	"EVAL256":           EVAL256,
	"CONV":            CONV,
	"HASH":           HASH,
	"HASH160":           HASH160,
	"SIGCHECK":           SIGCHECK,
	"SIGNTEXT":           SIGNTEXT,
	"IF":            IF,
	"CALL":           CALL,
	"LOAD":           LOAD,
	"STORE":           STORE,
	"DEL":           DEL,
	"LIBLOAD":           LIBLOAD,
	"MALLOC":           MALLOC,
	"ALLOC":           ALLOC,
	"COPY":           COPY,
	"COPYIMM":           COPYIMM,
	"PUSH":           PUSH,
//	"CODECOPY":           CODECOPY,
	"RECEIVED": RECEIVED,
	"TXFEE": TXFEE,
//	"TXIOCOUNT": TXIOCOUNT,
//	"GETTXIN": GETTXIN,
//	"GETTXOUT": GETTXOUT,
	"SPEND": SPEND,
	"ADDRIGHTDEF": ADDRIGHTDEF,
	"ADDTXOUT": ADDTXOUT,
	"GETDEFINITION": GETDEFINITION,
	"GETCOIN": GETCOIN,
	"NOP": NOP,
	"GETUTXO": GETUTXO,
	"SELFDESTRUCT":   SELFDESTRUCT,
	"REVERT":         REVERT,
	"RETURN":         RETURN,
	"MINT": MINT,
	"META": META,
	"TIME": TIME,
	"HEIGHT": HEIGHT,
}

func StringToOp(str string) OpCode {
	return stringToOp[str]
}
