/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import "github.com/omegasuite/omega"

type executionFunc func(pc *int, env *OVM, contract *Contract, stack *Stack) omega.Err

type operation struct {
	// op is the operation function
	execute executionFunc

	halts   bool // indicates whether the operation should halt further execution
	jumps   bool // indicates whether the program counter should not increment
	writes  bool // determines whether this a state modifying operation
	valid   bool // indication whether the retrieved operation is valid and known
	reverts bool // determines whether the operation reverts state (implicitly halts)
	returns bool // determines whether the operations sets the return Data content
}

var (
	omegaInstructionSet = NewOmegaInstructionSet()
)

// NewOmegaInstructionSet returns the Omega instructions.
func NewOmegaInstructionSet() [256]operation {
	// instructions that can be executed during the byzantium phase.
	return [256]operation{
		EVAL8: operation{
			execute:       opEval8,
			valid:         true,
		},
		EVAL16: operation{
			execute:       opEval16,
			valid:         true,
		},
		EVAL32: operation{
			execute:       opEval32,
			valid:         true,
		},
		EVAL64: operation{
			execute:       opEval64,
			valid:         true,
		},
		EVAL256: operation{
			execute:       opEval256,
			valid:         true,
		},
		CONV: operation{
			execute:       opConv,
			valid:         true,
		},
		HASH: operation{
			execute:       opHash,
			valid:         true,
		},
		HASH160: operation{
			execute:       opHash160,
			valid:         true,
		},
		SIGCHECK: operation{
			execute:       opSigCheck,
			valid:         true,
		},
		IF: operation{
			execute:       opIf,
			jumps:		   true,
			valid:         true,
		},
		CALL: {
			execute:       opCall,
			jumps:		   true,
			valid:         true,
		},
		EXEC: {
			execute:       opExec,
			valid:         true,
		},
		LOAD: operation{
			execute:       opLoad,
			valid:         true,
		},
		STORE: operation{
			execute:       opStore,
			valid:         true,
			writes:		   true,
		},
		DEL: operation{
			execute:       opDel,
			valid:         true,
			writes:		   true,
		},
		LIBLOAD: operation{
			execute:       opLibLoad,
			jumps:		   true,
			valid:         true,
		},
		MALLOC: operation{
			execute:       opMalloc,
			valid:         true,
		},
		ALLOC: operation{
			execute:       opAlloc,
			valid:         true,
		},
		COPY: operation{
			execute:       opCopy,
			valid:         true,
		},
		COPYIMM: operation{
			execute:       opCopyImm,
			valid:         true,
		},
/*		
		CODECOPY: operation{
			execute:       opCodeCopy,
			valid:         true,
		},
 */
		RECEIVED: operation{
			execute:       opReceived,
			valid:         true,
		},
		TXFEE: operation{
			execute:       opTxFee,
			valid:         true,
		},
		TXIOCOUNT: operation{
			execute:       opGetIOCount,
			valid:         true,
		},
/*
		GETTXIN: operation{
			execute:       opGetTxIn,
			valid:         true,
		},
		GETTXOUT: operation{
			execute:       opGetTxOut,
			valid:         true,
		},
 */
		SPEND: operation{
			execute:       opSpend,
			valid:         true,
			writes:        true,
		},
		ADDDEF:  operation{
			execute: opAddDef,
			valid:   true,
		},
		ADDTXOUT: operation{
			execute:       opAddTxOut,
			valid:         true,
		},
		GETDEFINITION: operation{
			execute:       opGetDefinition,
			valid:         true,
		},
		GETCOIN: operation{
			execute:       opGetCoin,
			valid:         true,
		},
		NOP: operation{
			execute:       opNul,
			valid:         true,
		},
		GETUTXO: operation{
			execute:       opGetUtxo,
			valid:         true,
		},
		SELFDESTRUCT: {
			execute:       opSuicide,
			halts:         true,
			valid:         true,
			writes:        true,
		},
		REVERT: operation{
			execute:       opRevert,
			halts:         true,
			reverts:	   true,
			returns:	   true,
			valid:         true,
		},
		STOP: {
			execute:       opStop,
			halts:         true,
			returns:	   true,
			valid:         true,
		},
		RETURN: {
			execute:       opReturn,
			valid:         true,
		},
		MINT: {
			execute:       opMint,
			valid:         true,
		},
		META: {
			execute:       opMeta,
			valid:         true,
		},
		TIME: {
			execute:       opTime,
			valid:         true,
		},
		HEIGHT: {
			execute:       opHeight,
			valid:         true,
		},
		VERSION: {
			execute:       opVersion,
			valid:         true,
		},
		TOKENCONTRACT: {
			execute:       opTokenContract,
			valid:         true,
		},
		LOG: {
			execute:       opLog,
			valid:         true,
		},
/*
		SIGNTEXT: operation{
			execute:       opSignText,
			valid:         true,
		},
 */
	}
}

// NewSignVMInstSet returns the signature VM instructions.
func NewSignVMInstSet() [256]operation {
	// instructions that can be executed during the byzantium phase.
	return [256]operation{
		SIGNTEXT: operation{
			execute:       opAddSignText,
			valid:         true,
		},
		PUSH: operation{
			execute:       opPush,
			valid:         true,
		},
		STOP: {
			execute:       opStop,
			halts:         true,
			returns:	   true,
			valid:         true,
		},
	}
}
