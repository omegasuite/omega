// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package main

type executionFunc func([]byte) []byte

type operation struct {
	// op is the operation function
	execute executionFunc

	halts   bool // indicates whether the operation should halt further execution
	jumps   bool // indicates whether the program counter should not increment
	writes  bool // determines whether this a state modifying operation
	valid   bool // indication whether the retrieved operation is valid and known
	reverts bool // determines whether the operation reverts state (implicitly halts)
	returns bool // determines whether the operations sets the return data content
}

var (
	omegaInstructionSet = NewOmegaInstructionSet()
)

// NewOmegaInstructionSet returns the frontier, homestead
// byzantium, contantinople and Omega instructions.
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
		SIGNTEXT: operation{
			execute:       opAddSignText,
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
		CODECOPY: operation{
			execute:       opCodeCopy,
			valid:         true,
		},
		RECEIVED: operation{
			execute:       opReceived,
			valid:         true,
		},
		TXIOCOUNT: operation{
			execute:       opTxIOCount,
			valid:         true,
		},
		GETTXIN: operation{
			execute:       opGetTxIn,
			valid:         true,
		},
		GETTXOUT: operation{
			execute:       opGetTxOut,
			valid:         true,
		},
		SPEND: operation{
			execute:       opSpend,
			valid:         true,
			writes:        true,
		},
		ADDRIGHTDEF:  operation{
			execute:       opAddRight,
			valid:         true,
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
	}
}
