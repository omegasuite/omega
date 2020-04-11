// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
//	"github.com/btcsuite/btcd/wire/common"
	"sync/atomic"
	"encoding/binary"
)

// Config are the configuration options for the Interpreter
type Config struct {
	// Debug enabled debugging Interpreter options
	Debug bool
	// Tracer is the op code logger
//	Tracer Tracer
	// NoRecursion disabled Interpreter call, callcode,
	// delegate call and create.
	NoRecursion bool
	// NoLoop forbids backward jump.
	NoLoop bool

	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool
	// JumpTable contains the EVM instruction table. This
	// may be left uninitialised and will be set to the default
	// table.
	JumpTable [256]operation
}

// Interpreter is used to run Ethereum based contracts and will utilise the
// passed evmironment to query external sources for state information.
// The Interpreter will run the byte code VM based on the passed
// configuration.
type Interpreter struct {
	evm      *OVM
	cfg      Config
//	intPool  *intPool

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewInterpreter returns a new instance of the Interpreter.
func NewInterpreter(evm *OVM, cfg Config) *Interpreter {
	// We use the STOP instruction whether to see
	// the jump table was initialised. If it was not
	// we'll set the default jump table.
	if !cfg.JumpTable[STOP].valid {
		cfg.JumpTable = omegaInstructionSet
	}

	return &Interpreter{
		evm:      evm,
		cfg:      cfg,
//		intPool:  newIntPool(),
	}
}

func (in *Interpreter) enforceRestrictions(op OpCode, operation operation, stack *Stack) error {
	if in.readOnly {
		// If the interpreter is operating in readonly mode, make sure no
		// state-modifying operation is performed.
		if operation.writes {
			return errWriteProtection
		}
	}

	return nil
}

func DisasmString(code []byte) string {
	var (
		op    OpCode        // current opcode
		pc   = uint64(0) // program counter
	)
	var s string

	for pc < uint64(len(code)) {
		op = OpCode(code[pc])
		s += opCodeToString[op] + " "

		pc++
	}
	return s
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// errExecutionReverted which means revert-and-keep-gas-left.
func (in *Interpreter) Run(contract *Contract, input []byte) (ret []byte, err error) {
	// Increment the call depth which is restricted to 1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op    OpCode        // current opcode
		stack = newstack()  // local stack
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   = int(0) // program counter
	)
	contract.Input = input

	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	for atomic.LoadInt32(&in.evm.abort) == 0 {
		in.evm.GasLimit--
		if in.evm.GasLimit < 0 {
			return nil, fmt.Errorf("Exceeded operation limit")
		}

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = contract.GetOp(pc)
		operation := in.cfg.JumpTable[op]
		if !operation.valid {
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}

		// If the operation is valid, enforce any write restrictions
		if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}

		if contract.pure && operation.writes {
			return nil, fmt.Errorf("State modification is not allowed")
		}

		// execute the operation
		err := operation.execute(&pc, in.evm, contract, stack)

		ln := int32(0)
		for i := 0; i < 4; i++ {
			ln |= int32(stack.data[0].space[i]) << (i * 8)
		}
		var res []byte

		if ln > 0 {
			res = make([]byte, ln)
			copy(res, stack.data[0].space[4:ln + 4])
		}

		// if the operation clears the return data (e.g. it has returning data)
		// set the last return to the result of the operation.
		if operation.returns {
			in.returnData = res
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return res, errExecutionReverted
		case operation.halts:
			return res, nil
		case !operation.jumps:
			pc++
		}
	}
	return nil, nil
}

func (in *Interpreter) SigVerify(code tbv, rep chan bool) {
	rep <- in.verifySig(code.txinidx, code.pkScript, code.sigScript)
}

func (in *Interpreter) VerifySig(txinidx int, pkScript, sigScript []byte) bool {
	return in.verifySig(txinidx, pkScript, sigScript)
}

func (in *Interpreter) verifySig(txinidx int, pkScript, sigScript []byte) bool {
	if pkScript[0] < 0x41 || pkScript[0] > 0x44 {	// check validation function range
		return false
	}

	contract := Contract {
		Code: ByteCodeParser(sigScript),
		CodeHash: chainhash.Hash{},
		self: nil,
//		jumpdests: make(destinations),
		Args:make([]byte, 4),
	}

	binary.LittleEndian.PutUint32(contract.Args[:], uint32(txinidx))

//	ret, err := in.Run(&contract, nil)
//	if err != nil {
//		return false
//	}

//	ret = append(pkScript[4:], ret[:]...)
	contract.CodeAddr = []byte{ pkScript[0], 0, 0, 0 }
//	contract.jumpdests = make(destinations)

	ret, err := run(in.evm, &contract, nil)	// ret)

	if err != nil || len(ret) != 1 || ret[0] != 1{
		return false
	} else {
		return true
	}
}