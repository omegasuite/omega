// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"fmt"
	"encoding/binary"
	//	"github.com/omegasuite/btcd/chaincfg/chainhash"
	//	"github.com/omegasuite/btcd/wire/common"
	"sync/atomic"
)

// Interpreter is used to run Ethereum based contracts and will utilise the
// passed evmironment to query external sources for state information.
// The Interpreter will run the byte code VM based on the passed
// configuration.
type Interpreter struct {
	evm      *OVM

	JumpTable [256]operation

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return Data for subsequent reuse
}

// NewInterpreter returns a new instance of the Interpreter.
func NewInterpreter(evm *OVM) *Interpreter {
	return &Interpreter{
		evm:      evm,
		JumpTable: omegaInstructionSet,
	}
}

func NewSigInterpreter(evm *OVM) *Interpreter {
	return &Interpreter{
		evm:      evm,
		JumpTable: NewSignVMInstSet(),
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

func (in *Interpreter) Step(code *inst) ([]byte, error) {
	stack := Newstack()
	pc   := int(0) // program counter

	contract := & Contract{
		Code: []inst{*code},
	}

	op := code.op
	operation := in.JumpTable[op]
	if !operation.valid {
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}
	if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}
	if operation.writes {
			return nil, fmt.Errorf("State modification is not allowed")
		}

	err := operation.execute(&pc, nil, contract, stack)
	
	return stack.data[0].space, err
}

// Run loops and evaluates the contract's code with the given input Data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// errExecutionReverted which means revert-and-keep-gas-left.
func (in *Interpreter) Run(contract *Contract, input []byte) (ret []byte, err error) {
	// Increment the call depth which is restricted to 1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Reset the previous call's return Data. It's unimportant to preserve the old buffer
	// as every returning call will return new Data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op    OpCode        // current opcode
		stack = Newstack()  // local stack
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   = int(0) // program counter
	)
	contract.libs[Address([20]byte{})] = lib {
		end: int32(len(contract.Code)),
		pure: contract.pure,
	}
	contract.Input = input
	stack.data[0].pure = contract.pure

	if len(input) > 0 {
		stack.malloc(8 + len(input))
		binary.LittleEndian.PutUint32(stack.data[0].space, uint32(len(input)))
		copy(stack.data[0].space[8:], input)
	}

	cost := int64(0)
	allowance := in.evm.Paidfees * 100000

	if in.evm.chainConfig.ContractExecFee == 0 {
		in.evm.CheckExecCost = false
	}
	
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	for atomic.LoadInt32(&in.evm.abort) == 0 {
		in.evm.GasLimit--
		if in.evm.GasLimit < 0 {
			return nil, fmt.Errorf("Exceeded operation limit")
		}
		if in.evm.CheckExecCost {
			cost += in.evm.chainConfig.ContractExecFee
			if cost > allowance {
				return nil, fmt.Errorf("Exceeded gas limit")
			}
		}

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = contract.GetOp(pc)
		operation := in.JumpTable[op]
		if !operation.valid {
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}

		// If the operation is valid, enforce any write restrictions
		if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}

		if contract.pure & NOWRITE != 0 && operation.writes {
			return nil, fmt.Errorf("State modification is not allowed")
		}

		// execute the operation
		fmt.Printf("%d: %s(%c) %s\n", pc, op.String(), op, string(contract.GetBytes(pc)))
		
		err = operation.execute(&pc, in.evm, contract, stack)
		ln := binary.LittleEndian.Uint32(stack.data[0].space)

		// if the operation clears the return Data (e.g. it has returning Data)
		// set the last return to the result of the operation.
		if operation.returns {
			in.returnData = stack.data[0].space[4:ln + 4]
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return stack.data[0].space[4:ln + 4], errExecutionReverted
		case operation.halts:
			return stack.data[0].space[4:ln + 4], nil
		case !operation.jumps:
			if pc + 1 < int(contract.libs[stack.data[stack.callTop].inlib].end) {
				pc++
			} else {
				return nil, fmt.Errorf("Instruction out of range.")
			}
		}
	}
	return nil, err
}

func (in *Interpreter) VerifySig(txinidx int, pkScript, sigScript []byte) bool {
	return in.verifySig(txinidx, pkScript, sigScript)
}

func (in *Interpreter) verifySig(txinidx int, pkScript, sigScript []byte) bool {
	if pkScript[0] < PAYFUNC_MIN || pkScript[0] > PAYFUNC_MAX {	// check validation function range
		return false
	}

	contract := Contract {
		Code: []inst{inst{OpCode(sigScript[0]), sigScript[1:]}},
//		CodeHash: chainhash.Hash{},
		self: nil,
		Args: make([]byte, 4),
		pure: PUREMASK,	// don't allow state write, spending, add output, mint.
					// actually its impossible since the inst set is limited
	}

	binary.LittleEndian.PutUint32(contract.Args[:], uint32(txinidx))
	
//	ret = append(pkScript[4:], ret[:]...)
	contract.CodeAddr = []byte{ pkScript[0], 0, 0, 0 }

	ret, err := run(in.evm, &contract, pkScript[4:])	// ret)

	if err != nil || len(ret) != 1 || ret[0] != 1{
		return false
	} else {
		return true
	}
}