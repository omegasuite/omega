/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"encoding/binary"
	"fmt"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/omega"
	"strings"
	"time"

	//	"github.com/omegasuite/btcd/chaincfg/chainhash"
	//	"github.com/omegasuite/btcd/wire/common"
	"sync/atomic"
)

// Interpreter is used to run Ethereum based contracts and will utilise the
// passed evmironment to query external sources for state information.
// The Interpreter will run the byte code VM based on the passed
// configuration.
type DebugCommand byte

const (
	Breakpoint = DebugCommand(iota)
	Unbreak
	Stepping
	GoUp
	Gorun
	Getdata
	Getstack
	Breaked
	Terminate
	Terminated
	Evaluate
)

type DebugCmd struct {
	Cmd   DebugCommand
	Data  []byte      // command come in
	Reply chan []byte // returned info
}
type Interpreter struct {
	evm *OVM

	JumpTable [256]operation

	//	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return Data for subsequent reuse
}

// smart contract debugger
var debugNotifier chan []byte
var debugging bool           // whether we are debugging
var breakpoints map[int]bool // breaks at inst. PC
var Control chan *DebugCmd   // chan for receiving Control
var inspector chan *DebugCmd // chan for inspect inst to prog. code
var stepping bool            // whether we are stepping
var stop bool
var attaching chan struct{}
var dbgreturn bool // where user has clicked 'up'

func DebugSetup(enable bool, comm chan []byte) {
	if comm == nil {
		enable = false
	}
	if debugging == enable {
		return
	}

	if attaching == nil {
		attaching = make(chan struct{}, 10)
	}

	stepping, dbgreturn, stop = false, false, false

	debugging = enable
	if enable {
		debugNotifier = comm
		breakpoints = make(map[int]bool)
		Control = make(chan *DebugCmd, 10)
		go intrepdebug()
	} else {
		debugNotifier = nil
		breakpoints = nil
		Control = nil
		inspector = nil
	}
}

// NewInterpreter returns a new instance of the Interpreter.
func NewInterpreter(evm *OVM) *Interpreter {
	a := &Interpreter{
		evm:       evm,
		JumpTable: omegaInstructionSet,
	}

	return a
}

var dbgcontract *Contract
var dbgstack *Stack
var readysent = false
var dbgcodebase int

func setdbgcontract(contract *Contract, addr Address, stack *Stack) {
	dbgcontract, dbgstack, dbgcodebase = contract, stack, int(contract.libs[addr].address)

	inspector = make(chan *DebugCmd, 10)

	var prepend [2]byte
	prepend[0] = 'C'
	if dbgcontract.isnew {
		prepend[1] = 'C'
	} else {
		prepend[1] = 'E'
	}

	debugNotifier <- append(prepend[:], addr[:]...)

	readysent = false

	<-attaching
}

func intrepdebug() {
	var breakat int
	var waitingchan chan []byte

	for debugging {
		select {
		case ctrl, ok := <-Control:
			if !ok {
				debugging = false
				break
			}

			switch ctrl.Cmd {
			case Breakpoint:
				inst := common.LittleEndian.Uint32(ctrl.Data)
				breakpoints[int(inst)] = true
				stepping = true

			case Unbreak:
				inst := common.LittleEndian.Uint32(ctrl.Data)
				delete(breakpoints, int(inst))

			case Stepping:
				stepping = true
				breakat = 0

				waitingchan = ctrl.Reply

				if !readysent {
					readysent = true
					attaching <- struct{}{}
				} else {
					inspector <- ctrl
				}

			case GoUp:
				breakat = 0
				stepping = false
				dbgreturn = true

				waitingchan = ctrl.Reply

				if !readysent {
					readysent = true
					attaching <- struct{}{}
				} else {
					inspector <- ctrl
				}

			case Gorun:
				breakat = 0
				stepping = false

				waitingchan = ctrl.Reply

				if !readysent {
					readysent = true
					attaching <- struct{}{}
				} else {
					inspector <- ctrl
				}

			case Breaked:
				breakat = int(common.LittleEndian.Uint32(ctrl.Data))
				stepping = true

				if waitingchan != nil {
					waitingchan <- append([]byte{byte(Breaked)}, ctrl.Data...)
				}

			case Terminate: // terminate by user. end debugging
				inspector <- ctrl
				debugging = false

			case Terminated: // natural termination of contract. in this case we will wait for next contract exec
				if waitingchan != nil {
					waitingchan <- []byte{byte(Terminated)}
				}

				if !readysent {
					readysent = true
					attaching <- struct{}{}
				}

			case Evaluate:
				v := common.LittleEndian.Uint64(ctrl.Data)
				l := common.LittleEndian.Uint32(ctrl.Data[8:])
				if int(uint32(v)) >= len(dbgstack.data[int32(v>>32)].space) {
					ctrl.Reply <- []byte{}
				} else {
					if int(uint32(v)+l) > len(dbgstack.data[int32(v>>32)].space) {
						l = uint32(len(dbgstack.data[int32(v>>32)].space)) - uint32(v)
					}
					ctrl.Reply <- dbgstack.data[int32(v>>32)].space[uint32(v) : uint32(v)+l]
				}

			case Getdata:
				if ctrl.Data != nil && breakat != 0 {
					v, _, _ := dbgstack.getNum(ctrl.Data[:len(ctrl.Data)-4], 0xFF) // parse data ad address
					l := common.LittleEndian.Uint32(ctrl.Data[len(ctrl.Data)-4:])
					ctrl.Reply <- dbgstack.data[int32(v>>32)].space[uint32(v) : uint32(v)+l]
				} else {
					ctrl.Reply <- nil
				}

			case Getstack:
				if breakat != 0 && dbgstack.callTop != 0 {
					buf := make([]byte, dbgstack.callTop*4)
					common.LittleEndian.PutUint32(buf[:], uint32(breakat))
					for i, j := dbgstack.callTop-1, 4; i > 0; i-- {
						common.LittleEndian.PutUint32(buf[j:], uint32(dbgstack.data[i].pc))
						j += 4
					}
					ctrl.Reply <- buf
				} else {
					ctrl.Reply <- nil
				}
			}

		case <-time.After(time.Minute * 10):
			debugging = false
		}
	}

	dbgcontract, dbgstack = nil, nil
	debugging, stop, stepping, breakpoints = false, true, false, make(map[int]bool)
}

func NewSigInterpreter(evm *OVM) *Interpreter {
	return &Interpreter{
		evm:       evm,
		JumpTable: NewSignVMInstSet(),
	}
}

func (in *Interpreter) enforceRestrictions(op OpCode, operation operation, stack *Stack) omega.Err {
	if (stack.data[stack.callTop].pure &^ INHERIT) != 0 { // in.readOnly {
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
		op OpCode      // current opcode
		pc = uint64(0) // program counter
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
	pc := int(0) // program counter

	contract := &Contract{
		Code: []inst{*code},
	}

	op := code.op
	operation := in.JumpTable[op]
	if !operation.valid {
		return nil, omega.ScriptError(omega.ErrInternal, fmt.Sprintf("invalid opcode 0x%x", int(op)))
	}
	if err := in.enforceRestrictions(op, operation, stack); err != nil {
		return nil, err
	}
	if operation.writes {
		return nil, omega.ScriptError(omega.ErrInternal, "State modification is not allowed")
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
func (in *Interpreter) Run(contract *Contract, input []byte) (ret []byte, err omega.Err) {
	// Increment the call depth which is restricted to 1024
	// this is exec call depth, not func call depth
	in.evm.depth++
	defer func() {
		if debugging {
			Control <- &DebugCmd{Terminated, nil, nil}
		}
		in.evm.depth--
	}()

	if debugging {
		log.Infof("Contract run()")
	}

	// Reset the previous call's return Data. It's unimportant to preserve the old buffer
	// as every returning call will return new Data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op    OpCode       // current opcode
		stack = Newstack() // local stack
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc = int(0) // program counter
	)
	contract.libs[Address([20]byte{})] = lib{
		end:  int32(len(contract.Code)),
		pure: contract.pure,
	}
	contract.Input = input
	stack.data[0].pure = contract.pure

	if len(input) > 0 {
		stack.malloc(8 + len(input))
		binary.LittleEndian.PutUint32(stack.data[0].space, uint32(len(input)))
		copy(stack.data[0].space[8:], input)
	}

	/*	cost := int64(0)
		allowance := in.evm.Paidfees * 100000

		if in.evm.chainConfig.ContractExecFee == 0 {
			in.evm.CheckExecCost = false
		}
	*/

	if debugging && in.evm.chainConfig.Net == common.TestNet {
		log.Info("start intrepdebug")
		if attaching == nil {
			attaching = make(chan struct{}, 10)
		}
	}

	//	debugging = true
	var printInst = in.evm.chainConfig.Net == common.TestNet && strings.Contains(in.evm.chainConfig.ExternalIPs[0], ":8383") // debugging

	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	for atomic.LoadInt32(&in.evm.abort) == 0 {
		in.evm.StepLimit--
		if in.evm.StepLimit < 0 && in.evm.chainConfig.Net == common.MainNet {
			err := omega.ScriptError(omega.ErrInternal, "Exceeded operation limit")
			err.ErrorLevel = omega.RecoverableLevel
			return nil, err
		}
		/*
			if in.evm.CheckExecCost {
				cost += in.evm.chainConfig.ContractExecFee
				if cost > allowance {
					return nil, omega.ScriptError(omega.ErrInternal,"Exceeded gas limit")
				}
			}
		*/

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = contract.GetOp(pc)
		operation := in.JumpTable[op]
		if !operation.valid {
			err := omega.ScriptError(omega.ErrInternal, fmt.Sprintf("invalid opcode 0x%x", int(op)))
			return nil, err
		}

		// If the operation is valid, enforce any write restrictions
		if err := in.enforceRestrictions(op, operation, stack); err != nil {
			return nil, err
		}

		if contract.pure&NOWRITE != 0 && operation.writes {
			return nil, omega.ScriptError(omega.ErrInternal, "State modification is not allowed")
		}

		// execute the operation
		if printInst {
			s := ""
			for i := int32(0); i < stack.callTop; i++ {
				s += "    "
			}
			fmt.Printf("%s%d: %s(%c) %s\n", s, pc, op.String(), op, string(contract.GetBytes(pc)))
		}

		err = operation.execute(&pc, in.evm, contract, stack)
		ln := binary.LittleEndian.Uint32(stack.data[0].space)

		// if the operation clears the return Data (e.g. it has returning Data)
		// set the last return to the result of the operation.
		mln := ln + 4
		if len(stack.data[0].space) < int(ln+4) {
			mln = uint32(len(stack.data[0].space))

		}
		if operation.returns {
			in.returnData = stack.data[0].space[4:mln]
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return stack.data[0].space[4:mln], errExecutionReverted
		case stop:
			stop = false
			return nil, nil
		case operation.halts:
			return stack.data[0].space[4:mln], nil
		case !operation.jumps:
			if pc+1 < int(contract.libs[stack.data[stack.callTop].inlib].end) {
				pc++
			} else {
				return nil, omega.ScriptError(omega.ErrInternal, "Instruction out of range.")
			}
		}
	}
	return nil, err
}

func (in *Interpreter) VerifySig(txinidx int, pkScript, sigScript []byte) bool {
	return in.verifySig(txinidx, pkScript, sigScript)
}

func (in *Interpreter) verifySig(txinidx int, pkScript, sigScript []byte) bool {
	if pkScript[0] < PAYFUNC_MIN || pkScript[0] > PAYFUNC_MAX { // check validation function range
		return false
	}

	contract := Contract{
		Code: []inst{inst{OpCode(sigScript[0]), sigScript[1:]}},
		//		CodeHash: chainhash.Hash{},
		self: nil,
		Args: make([]byte, 4),
		pure: PUREMASK, // don't allow state write, spending, add output, mint.
		// actually its impossible since the inst set is limited
	}

	binary.LittleEndian.PutUint32(contract.Args[:], uint32(txinidx))

	//	ret = append(pkScript[4:], ret[:]...)
	contract.CodeAddr = []byte{pkScript[0], 0, 0, 0}

	ret, err := run(in.evm, &contract, pkScript[4:]) // ret)

	if err != nil || len(ret) != 1 || ret[0] != 1 {
		return false
	} else {
		return true
	}
}
