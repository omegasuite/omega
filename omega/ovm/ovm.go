// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ovm

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/omega/token"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = chainhash.DoubleHashB(nil)

type (
	// GetHashFunc returns the hash of input parameter
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) *chainhash.Hash

	// GetTxTemplate returns the transaction template for currect transaction
	// and is used by the TXTEMP EVM op code.
	GetTxTemplateFunc func() * wire.MsgTx

	// AddTxInput adds an input to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	SpendFunc func(token.Token) bool

	// AddTxOutput adds an output to  the transaction template for currect transaction
	// and is used by the ADDTXOUT EVM op code.
	AddTxOutputFunc func(wire.TxOut) bool

	// AddTxDef adds an definition to  the transaction template for currect transaction
	// limited to right definition only for now
	// and is used by the ADDTXDEF EVM op code.
	AddTxDefFunc func(token.Definition) bool

	// SubmitTx submits the currect transaction to the blockchain. returns Tx hash if
	// into the chain. and is used by the SUBMITTX EVM op code.
	// successful, otherwise nil
	SubmitTxFunc func() chainhash.Hash

	// GetBlockNumberFunc returns the block numer of the block of current execution environment
	GetBlockNumberFunc func() uint64

	// GetBlockTimeFunc returns the block time of the block of current execution environment
	GetBlockTimeFunc func() time.Time
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *OVM, contract *Contract, input []byte) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContractsHomestead
		if p := precompiles[*contract.CodeAddr]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	return evm.interpreter.Run(contract, input)
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	GetTxTemplate GetTxTemplateFunc
	Spend SpendFunc
	AddTxOutput AddTxOutputFunc
	SubmitTx SubmitTxFunc

	// GetHash returns the hash corresponding to block n
	GetHash GetHashFunc // GetHash 返回第 n 个区块的哈希值

	// Message information
//	Origin   common.Address // Provides information for ORIGIN. provided by the sender for the purpose to return gas
//	TxTemplate  wire.MsgTx	// Tx template of sending Tx

	// Block information
//	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // GASLIMIT policy
	BlockNumber GetBlockNumberFunc    // Provides information for NUMBER
	Time        GetBlockTimeFunc      // Provides information for TIME
//	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type OVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB map[Address]stateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *chaincfg.Params

	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.

	interpreter *Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
}

// NewOVM returns a new OVM. The returned OVM is not thread safe and should
// only ever be used *once*.for each block
func NewOVM(ctx Context, chainConfig *chaincfg.Params, vmConfig Config) *OVM {
	evm := &OVM{
		Context:     ctx,
		StateDB:     make(map[Address]stateDB, 0),
		vmConfig:    vmConfig,
		chainConfig: chainConfig,
	}
	evm.GasLimit    = uint64(chainConfig.ContractExecLimit)         // step limit the contract can run, node decided policy

	evm.interpreter = NewInterpreter(evm, vmConfig)
	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *OVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *OVM) Call(addr btcutil.Address, method []byte, sent * token.Token, params [][]byte) (ret []byte, steps uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, 0, nil
	}

	// Fail if we're trying to execute above the call depth limit
/*
	if evm.depth > int(params.CallCreateDepth) {
		return nil, 0, ErrDepth
	}
*/
	var (
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if precompiles[addr] == nil && value.Sign() == 0 {
			return nil, 0, nil
		}
		evm.StateDB.CreateAccount(addr)
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, addr, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	start := time.Now()

	steps = 0

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, time.Since(start), err)
		}()
	}
	ret, steps, err = run(evm, contract, input)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, steps, err
}

// Create creates a new contract using code as deployment code.
func (evm *OVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr btcutil.Address, leftOverGas uint64, err error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}

	// Ensure there's no existing contract already at the designated address
	contractAddr = crypto.CreateAddress(caller.Address())
	contractHash := evm.StateDB.GetCodeHash(contractAddr)
	if (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(contractAddr)

	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, AccountRef(contractAddr), value, gas)
	contract.SetCallCode(&contractAddr, crypto.Keccak256Hash(code), code)

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, contractAddr, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), contractAddr, true, code, gas, value)
	}
	start := time.Now()

	ret, steps, err := run(evm, contract, nil)

	// check whether the max code size has been exceeded
	maxCodeSizeExceeded := len(ret) > params.MaxCodeSize
	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(contractAddr, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil) {
		evm.StateDB.RevertToSnapshot(snapshot)
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, contractAddr, steps, err
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
