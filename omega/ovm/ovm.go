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
	"sync/atomic"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/omega"
	"bytes"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = chainhash.DoubleHashB(nil)

type (
	// GetHashFunc returns the hash of input parameter
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) *chainhash.Hash

	// GetTxFunc returns the transaction for currect transaction
	// and is used by the GETTX EVM op code.
	GetTxFunc func() * wire.MsgTx

	// GetUtxoFunx returns the UTXO indicated by hash and seq #.
	GetUtxoFunc func(chainhash.Hash, uint64) *wire.TxOut

	// GetCurrentOutputFunx returns the output that triggers the current contract call.
	GetCurrentOutputFunc func() *wire.TxOut

	// SpendFunc adds an input to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	SpendFunc func(token.Token) bool

	// AddRight adds an right definition to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	AddRightFunc func(*token.RightDef) bool

	// AddTxOutput adds an output to  the transaction template for currect transaction
	// and is used by the ADDTXOUT EVM op code.
	AddTxOutputFunc func(wire.TxOut) bool

	// GetBlockNumberFunc returns the block numer of the block of current execution environment
	GetBlockNumberFunc func() uint64
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *OVM, contract *Contract, input []byte) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContracts
		precompiles[[4]byte{0,0,0,0}] = &create{evm, contract }
		precompiles[[4]byte{0x40,0,0,0}] = &mint{evm, contract }
		var abi [4]byte
		copy(abi[:], contract.CodeAddr)
		if p := precompiles[abi]; p != nil {
			return RunPrecompiledContract(p, input, contract)
		}
	}
	return evm.interpreter.Run(contract, input)
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	GetTx GetTxFunc
	Spend SpendFunc
	AddTxOutput AddTxOutputFunc
	AddRight AddRightFunc
	GetUtxo GetUtxoFunc
	GetCurrentOutput GetCurrentOutputFunc

	// GetHash returns the hash corresponding to number n
	GetHash GetHashFunc

	// Block information
	GasLimit    uint64         // GASLIMIT policy
	BlockNumber GetBlockNumberFunc    // Provides information for NUMBER
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

	// views provide viewpoint of chain
	views * viewpoint.ViewPointSet

	// StateDB gives access to the underlying state
	StateDB map[Address]*stateDB

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
func NewOVM(ctx Context, chainConfig *chaincfg.Params, vmConfig Config, db database.DB) *OVM {
	evm := &OVM{
		Context:     ctx,
		StateDB:     make(map[Address]*stateDB, 0),
		vmConfig:    vmConfig,
		chainConfig: chainConfig,
		views: viewpoint.NewViewPointSet(db),
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
// parameters. It also takes the necessary steps to reverse the state in case of an
// execution error.
func (evm *OVM) Call(d Address, method []byte, sent * token.Token, params []byte) (ret []byte, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, nil
	}

	// Fail if we're trying to execute above the call depth limit
/*
	if evm.depth > int(params.CallCreateDepth) {
		return nil, 0, ErrDepth
	}
*/
	var (
		snapshot = evm.StateDB[d].Copy()
	)

	if method[0] > 0 && bytes.Compare(method[1:], []byte{0, 0, 0}) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "May not call system method directly.")
	}

		/*
			if !evm.StateDB[d].Exists() {
				precompiles := PrecompiledContractsHomestead
				if precompiles[addr] == nil && value.Sign() == 0 {
					return nil, 0, nil
				}
				evm.StateDB.CreateAccount(addr)
			}
		*/

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := evm.NewContract(d, sent)
//	contract.owner = evm.StateDB[d].GetOwner()
	contract.SetCallCode(method, evm.StateDB[d].GetCodeHash(), evm.StateDB[d].GetCode())

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
//		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, value)

//		defer func() { // Lazy evaluation of the parameters
//			evm.vmConfig.Tracer.CaptureEnd(ret, time.Since(start), err)
//		}()
	}

	ret, err = run(evm, contract, params)

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		* evm.StateDB[d] = snapshot
	}
	return ret, err
}
/*
func (evm *OVM) StaticCall(d Address, method []byte, sent * token.Token, params []byte) (ret []byte, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, nil
	}

	if method[0] > 0 && bytes.Compare(method[1:], []byte{0, 0, 0}) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "May not call system method directly.")
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := evm.NewContract(d, sent)
	contract.owner = evm.StateDB[d].GetOwner()
	contract.SetCallCode(method, evm.StateDB[d].GetCodeHash(), evm.StateDB[d].GetCode())

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		//		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, value)

		//		defer func() { // Lazy evaluation of the parameters
		//			evm.vmConfig.Tracer.CaptureEnd(ret, time.Since(start), err)
		//		}()
	}

	readonly := evm.interpreter.readOnly
	evm.interpreter.readOnly = true

	ret, err = run(evm, contract, params)

	evm.interpreter.readOnly = readonly

	return ret, err
}
*/

func (ovm *OVM) NewContract(d Address, value *token.Token) *Contract {
	c := &Contract{
		self: AccountRef(d),
		Args: nil,
		jumpdests: make(destinations),
		value: value,
	}

	c.self = ovm.StateDB[d].GetAddres()
	c.owner = ovm.StateDB[d].GetOwner()
//	c.Code = ovm.StateDB[d].GetCode()
//	c.CodeHash = ovm.StateDB[d].GetCodeHash()

	return c
}

// Create creates a new contract using code as deployment code.
func (ovm *OVM) Create(data []byte, contract *Contract) ([]byte, error) {
	// Ensure there's no existing contract already at the designated address
	contractAddr := Hash160(chainhash.DoubleHashB(data))

	var d Address
	copy(d[:], contractAddr)

	if _,ok := ovm.StateDB[d]; !ok {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract address incorrect.")
	}
	if ovm.StateDB[d].Exists() {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract already exists.")
	}

	contract.self = AccountRef(d)

//	copy(contract.owner[:], data[:20])

	contract.Code = data	// [20:]
	copy(contract.CodeHash[:], chainhash.DoubleHashB(data))	// [20:]))

	ovm.StateDB[d].SetAddres(contract.self.(AccountRef))
	ovm.StateDB[d].SetCode(contract.Code)
//	ovm.StateDB[d].SetOwner(contract.owner)
	ovm.StateDB[d].SetCodeHash(contract.CodeHash)

	contract.CodeAddr = nil
	ret, err := run(ovm, contract, nil)	// contract constructor. ret is the real contract code, ex. constructor
	if err != nil || len(ret) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "Fail to initialize contract.")
	}

	contract.Code = ret
	ovm.StateDB[d].SetCode(ret)
	copy(contract.CodeHash[:], chainhash.DoubleHashB(ret))
	ovm.StateDB[d].SetCodeHash(contract.CodeHash)

	return nil, nil
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
