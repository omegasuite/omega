// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
	"sync/atomic"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = chainhash.DoubleHashB(nil)

type (
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
		precompiles[[4]byte{OP_MINT,0,0,0}] = &mint{evm, contract }
		var abi [4]byte
		copy(abi[:], contract.CodeAddr)
		if p := precompiles[abi]; p != nil {
			return evm.interpreter.RunPrecompiledContract(p, input, contract)
		}
	}
	return evm.interpreter.Run(contract, input)
}

// Context provides the OVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	GetTx GetTxFunc
	Spend SpendFunc
	AddTxOutput AddTxOutputFunc
	AddRight AddRightFunc
	GetUtxo GetUtxoFunc
	GetCurrentOutput GetCurrentOutputFunc

	// Block information
	GasLimit    uint64 			      // GASLIMIT policy
	BlockNumber GetBlockNumberFunc    // Provides information for NUMBER
}

type lib struct{
	address int32		// code address
	end int32			// code end
	base int32			// lib global data
	pure bool
}

// OVM is the Omega Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state operation, no checks on specific errors should
// ever be performed. The interpreter makes sure that any errors
// generated are to be considered faulty code.
//
// The OVM should never be reused and is not thread safe.
type OVM struct {
	// Context provides auxiliary blockchain related information
	Context

	// views provide viewpoint of chain
	views * viewpoint.ViewPointSet

	// StateDB gives access to the underlying state
	StateDB map[Address]*stateDB

	libs map[Address]lib

	// Depth of the current call stack
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

	DB database.DB
}

// NewOVM returns a new OVM. The returned OVM is not thread safe and should
// only ever be used *once*.for each block
func NewOVM(ctx Context, chainConfig *chaincfg.Params, vmConfig Config, db database.DB) *OVM {
	evm := &OVM{
		Context:     ctx,
		StateDB:     make(map[Address]*stateDB),
		libs:		 make(map[Address]lib),
		vmConfig:    vmConfig,
		chainConfig: chainConfig,
		views: viewpoint.NewViewPointSet(db),
		DB: db,
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
		snapshot * stateDB
	)
	if _,ok := evm.StateDB[d]; ok {
		t := evm.StateDB[d].Copy()
		snapshot = &t
	}

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

	if contract == nil {
		return nil, fmt.Errorf("Contract does not exist")
	}
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
		evm.StateDB[d] = snapshot
	}
	return ret, err
}

func (ovm *OVM) NewContract(d Address, value *token.Token) *Contract {
	c := &Contract{
		self: AccountRef(d),
		Args: nil,
		value: value,
	}

	if _, ok := ovm.StateDB[d]; !ok {
		t := NewStateDB(ovm.views.Db, d)

		existence := t.Exists()
		if !existence {
			return nil
		}
		ovm.StateDB[d] = t
	}

	c.owner = ovm.StateDB[d].GetOwner()

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

	contract.Code = ByteCodeParser(data)	// [20:]
	if !ByteCodeValidator(contract.Code) {
		return nil, omega.ScriptError(omega.ErrInternal, "Illegal instruction is contract code.")
	}
	copy(contract.CodeHash[:], chainhash.DoubleHashB(data))	// [20:]))

	ovm.StateDB[d].SetAddres(contract.self.(AccountRef))
	ovm.StateDB[d].SetInsts(contract.Code)
	ovm.StateDB[d].SetCodeHash(contract.CodeHash)

	contract.CodeAddr = nil
	ret, err := run(ovm, contract, nil)	// contract constructor. ret is the real contract code, ex. constructor
	if err != nil || len(ret) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "Fail to initialize contract.")
	}

	contract.Code = ByteCodeParser(ret)
	ovm.StateDB[d].SetCode(ret)
	copy(contract.CodeHash[:], chainhash.DoubleHashB(ret))
	ovm.StateDB[d].SetCodeHash(contract.CodeHash)

	return nil, nil
}

func CreateSysWallet(chainConfig *chaincfg.Params, db database.DB) {
	var addr [20]byte

	sdb := * NewStateDB(db, addr)

	sdb.SetAddres(addr)
	sdb.Commit(0)
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
