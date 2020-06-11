// Copyright 2014 The omega suite Authors
// This file is part of the omega library.
//

package ovm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcutil"
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
	GetTxFunc func() * btcutil.Tx

	GetCoinBaseFunc func() * btcutil.Tx

	// GetUtxoFunx returns the UTXO indicated by hash and seq #.
	GetUtxoFunc func(chainhash.Hash, uint64) *wire.TxOut

	// GetCurrentOutputFunx returns the output that triggers the current contract call.
	GetCurrentOutputFunc func() wire.OutPoint

	// SpendFunc adds an input to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	SpendFunc func(wire.OutPoint) bool

	// AddRight adds an right definition to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	AddRightFunc func(*token.RightDef) bool

	// AddTxOutput adds an output to  the transaction template for currect transaction
	// and is used by the ADDTXOUT EVM op code.
	AddTxOutputFunc func(wire.TxOut) bool

	// GetBlockNumberFunc returns the block numer of the block of current execution environment
	GetBlockNumberFunc func() uint64
	GetBlockFunc func() * btcutil.Block

	AddCoinBaseFunc func(wire.TxOut) wire.OutPoint
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *OVM, contract *Contract, input []byte) ([]byte, error) {
	if contract.CodeAddr != nil {
		precompiles := PrecompiledContracts
		precompiles[[4]byte{0,0,0,0}] = &create{evm, contract }
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
	GetCoinBase GetCoinBaseFunc
	GetTx GetTxFunc
	Spend SpendFunc
	AddTxOutput AddTxOutputFunc
	AddRight AddRightFunc
	GetUtxo GetUtxoFunc
	GetCurrentOutput GetCurrentOutputFunc
	AddCoinBase AddCoinBaseFunc

	// Block information
	GasLimit    uint64 			      // GASLIMIT policy
	BlockNumber GetBlockNumberFunc    // Provides information for NUMBER
	Block 		GetBlockFunc
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

	// stateDB gives access to the underlying state
	StateDB map[Address]*stateDB
	TokenTypes map[uint64]Address

	// Depth of the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *chaincfg.Params

	NoLoop bool
	NoRecursion bool

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
func NewOVM(chainConfig *chaincfg.Params) *OVM {
	evm := &OVM{
		StateDB:     make(map[Address]*stateDB),
		TokenTypes:  make(map[uint64]Address),
		chainConfig: chainConfig,
	}
	evm.GasLimit    = uint64(chainConfig.ContractExecLimit)         // step limit the contract can run, node decided policy

	evm.interpreter = NewInterpreter(evm)
	return evm
}

func NewSigVM(chainConfig *chaincfg.Params) *OVM {
	evm := &OVM{
		StateDB:     make(map[Address]*stateDB),
		TokenTypes:  make(map[uint64]Address),
		chainConfig: chainConfig,
	}
	evm.GasLimit    = uint64(chainConfig.ContractExecLimit)         // step limit the contract can run, node decided policy

	evm.interpreter = NewSigInterpreter(evm)
	return evm
}

func (v * OVM) SetContext(ctx Context) {
	v.Context = ctx
}

type blockRollBack struct {
	prevBlock uint64
	rollBacks map[Address][2]rollback
	tokentypes map[uint64]Address
}

func (v * OVM) Commit() {
	var lastBlock uint64

	v.DB.View(func (dbTx  database.Tx) error {
		lastBlock = DbFetchVersion(dbTx, []byte("lastCommitBlock"))
		return nil
	})

	if v.BlockNumber() <= lastBlock {
		return
	}

	rollBacks := blockRollBack{ lastBlock, make(map[Address][2]rollback),
		v.TokenTypes,
	}

	for k,d := range v.StateDB {
		t := d.commit(v.BlockNumber())
		if len(t[0]) != 0 || len(t[1]) != 0 {
			rollBacks.rollBacks[k] = t
		}
	}

	s,err := json.Marshal(rollBacks)
	if err != nil {
		return
	}

	var rbkey [16]byte
	copy(rbkey[:], []byte("rollback"))
	binary.LittleEndian.PutUint64(rbkey[8:], v.BlockNumber())

	v.DB.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
		for t,a := range v.TokenTypes {
			var mtk [8]byte
			binary.LittleEndian.PutUint64(mtk[:], t)
			bucket.Put(mtk[:], a[:])
		}
		DbPutVersion(dbTx, []byte("lastCommitBlock"), v.BlockNumber())
		return dbTx.Metadata().Put(rbkey[:], s)
	})
	v.StateDB = make(map[Address]*stateDB)
	v.GasLimit = uint64(v.chainConfig.ContractExecLimit)         // step limit the contract can run, node decided policy
}

func (d *OVM) Rollback() {
	var lastBlock uint64

	d.DB.View(func (dbTx  database.Tx) error {
		lastBlock = DbFetchVersion(dbTx, []byte("lastCommitBlock"))
		return nil
	})

	if d.BlockNumber() != lastBlock {
		return
	}

	var rbkey [16]byte
	copy(rbkey[:], []byte("rollback"))

	binary.LittleEndian.PutUint64(rbkey[8:], lastBlock)

	var data []byte
	d.DB.View(func (dbTx  database.Tx) error {
		data = dbTx.Metadata().Get(rbkey[:])
		return nil
	})

	rollBacks := blockRollBack{ }
	err := json.Unmarshal(data, &rollBacks)
	if err != nil {
		return
	}

	d.DB.Update(func (dbTx  database.Tx) error {
		DbPutVersion(dbTx, []byte("lastCommitBlock"), rollBacks.prevBlock)
		dbTx.Metadata().Delete(rbkey[:])

		bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
		for t,_ := range rollBacks.tokentypes {
			var mtk [8]byte
			binary.LittleEndian.PutUint64(mtk[:], t)
			bucket.Delete(mtk[:])
		}

		for contract,d := range rollBacks.rollBacks {
			bucket := dbTx.Metadata().Bucket([]byte("storage" + string(contract[:])))

			for k,v := range d[0] {
				if len(v) == 0 {
					bucket.Delete([]byte(k))
				} else if err := bucket.Put([]byte(k), v); err != nil {
					return err
				}
			}

			bucket = dbTx.Metadata().Bucket([]byte("contract" + string(contract[:])))

			for k,v := range d[1] {
				if len(v) == 0 {
					bucket.Delete([]byte(k))
				} else if err := bucket.Put([]byte(k), v); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (v * OVM) SetCoinBaseOp(b AddCoinBaseFunc) {
	v.AddCoinBase = b
}

func (v * OVM) SetViewPoint(vp * viewpoint.ViewPointSet) {
	v.views = vp
	v.DB = vp.Db
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
	if evm.NoRecursion && evm.depth > 0 {
		return nil, nil
	}

	var (
		snapshot *stateDB
	)
	if _,ok := evm.StateDB[d]; ok {
		t := evm.StateDB[d].Copy()
		snapshot = &t
	}

	if method[0] > 0 && bytes.Compare(method[1:], []byte{0, 0, 0}) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "May not call system method directly.")
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := evm.NewContract(d, sent)

	if contract == nil {
		return nil, fmt.Errorf("Contract does not exist")
	}
	if bytes.Compare(method, []byte{0,0,0,0}) != 0 {
		contract.SetCallCode(method, evm.GetCode(d))
	} else {
		contract.CodeAddr = []byte{0,0,0,0}
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
		libs: make(map[Address]lib),
	}

	if _, ok := ovm.StateDB[d]; !ok {
		t := NewStateDB(ovm.views.Db, d)

		existence := t.Exists(true)
		if !existence {
			return nil
		}
		ovm.StateDB[d] = t
	}

//	c.owner = ovm.StateDB[d].GetOwner()

	return c
}

// Create creates a new contract using code as deployment code.
func (ovm *OVM) Create(data []byte, contract *Contract) ([]byte, error) {
	var d = contract.self.Address()

	if _,ok := ovm.StateDB[d]; !ok {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract address incorrect.")
	}
	if ovm.StateDB[d].Exists(false) {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract already exists.")
	}
	ovm.StateDB[d].fresh = true

	contract.Code = ByteCodeParser(data)
	if !ByteCodeValidator(contract.Code) {
		return nil, omega.ScriptError(omega.ErrInternal, "Illegal instruction is contract code.")
	}
//	copy(contract.CodeHash[:], chainhash.DoubleHashB(data))

	ovm.SetAddres(d, contract.self.(AccountRef))
//	ovm.SetInsts(d, contract.Code)
//	ovm.SetCodeHash(d, contract.CodeHash)

	contract.CodeAddr = nil
	ret, err := run(ovm, contract, nil)	// contract constructor. ret is the real contract code, ex. constructor

	if err != nil || len(ret) < 4 {
		return nil, omega.ScriptError(omega.ErrInternal, "Fail to initialize contract.")
	}

	block := ovm.Block()

	if block == nil {
		return nil, nil
	}

	m := ovm.GetCurrentOutput()

	loc,_ := block.TxLoc()
	tx := ovm.GetTx()
	n := m.Index
	msg := tx.MsgTx()

	p := 4
	p += common.VarIntSerializeSize(uint64(len(msg.TxDef)))
	for _, ti := range msg.TxDef {
		p += ti.SerializeSize()
	}

	p += common.VarIntSerializeSize(uint64(len(msg.TxIn)))
	for _, ti := range msg.TxIn {
		p += ti.SerializeSize()
	}

	p += common.VarIntSerializeSize(uint64(len(msg.TxOut)))
	for i, ti := range msg.TxOut {
		if i < int(n) {
			p += ti.SerializeSize()
		} else if i == int(n) {
			p += ti.Token.SerializeSize() + 25 + common.VarIntSerializeSize(uint64(len(ti.PkScript)))
		}
	}
	
	start := common.LittleEndian.Uint32(ret)
	ln := len(msg.TxOut[n].PkScript) - 25
	pks := msg.TxOut[n].PkScript[25:]
	dd := 0
	for i := 0; start > 0; i++ {
		if pks[i] == '\n' {
			start--
		}
		p++
		ln--
		dd++
	}
	pks = pks[dd:]

	r := database.BlockRegion {
		ovm.Block().Hash(),
		uint32(loc[n].TxStart + p),
		uint32(ln),
	}
	br := make([]byte, 40)
	copy(br, (*r.Hash)[:])
	common.LittleEndian.PutUint32(br[32:], r.Offset)
	common.LittleEndian.PutUint32(br[36:], r.Len)

	ovm.setMeta(d, "code", br)
	
	log.Infof("Contract created: %x", d)

//	contract.Code = ByteCodeParser(ret)
//	ovm.SetCode(d, ret)
//	copy(contract.CodeHash[:], chainhash.DoubleHashB(ret))
//	ovm.SetCodeHash(d, contract.CodeHash)

	return nil, nil
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
