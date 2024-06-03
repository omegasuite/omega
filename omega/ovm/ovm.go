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
	"encoding/json"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/chaincfg"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcutil"
	"github.com/omegasuite/famofchains/omega"
	"github.com/omegasuite/famofchains/omega/token"
	"github.com/omegasuite/famofchains/omega/viewpoint"
	"sync/atomic"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = chainhash.DoubleHashB(nil)

type (
	// GetTxFunc returns the transaction for currect transaction
	// and is used by the GETTX EVM op code.
	GetTxFunc func() *btcutil.Tx

	GetCoinBaseFunc func() *btcutil.Tx

	// GetUtxoFunx returns the UTXO indicated by hash and seq #.
	GetUtxoFunc func(chainhash.Hash, uint64) *wire.TxOut

	// GetCurrentOutputFunx returns the output that triggers the current contract call.
	GetCurrentOutputFunc func() wire.OutPoint

	// SpendFunc adds an input to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	SpendFunc func(wire.OutPoint, []byte) bool

	// AddDef adds an right definition to the transaction template for currect transaction
	// and is used by the ADDTXIN EVM op code.
	AddDefFunc func(token.Definition, bool) chainhash.Hash

	// AddTxOutput adds an output to  the transaction template for currect transaction
	// and is used by the ADDTXOUT EVM op code.
	AddTxOutputFunc func(wire.TxOut) int

	// GetBlockNumberFunc returns the block numer of the block of current execution environment
	GetBlockNumberFunc  func() uint64
	GetBlockTimeFunc    func() uint32
	GetBlockVersionFunc func() uint32
	//	GetBlockFunc func() * btcutil.Block

	AddCoinBaseFunc func(wire.TxOut) wire.OutPoint
)

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *OVM, contract *Contract, input []byte) ([]byte, omega.Err) {
	if contract.CodeAddr != nil {
		var abi [4]byte
		copy(abi[:], contract.CodeAddr)
		p := PrecompiledContracts[abi]
		if p != nil {
			return evm.interpreter.RunPrecompiledContract(p(evm, contract), input, contract)
		}
	}
	return evm.interpreter.Run(contract, input)
}

// Context provides the OVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	GetCoinBase      GetCoinBaseFunc
	GetTx            GetTxFunc
	Spend            SpendFunc
	AddTxOutput      AddTxOutputFunc
	AddDef           AddDefFunc
	GetUtxo          GetUtxoFunc
	GetCurrentOutput GetCurrentOutputFunc
	AddCoinBase      AddCoinBaseFunc

	// Block information
	StepLimit    int64              // Step LIMIT policy
	BlockNumber  GetBlockNumberFunc // Provides information for NUMBER
	BlockTime    GetBlockTimeFunc
	BlockVersion GetBlockVersionFunc

	exeout []bool
	//	Block 		GetBlockFunc
}

func (vm *Context) Init(tx *btcutil.Tx, views *viewpoint.ViewPointSet) {
	vm.GetTx = func() *btcutil.Tx { return tx }
	vm.AddTxOutput = func(t wire.TxOut) int {
		if tx == nil {
			return -1
		}
		if !tx.HasOuts {
			vm.exeout = append(vm.exeout, true)
		}
		if t.TokenType == token.DefTypeSeparator {
			to := wire.TxOut{}
			to.Token = token.Token{TokenType: token.DefTypeSeparator}
			return tx.AddTxOut(to)
		} else {
			vm.exeout = append(vm.exeout, false)
			return tx.AddTxOut(t)
		}
	}
	vm.Spend = func(t wire.OutPoint, sig []byte) bool {
		if tx == nil {
			return false
		}
		// it has already been verified that the coin either belongs to the contract
		// or has a signature (will verify after contract exec)
		tx.AddTxIn(t, sig)
		return true
	}
	vm.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut {
		if tx != nil && hash.IsEqual(tx.Hash()) {
			if int(seq) >= len(tx.MsgTx().TxOut) {
				return nil
			}
			return tx.MsgTx().TxOut[seq]
		}
		op := make(map[wire.OutPoint]struct{})
		p := wire.OutPoint{hash, uint32(seq)}
		e := views.Utxo.LookupEntry(p)
		if e != nil {
			return e.ToTxOut()
		}
		op[p] = struct{}{}
		if views.Utxo.FetchUtxosMain(views.Db, op) != nil {
			return nil
		}
		e = views.Utxo.LookupEntry(p)
		if e == nil {
			return nil
		}
		return e.ToTxOut()
	}
}

type Rollback struct {
	Key   []byte
	Value []byte
}

type PrevInfo struct {
	NewContract bool
	Addr        Address
	Data        [2][]Rollback
}

type RBTokenTypes struct {
	ID   uint64
	Addr []byte
}

type BlockRollBack struct {
	PrevBlock  uint64
	RollBacks  []*PrevInfo
	Tokentypes []RBTokenTypes
}

type fstate struct {
	issuedToken uint64
	suicided    bool
	data        map[string]*entry
	meta        map[string]*entry
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
	views *viewpoint.ViewPointSet

	// stateDB gives access to the underlying state
	StateDB            map[Address]*stateDB
	TokenTypes         map[uint64]Address
	ExistingTokenTypes map[uint64]Address

	// roll back mgmt
	lastBlock uint64
	//	rollbacks map[uint64]*BlockRollBack
	//	final map[Address] * fstate

	// Depth of the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *chaincfg.Params

	NoLoop      bool
	NoRecursion bool

	contractStack []Address

	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.

	interpreter *Interpreter

	writeback bool
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32

	DB database.DB

	//	CheckExecCost	bool	// whether we will check execution cost. This will be true only when packing blocks, not wen validating
	//	Paidfees int64
}

func NewSigVM(chainConfig *chaincfg.Params) *OVM {
	evm := &OVM{
		StateDB:     make(map[Address]*stateDB),
		chainConfig: chainConfig,
	}
	evm.StepLimit = chainConfig.ContractExecLimit // step limit the contract can run, node decided policy

	evm.interpreter = NewSigInterpreter(evm)
	return evm
}

func (v *OVM) SetContext(ctx Context) {
	v.Context = ctx
}

func (v *OVM) Commit() {
	// commit contract Data to Db. also roll back info.
	if len(v.StateDB) == 0 {
		return
	}

	var lastBlock uint64

	v.DB.View(func(dbTx database.Tx) error {
		lastBlock = DbFetchVersion(dbTx, []byte("lastCommitBlock"))
		return nil
	})

	if v.BlockNumber() <= lastBlock {
		return
	}

	rollBacks := BlockRollBack{lastBlock, make([]*PrevInfo, 0, len(v.StateDB)),
		make([]RBTokenTypes, 0, len(v.TokenTypes)),
	}
	for t, a := range v.TokenTypes {
		if _, ok := v.ExistingTokenTypes[t]; ok && a == v.ExistingTokenTypes[t] {
			continue
		} else if !ok {
			rollBacks.Tokentypes = append(rollBacks.Tokentypes, RBTokenTypes{t, nil})
		} else {
			tmp := v.ExistingTokenTypes[t]
			rollBacks.Tokentypes = append(rollBacks.Tokentypes, RBTokenTypes{t, tmp[:]})
		}
	}

	for k, d := range v.StateDB {
		t := d.commit(v.BlockNumber())
		t.Addr = k
		if len(t.Data[0]) != 0 || len(t.Data[1]) != 0 {
			rollBacks.RollBacks = append(rollBacks.RollBacks, t)
		}
	}

	s, err := json.Marshal(rollBacks)
	if err != nil {
		panic("Unable to Marshal rollBacks")
	}

	var rbkey [16]byte
	copy(rbkey[:], []byte("Rollback"))
	binary.LittleEndian.PutUint64(rbkey[8:], v.BlockNumber())

	v.DB.Update(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
		for t, a := range v.TokenTypes {
			var mtk [8]byte
			binary.LittleEndian.PutUint64(mtk[:], t)
			bucket.Put(mtk[:], a[:])
		}
		DbPutVersion(dbTx, []byte("lastCommitBlock"), v.BlockNumber())
		return dbTx.Metadata().Put(rbkey[:], s)
	})

	//	fmt.Printf("OVM.Commit rollback lastCommitBlock=%d:\n%s\n", v.BlockNumber(), spew.Sdump(rollBacks))

	v.StateDB = make(map[Address]*stateDB)
	v.TokenTypes = make(map[uint64]Address)
	v.ExistingTokenTypes = make(map[uint64]Address)
	v.lastBlock = v.BlockNumber()
	v.StepLimit = v.chainConfig.ContractExecLimit // step limit the contract can run, node decided policy
}

func (d *OVM) Rollback() error {
	// perform roll back op. roll back is performed on block basis
	if d.BlockNumber() != d.lastBlock {
		return nil
	}

	var rbkey [16]byte
	copy(rbkey[:], []byte("Rollback"))

	binary.LittleEndian.PutUint64(rbkey[8:], d.lastBlock)

	return d.DB.Update(func(dbTx database.Tx) error {
		data := dbTx.Metadata().Get(rbkey[:])

		rollBacks := BlockRollBack{}
		err := json.Unmarshal(data, &rollBacks)
		if err != nil {
			return err
		}

		//		fmt.Printf("OVM.Rollback lastCommitBlock=%d:\n%s\n", d.lastBlock, spew.Sdump(rollBacks))

		//		d.rollbacks[d.lastBlock] = &rollBacks
		d.lastBlock = rollBacks.PrevBlock
		DbPutVersion(dbTx, []byte("lastCommitBlock"), rollBacks.PrevBlock)
		dbTx.Metadata().Delete(rbkey[:])

		bucket := dbTx.Metadata().Bucket(IssuedTokenTypes)
		for _, rb := range rollBacks.Tokentypes {
			// Rollback all new token types created here
			var mtk [8]byte
			t := rb.ID
			binary.LittleEndian.PutUint64(mtk[:], t)
			if len(rb.Addr) == 0 { // rb.Addr is prev contract that owns this token type
				err = bucket.Delete(mtk[:]) // if none, then it is a new token type
			} else { // this will happen only if contract rb.Addr transfers token right
				err = bucket.Put(mtk[:], rb.Addr[:])
			}
			if err != nil {
				return err
			}
			/*
				if _,ok := d.final[addr]; !ok {
					d.final[addr] = &fstate {
						t,
						suicided,
						make(map[string]*entry),
						make(map[string]*entry),
					}
				} else {
					d.final[addr].issuedToken = t
				}
			*/
		}

		for _, dd := range rollBacks.RollBacks {
			if dd.NewContract {
				// remove contract
				mta := dbTx.Metadata()
				mta.DeleteBucket([]byte("contract" + string(dd.Addr[:])))
				mta.DeleteBucket([]byte("storage" + string(dd.Addr[:])))
			} else {
				// undo Data updates
				bucket = dbTx.Metadata().Bucket([]byte("contract" + string(dd.Addr[:])))
				/*
					if _, ok := d.final[dd.Addr]; !ok {
						suicided := false
						if scd := bucket.Get([]byte("suicided")); scd != nil {
							suicided = true
						}

						d.final[dd.Addr] = &fstate{
							0,
							suicided,
							make(map[string]*entry),
							make(map[string]*entry),
						}
					}
				*/

				for _, v := range dd.Data[1] { // meta
					/*
						if _, ok := d.final[dd.Addr].meta[k]; !ok {
							fv := bucket.Get([]byte(k))
							if fv == nil {
								d.final[dd.Addr].meta[k] = &entry{
									olddata: v.Value,
								}
							} else {
								d.final[dd.Addr].meta[k] = &entry{
									olddata: v.Value,
									Data:    fv,
								}
							}
						}
					*/
					if len(v.Value) == 0 {
						err = bucket.Delete(v.Key)
					} else {
						err = bucket.Put(v.Key, v.Value)
					}
					if err != nil {
						return err
					}
				}

				bucket = dbTx.Metadata().Bucket([]byte("storage" + string(dd.Addr[:])))
				for _, v := range dd.Data[0] { // Data
					/*
						if _, ok := d.final[dd.Addr].Data[k]; !ok {
							fv := bucket.Get([]byte(k))
							if fv == nil {
								d.final[dd.Addr].Data[k] = &entry{
									olddata: v.Value,
								}
							} else {
								d.final[dd.Addr].Data[k] = &entry{
									olddata: v.Value,
									Data:    fv,
								}
							}
						}
					*/
					if len(v.Value) == 0 {
						err = bucket.Delete(v.Key)
					} else {
						err = bucket.Put(v.Key, v.Value)
					}
					if err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (v *OVM) SetCoinBaseOp(b AddCoinBaseFunc) {
	v.AddCoinBase = b
}

func (v *OVM) SetViewPoint(vp *viewpoint.ViewPointSet) {
	v.views = vp
	v.DB = vp.Db

	v.DB.View(func(dbTx database.Tx) error {
		v.lastBlock = DbFetchVersion(dbTx, []byte("lastCommitBlock"))
		return nil
	})
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *OVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

func (ovm *OVM) NewContract(d Address, value *token.Token) *Contract {
	c := &Contract{
		self:  AccountRef(d),
		Args:  nil,
		value: value,
		libs:  make(map[Address]lib),
	}

	if _, ok := ovm.StateDB[d]; !ok {
		t := NewStateDB(ovm.views.Db, d)

		existence := t.Exists(true)
		if !existence {
			return nil
		}
		ovm.StateDB[d] = t
	}

	return c
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
