/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package ovm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/viewpoint"
	"golang.org/x/crypto/ripemd160"
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

// NewOVM returns a new OVM. The returned OVM is not thread safe and should
// only ever be used *once*.for each block
func NewOVM(chainConfig *chaincfg.Params) *OVM {
	evm := &OVM{
		StateDB:            make(map[Address]*stateDB),
		TokenTypes:         make(map[uint64]Address),
		ExistingTokenTypes: make(map[uint64]Address),
		chainConfig:        chainConfig,
		lastBlock:          0,
		//		CheckExecCost: false,
	}
	evm.StepLimit = chainConfig.ContractExecLimit // step limit the contract can run, node decided policy

	evm.interpreter = NewInterpreter(evm)
	return evm
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

// Call executes the contract associated with the addr with the given input as
// parameters. It also takes the necessary steps to reverse the state in case of an
// execution error.
func (evm *OVM) Call(d Address, method []byte, sent *token.Token, params []byte, pure byte) (ret []byte, err omega.Err) {
	if evm.NoRecursion && evm.depth > 0 {
		return nil, nil
	}

	var (
		snapshot  = make(map[Address]*stateDB)
		steplimit = evm.StepLimit
	)
	for adr, db := range evm.StateDB {
		t := db.Copy()
		snapshot[adr] = &t
	}

	if method[0] > OP_PUBLIC && bytes.Compare(method[1:], []byte{0, 0, 0}) == 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "May not call system method directly.")
	}

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := evm.NewContract(d, sent)

	if contract == nil {
		err := omega.ScriptError(omega.ErrInternal, "Contract does not exist")
		err.ErrorLevel = omega.RecoverableLevel
		return nil, err
	}
	if bytes.Compare(method, []byte{0, 0, 0, 0}) != 0 {
		if err := contract.SetCallCode(method, evm.GetCode(d)); err != nil {
			return nil, err
		}
		contract.isnew = false
	} else {
		contract.CodeAddr = []byte{0, 0, 0, 0}
		contract.isnew = true
	}
	contract.pure = pure

	ret, err = run(evm, contract, params)

	if err != nil || !evm.writeback {
		if err != nil {
			evm.StepLimit = steplimit
		}
		evm.StateDB = snapshot
	}
	return ret, err
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

	//	c.owner = ovm.StateDB[d].GetOwner()

	return c
}

// Create creates a new contract using code as deployment code.
func (ovm *OVM) Create(data []byte, contract *Contract) ([]byte, omega.Err) {
	var d = contract.self.Address()

	if _, ok := ovm.StateDB[d]; !ok {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract address incorrect.")
	}
	if ovm.StateDB[d].Exists(false) {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract already exists.")
	}

	tx := ovm.GetTx()
	m := ovm.GetCurrentOutput()
	coin := tx.MsgTx().TxOut[m.Index].Token
	if coin.TokenType != 0 || coin.Value.(*token.NumToken).Val != 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract creation does not take a value.")
	}

	if len(tx.MsgTx().TxIn) != 1 {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract creation must have exactly one input.")
	}
	// the only input must come from a pkh address so we can identify the creator
	ovm.views.Utxo.FetchUtxosMain(ovm.DB, map[wire.OutPoint]struct{}{tx.MsgTx().TxIn[0].PreviousOutPoint: struct{}{}})
	e := ovm.views.Utxo.LookupEntry(tx.MsgTx().TxIn[0].PreviousOutPoint)
	if e == nil {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract creation input is not available.")
	}
	version, addr, _, _ := parsePkScript(e.PkScript())
	if version != ovm.chainConfig.PubKeyHashAddrID {
		return nil, omega.ScriptError(omega.ErrInternal, "Contract creator must be a pubkeyhash address.")
	}
	var creator [21]byte
	creator[0] = version
	copy(creator[1:], addr)

	ovm.StateDB[d].fresh = true

	contract.Code = ByteCodeParser(data)
	if err := ByteCodeValidator(contract.Code); err != nil {
		return nil, err
	}

	ripemd160 := ripemd160.New()
	ripemd160.Write(data)
	hash := ripemd160.Sum(nil)

	if bytes.Compare(hash, d[:]) != 0 {
		return nil, omega.ScriptError(omega.ErrInternal, "contract address does not match code hash")
	}

	ovm.setAddress(d, contract.self.(AccountRef))

	contract.CodeAddr = nil
	ret, err := run(ovm, contract, nil) // contract constructor. ret is the real contract code, ex. constructor

	if err != nil || len(ret) < 4 {
		return nil, omega.ScriptError(omega.ErrInternal, "Fail to initialize contract.")
	}

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

	br := make([]byte, 40)
	copy(br, (*tx.Hash())[:])
	common.LittleEndian.PutUint32(br[32:], uint32(p))
	common.LittleEndian.PutUint32(br[36:], uint32(ln))

	ovm.setMeta(d, "code", br)
	ovm.setMeta(d, "creator", creator[:])

	log.Infof("Contract created: %x", d)

	return nil, nil
}

// ChainConfig returns the environment's chain configuration
func (evm *OVM) ChainConfig() *chaincfg.Params { return evm.chainConfig }

// Interpreter returns the EVM interpreter
func (evm *OVM) Interpreter() *Interpreter { return evm.interpreter }
