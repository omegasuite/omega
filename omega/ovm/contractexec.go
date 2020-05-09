// Copyright (c) 2019 The Omega developers
// Use of this source code is governed by an license that can
// be found in the LICENSE file.

package ovm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/validate"
	"github.com/btcsuite/omega/viewpoint"
	"golang.org/x/crypto/ripemd160"
	"sync/atomic"
)

// hash160 returns the RIPEMD160 hash of the SHA-256 HASH of the given data.
func hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	return ripemd160h(h[:])
}

// ripemd160h returns the RIPEMD160 hash of the given data.
func ripemd160h(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}

func Hash160(data []byte) []byte {
	return hash160(data)
}

func zeroaddr(addr []byte) bool {
	for _,t := range addr {
		if t != 0 {
			return false
		}
	}
	return true
}

func parsePkScript(script []byte) (byte, []byte, []byte, []byte) {
	if len(script) < 25 {
		return 0, nil, nil, nil
	}

	return script[0], script[1:21], script[21:25], script[21:]
}

type tbv struct {
	txinidx	int
	sigScript []byte
	pkScript []byte
}

func CalcSignatureHash(tx *wire.MsgTx, txinidx int, script []byte, txHeight int32,
	chainParams *chaincfg.Params) (chainhash.Hash, error) {
	// based on partial script (!!!must!!!) for TxIn, calculate signature hash for signing
	if tx.IsCoinBase() {
		return chainhash.Hash{}, omega.ScriptError(omega.ErrInternal, "Can not sign a coin base.")
	}

	ctx := Context{}

	utx := btcutil.NewTx(tx)

	ctx.GetTx = func () * btcutil.Tx {	return utx	}
	ctx.Spend = func(t wire.OutPoint) bool { return false }
	ctx.AddTxOutput = func(t wire.TxOut) bool { return false	}
	ctx.BlockNumber = func() uint64 { return uint64(txHeight) }
	ctx.AddRight = func(t *token.RightDef) bool { return false }
	ctx.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut {	return nil	}

	ovm := NewSigVM(chainParams)
	ovm.SetContext(ctx)

//	ovm.interpreter = NewSigInterpreter(ovm, cfg)
	ovm.interpreter.readOnly = true
	ovm.NoLoop = true

	return calcSignatureHash(txinidx, script, ovm)
}

func calcSignatureHash(txinidx int, script []byte, vm * OVM) (chainhash.Hash, error) {
	contract := Contract {
		Code: []inst{inst {OpCode(script[0]), script[1:]}},
		CodeHash: chainhash.Hash{},
		self: nil,
		Args:make([]byte, 4),
		libs: make(map[Address]lib),
	}

	binary.LittleEndian.PutUint32(contract.Args[:], uint32(txinidx))

	ret, err := vm.Interpreter().Run(&contract, nil)

	if err != nil {
		return chainhash.Hash{}, err
	}

//	ret,_ = reformatData(ret)

	return chainhash.DoubleHashH(ret), nil
}

// there are 2 sig verify methods: one in interpreter, one is here. the differernce is that
// the one in interpreter is intended for client side. here is for the miner. here, verification
// is deeper in that it checks monitering status, a tx will be rejected if monitore checing fails
// while it may pass interpreter verification because only signature verification is done there
func (ovm * OVM) VerifySigs(tx *btcutil.Tx, txHeight int32) error {
	if tx.IsCoinBase() {
		return nil
	}

	ovm.GetTx = func () * btcutil.Tx {	return tx }
	ovm.Spend = func(t wire.OutPoint) bool { return false }
	ovm.AddTxOutput = func(t wire.TxOut) bool { return false	}
	ovm.BlockNumber = func() uint64 { return uint64(txHeight) }
	ovm.AddRight = func(t *token.RightDef) bool { return false }
	ovm.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut {	return nil	}

	ovm.NoLoop = true

	ovm.interpreter.readOnly = true

	// set up for concurrent execution
	verifiers := make(chan bool, ovm.chainConfig.SigVeriConcurrency)
	queue := make(chan tbv, ovm.chainConfig.SigVeriConcurrency)
	final := make(chan bool, 1)

	views := ovm.views

	defer func () {
		close(verifiers)
	} ()

	allrun := false

	for i := 0; i < ovm.chainConfig.SigVeriConcurrency; i++ {
		verifiers <- true
	}

	var toverify int32

	go func() {
		for {
			select {
			case code, more := <-queue:
				if !more {
					return
				}
				<-verifiers
				go func() {
					res := ovm.Interpreter().verifySig(code.txinidx, code.pkScript, code.sigScript)
					if res {
						verifiers <- true
						if allrun && atomic.LoadInt32(&toverify) == 1 {
							final <- true
						}
						atomic.AddInt32(&toverify, -1)
					} else {
						final <- false
					}
					log.Infof("verifySig result = %v", res)
				}()
			}
		}
	} ()

	// prepare and shoot the real work
	for txinidx, txin := range tx.MsgTx().TxIn {
		if txin.IsSeparator() {
			continue
		}
		if tx.MsgTx().SignatureScripts[txin.SignatureIndex] == nil {		// no signature
			return omega.ScriptError(omega.ErrInternal, "Signature script does not exist.")
		}

		// get utxo
		utxo := views.Utxo.LookupEntry(txin.PreviousOutPoint)

		if utxo == nil {
			return omega.ScriptError(omega.ErrInternal, "UTXO does not exist.")
		}

		ovm.GetCurrentOutput = func() (wire.OutPoint, *wire.TxOut) {
			return txin.PreviousOutPoint, utxo.ToTxOut()
		}

		version, addr, method, excode := parsePkScript(utxo.PkScript())

		if addr == nil {
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}

		if zeroaddr(addr) || isContract(version) { // zero address, sys call
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}

		// check if it is monitored
		if utxo.TokenType == 3 {
			y := validate.TokenRights(views, utxo)

			for _, r := range y {
				e, _ := views.Rights.FetchEntry(views.Db, &r)
				if e.(*viewpoint.RightEntry).Attrib & token.Monitored != 0 {
					// all the way up to the right without Monitored flag, on the way find out all IsMonitorCall
					re := e.(*viewpoint.RightEntry)
					monitoreds := make([]*viewpoint.RightEntry, 0)
					for re != nil && re.Attrib & token.Monitored != 0 {
						if re.Attrib & token.IsMonitorCall != 0 {
							monitoreds = append(monitoreds, re)
						}
						if re.Father.IsEqual(&chainhash.Hash{}) {
							re = nil
						} else {
							te, _ := views.Rights.FetchEntry(views.Db, &re.Father)
							re = te.(*viewpoint.RightEntry)
						}
					}

					for _, re := range monitoreds {
						monitored := re.Desc

						// a token may subject to multiple monitoring, each could have multiple condition,
						// the Tx must pass all

						// check if it is under monitoring
						// 1. find the contract
						// 2. find owner of the contract
						// 3. find polygon utxo under the owner for this polygon
						// 4. if found, plan the contract call
						var d Address
						copy(d[:], monitored[1:21])

						existence := true

						if _, ok := ovm.StateDB[d]; !ok {
							t := NewStateDB(ovm.views.Db, d)

							existence = t.Exists(true)
							if !existence {
								continue
							}
							ovm.StateDB[d] = t
						}
						if existence {
							owner := ovm.StateDB[d].GetOwner()
							m := views.FindMonitor(owner[:], utxo.Amount.(*token.HashToken).Hash) // a utxo entry
							if m == nil {
								continue
							}
							code := make([]byte, 24)

							copy(code[:], monitored[21:25])
							copy(code[4:], addr)

							y := validate.TokenRights(views, m)

							// do check only if the sibling right of the monitored right is present
							param := make([]byte, 0, 100)
							s := re.Sibling()
							docheck := false
							for _, r := range y {
								if s.IsEqual(&r) {
									docheck = true
								} else {
									e, _ := views.Rights.FetchEntry(views.Db, &r)
									param = append(param, e.(*viewpoint.RightEntry).Desc...)
								}
							}

							if docheck {
								queue <- tbv{txinidx, param, code}
							}
						}
					}
				}
			}
		}

		pkslen := len(utxo.PkScript())
		code := make([]byte,  pkslen - 1)

		copy(code[:], method)
		copy(code[4:], addr)
		copy(code[4 + len(addr):], excode)

		atomic.AddInt32(&toverify, 1)

		if txinidx == len(tx.MsgTx().TxIn) - 1 {
			allrun = true
		}

		queue <- tbv { txinidx, tx.MsgTx().SignatureScripts[txin.SignatureIndex], code }
	}

	close(queue)

	res := <- final
	if !res {
		return omega.ScriptError(omega.ErrInternal, "Signature incorrect.")
	}

	return nil
}

func isContract(netid byte) bool {
	return netid & 0x88 == 0x88
}

func GetHash(d uint64) *chainhash.Hash {
	var w bytes.Buffer
	err := common.BinarySerializer.PutUint64(&w, common.LittleEndian, d)
	if err != nil {
		return &chainhash.Hash{}
	}
	h, _ := chainhash.NewHash(chainhash.DoubleHashB(w.Bytes()))
	return h
}

func (ovm * OVM) ExecContract(tx *btcutil.Tx, txHeight int32, chainParams *chaincfg.Params) error {
	// no need to make a copy of tx, if exec fails, the tx (even a block) will be abandoned
	if tx.IsCoinBase() {
		return nil
	}

	ovm.GetTx = func () * btcutil.Tx { return tx }
	ovm.AddTxOutput = func(t wire.TxOut) bool {
		if isContract(t.PkScript[0]) {
			// can't add a contract call txout within a contract execution
			// it must be done by Exec instruction
			return false
		}
		tx.AddTxOut(t)
		return true
	}
	ovm.Spend = func(t wire.OutPoint) bool {
		tx.AddTxIn(t)
		return true
	}
	ovm.AddRight = func(t *token.RightDef) bool {
		tx.AddDef(t)
		return true
	}
	ovm.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut {
		op := make(map[wire.OutPoint]struct{})
		p := wire.OutPoint{hash,uint32(seq)}
		op[p] = struct{}{}
		if ovm.views.Utxo.FetchUtxosMain(ovm.views.Db, op) != nil {
			return nil
		}
		e := ovm.views.Utxo.LookupEntry(p)
		return e.ToTxOut()
	}
	ovm.BlockNumber = func() uint64 { return uint64(txHeight) }

	ovm.NoLoop = false
	ovm.interpreter.readOnly = false

	// do some validation w/o execution
	for _, txOut := range tx.MsgTx().TxOut {
		version, addr, method, _ := parsePkScript(txOut.PkScript)

		if addr == nil {
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}
		if zeroaddr(addr) {
			return omega.ScriptError(omega.ErrInternal, "Incorrect pkScript format.")
		}
		if !isContract(version) {
			continue
		}

		var d Address
		copy(d[:], addr)

		creation := bytes.Compare(method, []byte{0,0,0,0}) == 0

		if _,ok := ovm.StateDB[d]; !ok {
			t := NewStateDB(ovm.views.Db, d)

			if !t.Exists(true) && !creation {
				return omega.ScriptError(omega.ErrInternal, "Contract does not exist.")
			}
			if t.Exists(false) && creation {
				return omega.ScriptError(omega.ErrInternal, "Attempt to recreate a contract.")
			}

			ovm.StateDB[d] = t
		} else if creation {
			return omega.ScriptError(omega.ErrInternal, "Attempt to recreate a contract.")
		}
	}

	savedTx := *tx.MsgTx().Copy()
	haves := []bool {tx.HasDefs, tx.HasIns, tx.HasOuts}
	end := len(tx.MsgTx().TxOut)
	hash := *tx.Hash()

	for i, txOut := range tx.MsgTx().TxOut {
		if i >= end {
			continue
		}
		ovm.GetCurrentOutput = func() (wire.OutPoint, *wire.TxOut) {
			return wire.OutPoint{hash, uint32(i) }, txOut
		}

		version, addr, method, param := parsePkScript(txOut.PkScript)

		if !isContract(version) {
			continue
		}

		var d Address
		copy(d[:], addr)

		_, err := ovm.Call(d, method, &txOut.Token, param)

		if err != nil {
			// if fail, ovm.Call should have restored ovm.stateDB[d]
			// we need to restore Tx
			tx.HasDefs = haves[0]
			tx.HasIns = haves[1]
			tx.HasOuts = haves[2]
			*tx.MsgTx() = savedTx
			return err
		}
	}

	return nil
}

var byteOrder = binary.LittleEndian

func DbPutNextTokenType(dbTx database.Tx, v uint64) error {
	r := DbFetchNextTokenType(dbTx)

	r[v & 0x3] = v

	var serialized [32]byte
	for i := 0; i < 4; i++ {
		byteOrder.PutUint64(serialized[8 * i:], r[i])
	}
	return dbTx.Metadata().Put(IssuableTokenType, serialized[:])
}

func DbFetchNextTokenType(dbTx database.Tx) [4]uint64 {
	var r [4]uint64
	serialized := dbTx.Metadata().Get(IssuableTokenType)
	if serialized == nil {
		return r
	}

	r[0] = byteOrder.Uint64(serialized[:])
	r[1] = byteOrder.Uint64(serialized[8:])
	r[2] = byteOrder.Uint64(serialized[16:])
	r[3] = byteOrder.Uint64(serialized[24:])

	return r
}

func DbFetchVersion(dbTx database.Tx, key []byte) uint64 {
	serialized := dbTx.Metadata().Get(key)
	if serialized == nil {
		return 0
	}

	return byteOrder.Uint64(serialized[:])
}

func DbPutVersion(dbTx database.Tx, key []byte, version uint64) error {
	var serialized [8]byte
	byteOrder.PutUint64(serialized[:], version)
	return dbTx.Metadata().Put(key, serialized[:])
}
