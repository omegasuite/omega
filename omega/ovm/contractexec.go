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
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/chaincfg"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcutil"
	"github.com/omegasuite/famofchains/omega"
	"github.com/omegasuite/famofchains/omega/token"
	"github.com/omegasuite/famofchains/omega/validate"
	"github.com/omegasuite/famofchains/omega/viewpoint"
	"sync"
	"sync/atomic"
)

func zeroaddr(addr []byte) bool {
	for _, t := range addr {
		if t != 0 {
			return false
		}
	}
	return true
}

func parsePkScript(script []byte) (byte, []byte, []byte, []byte) {
	if len(script) < 21 {
		return 0, nil, nil, nil
	}
	if len(script) < 25 {
		if script[0] == 0x88 {
			return script[0], script[1:21], script[21:], script[21:]
		}
		var method [4]byte
		copy(method[:], script[21:])
		return script[0], script[1:21], method[:], script[21:]
	}

	return script[0], script[1:21], script[21:25], script[21:]
}

type tbv struct {
	txinidx   int
	outpoint  wire.OutPoint
	sigScript []byte
	pkScript  []byte
}

// there are 2 sig verify methods: one in interpreter, one is here. the differernce is that
// the one in interpreter is intended for client side. here is for the miner. here, verification
// is deeper in that it checks monitering status, a tx will be rejected if monitor checing fails
// while it may pass interpreter verification because only signature verification is done there

// sig verification includes all pk script type, e.g. multi sig, pkscripthash

var e error

func VerifySigs(tx *btcutil.Tx, param *chaincfg.Params, skip int, views *viewpoint.ViewPointSet) omega.Err {
	if tx.IsCoinBase() {
		return nil
	}
	if tx.MsgTx().IsForfeit() {
		return nil
	}

	nsigs := uint32(len(tx.MsgTx().SignatureScripts))
	for _, tin := range tx.MsgTx().TxIn[skip:] {
		if tin.IsSeparator() {
			break
		}
		if tin.IsSepadding() {
			continue
		}

		if tin.SignatureIndex >= nsigs || tx.MsgTx().SignatureScripts[tin.SignatureIndex] == nil { // no signature
			return omega.ScriptError(omega.ErrInternal, "Signature script does not exist.")
		}
	}

	if nsigs == 0 {
		return nil
	}

	// set up for concurrent execution
	verifiers := make(chan bool, param.SigVeriConcurrency)
	queue := make(chan tbv, param.SigVeriConcurrency)
	final := make(chan bool, 2)

	defer func() {
		//		close(verifiers)
	}()

	allrun := false

	for i := 0; i < param.SigVeriConcurrency; i++ {
		verifiers <- true
	}

	var toverify int32
	finalized := false
	mtx := sync.Mutex{}

	go func() {
		for {
			select {
			case code, more := <-queue:
				if !more {
					if !finalized && len(verifiers) == param.SigVeriConcurrency {
						final <- true
					}
					return
				}
				if finalized {
					continue
				}
				<-verifiers
				go func() {
					ovm := NewSigVM(param)
					ovm.SetViewPoint(views)
					ovm.Init(tx, views)
					ovm.GetCoinBase = func() *btcutil.Tx { return nil }
					ovm.Spend = func(t wire.OutPoint, _ []byte) bool { return false }
					ovm.AddTxOutput = func(t wire.TxOut) int { return -1 }
					ovm.BlockNumber = func() uint64 { return 0 } // uint64(txHeight) }
					ovm.BlockTime = func() uint32 { return 0 }
					ovm.BlockVersion = func() uint32 { return wire.CodeVersion }

					//					ovm.Block = func() *btcutil.Block { return nil }
					ovm.AddDef = func(t token.Definition, coinbase bool) chainhash.Hash { return chainhash.Hash{} }
					ovm.NoLoop = true
					//					ovm.interpreter.readOnly = true

					ovm.GetCurrentOutput = func() wire.OutPoint {
						return code.outpoint
					}

					res := ovm.Interpreter().verifySig(code.txinidx, code.pkScript, code.sigScript)

					mtx.Lock()
					defer mtx.Unlock()

					if finalized {
						return
					}
					verifiers <- true
					if res {
						if allrun && atomic.LoadInt32(&toverify) == 1 {
							final <- true
						}
						atomic.AddInt32(&toverify, -1)
					} else {
						final <- false
						finalized = true
					}
					//					log.Infof("verifySig result = %v", res)
				}()
			}
		}
	}()

	type shared struct {
		sign []byte
		skip byte
	}
	sharedSigs := make(map[uint32]*shared)

	// prepare and shoot the real work
	for txinidx, txin := range tx.MsgTx().TxIn[skip:] {
		if txin.IsSeparator() { // never
			break
		}
		if txin.IsSepadding() {
			continue
		}

		tinidx := txinidx + skip

		// get utxo
		utxo := views.Utxo.LookupEntry(txin.PreviousOutPoint)

		if utxo == nil {
			final <- false
			break
		}

		version, addr, method, excode := parsePkScript(utxo.PkScript())

		if addr == nil {
			final <- false
			break
		}

		if zeroaddr(addr) || isContract(version) { // zero address, sys call
			final <- false
			break
		}

		if method[0] == OP_PAY2ANY {
			continue
		}
		if method[0] == OP_PAY2NONE {
			final <- false
			break
		}
		if version == param.PubKeyHashAddrID && method[0] == OP_PAY2PKH && txin.SignatureIndex == 0xFFFFFFFF {
			final <- false
			break
		}
		if txin.SignatureIndex == 0xFFFFFFFF {
			continue
		}
		if txin.SignatureIndex >= uint32(len(tx.MsgTx().SignatureScripts)) ||
			len(tx.MsgTx().SignatureScripts[txin.SignatureIndex]) < btcec.MinSigLen {
			final <- false
			break
		}

		// check if it is monitored
		if utxo.TokenType == 3 {
			y := validate.TokenRights(views, utxo)

			for _, r := range y {
				e, _ := views.FetchRightEntry(&r)
				if e.(*viewpoint.RightEntry).Attrib&token.Monitored != 0 {
					// all the way up to the right without Monitored flag, on the way find out all IsMonitorCall
					re := e.(*viewpoint.RightEntry)

					monitoreds := make([]*viewpoint.RightEntry, 0)
					for re != nil && re.Attrib&token.Monitored != 0 {
						if re.Attrib&token.IsMonitorCall != 0 {
							monitoreds = append(monitoreds, re)
						}
						if re.Father.IsEqual(&chainhash.Hash{}) {
							re = nil
						} else {
							te, _ := views.FetchRightEntry(&re.Father)
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

						if t := NewStateDB(views.Db, d); !t.Exists(true) {
							continue
						}

						owner := re.Desc[1:21]
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
								e, _ := views.FetchRightEntry(&r)
								param = append(param, e.(*viewpoint.RightEntry).Desc...)
							}
						}

						if docheck {
							queue <- tbv{tinidx, txin.PreviousOutPoint, param, code}
						}
					}
				}
			}
		}

		pkslen := len(utxo.PkScript())
		if pkslen < 25 {
			pkslen = 25
		}
		code := make([]byte, pkslen-1)

		copy(code[:], method)
		copy(code[4:], addr)

		if len(excode) > 4 {
			copy(code[4+len(addr):], excode[4:])
		}

		if pks, ok := sharedSigs[txin.SignatureIndex]; ok {
			switch pks.skip {
			case 2:
				continue
			case 0:
				if bytes.Compare(pks.sign, utxo.PkScript()) == 0 {
					// examine pks to see if we can skip it
					sig := tx.MsgTx().SignatureScripts[txin.SignatureIndex]
					pks.skip = 2
					for idx := 0; idx < len(sig); idx++ {
						switch OpCode(sig[idx]) {
						case PUSH:
							idx++
							idx += int(sig[idx])

						case SIGNTEXT:
							idx++
							si := SigHashType(sig[idx])
							if (si&SigHashMask) != SigHashAll || (si&SigHashAnyOneCanPay) != 0 {
								// these sign text are not idx independent, can not assume
								// these signatures would be the same
								pks.skip = 1
								break
							}

						default: // never
							pks.skip = 1
							break
						}
					}
					if pks.skip == 2 {
						continue
					}
				}
			}
		} else {
			sharedSigs[txin.SignatureIndex] = &shared{
				sign: utxo.PkScript(),
				skip: 0,
			}
		}

		if finalized {
			break
		}

		atomic.AddInt32(&toverify, 1)

		queue <- tbv{tinidx, txin.PreviousOutPoint, tx.MsgTx().SignatureScripts[txin.SignatureIndex], code}
	}

	allrun = true
	close(queue)

	res := <-final
	if !res {
		return omega.ScriptError(omega.ErrInternal, "Signature incorrect.")
	}

	return nil
}

func isContract(netid byte) bool {
	return netid == 0x88
}

var byteOrder = binary.LittleEndian

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
