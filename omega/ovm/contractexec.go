// Copyright (c) 2019 The Omega developers
// Use of this source code is governed by an license that can
// be found in the LICENSE file.

package ovm

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
	"github.com/btcsuite/btcd/txscript/txsparser"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcd/database"
	"bytes"
	"time"
	"encoding/json"
	"encoding/binary"
)

func zeroaddr(addr []byte) bool {
	for _,t := range addr {
		if t != 0 {
			return false
		}
	}
	return true
}

type contractCreation struct {
	Code 	[]byte			 `json:"code"`
	Owner	string			 `json:"owner"`
	Mint	uint64			 `json:"mint"`
	Rights	* chainhash.Hash	 `json:"right"`
}

func (t * contractCreation) serialize() ([]byte, error) {
	var w bytes.Buffer

	if _,err := w.Write(t.Code); err != nil {
		return nil, err
	}
	if _,err := w.WriteString(t.Owner); err != nil {
		return nil, err
	}

	if err := common.WriteElement(&w, t.Mint); err != nil {
		return nil, err
	}

	if t.Rights != nil {
		if _,err := w.Write((*t.Rights)[:]); err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

type WalletItem struct {
	Outpoint	wire.OutPoint		 `json:"outpoint"`
	// whether the item is a collateral (only return to sender upon contract destruction or destruction of coin)
	Worth	uint64					 `json:"worth"`
}

func parsePkScript(script []byte) ([]byte, []byte) {
	var addr [20]byte

	if len(script) < 24 {
		return nil, nil
	}

	return addr[:], script[20:]
}

func VerifySigs(tx *btcutil.Tx, txHeight int32, ovm * OVM, chainParams *chaincfg.Params) error {
	if tx.IsCoinBase() {
		return nil
	}

	ovm.GetTxTemplate = func () * wire.MsgTx {	return nil	}
	ovm.Spend = func(t token.Token) bool { return false }
	ovm.AddTxOutput = func(t wire.TxOut) bool { return false	}
	ovm.SubmitTx = func() chainhash.Hash { return chainhash.Hash{} }
	ovm.GetHash = func(d uint64) *chainhash.Hash { return nil }
	ovm.BlockNumber = func() uint64 { return uint64(txHeight) }
	now := time.Now()
	ovm.Time        = func() time.Time { return now }

	db := ovm.StateDB[Address{}].DB
	views := viewpoint.NewViewPointSet(&db)

	req := map[wire.OutPoint]struct{}{}
	for _, txin := range tx.MsgTx().TxIn {
		req[txin.PreviousOutPoint] = struct{}{}
	}
	views.Utxo.FetchUtxosMain(db, req)

	for i, txin := range tx.MsgTx().TxIn {
		if i >= len(tx.MsgTx().TxIn)-int(tx.MsgTx().ContractIns) {
			continue
		}

		// get utxo
		utxo := views.Utxo.LookupEntry(txin.PreviousOutPoint)

		if utxo == nil {
			return txsparser.ScriptError(txsparser.ErrInternal, "UTXO does not exist.")
		}

		addr, _ := parsePkScript(utxo.PkScript())

		if addr == nil {
			return txsparser.ScriptError(txsparser.ErrInternal, "Incorrect pkScript format.")
		}

		if zeroaddr(addr) || isContract(addr) { // zero address, sys call
			return txsparser.ScriptError(txsparser.ErrInternal, "Incorrect pkScript format.")
		}

		_, err := syscall(nil, append(utxo.PkScript(), txin.SignatureScript[:]...))

		if err != nil {
			return err
		}
	}

	return nil
}

func ExecContract(tx *btcutil.Tx, txHeight int32, ovm * OVM, chainParams *chaincfg.Params) (*btcutil.Tx, uint64, error) {
	if tx.IsCoinBase() {
		return tx, 0, nil
	}

	// Scan outputs.and execute them?
	outtx := tx.Copy()
	var spend []token.Token
	var spendPoint []token.Token

	submitting := (*wire.MsgTx)(nil)

	ovm.GetTxTemplate = func () * wire.MsgTx {
		return outtx.MsgTx()
	}

	ovm.Spend = func(t token.Token) bool {
		spend = append(spend, t)	// record it, handle later
		return true	// should check whether we have enough of it
	}

	ovm.AddTxOutput = func(t wire.TxOut) bool {
		outtx.MsgTx().AddContractTxOut(&t)
		return true
	}
	ovm.SubmitTx = func() chainhash.Hash {
		submitting := &wire.MsgTx{}
		*submitting = * outtx.MsgTx()
		spendPoint = make([]token.Token, len(spend))
		for i,t := range spend {
			spendPoint[i] = t
		}
		return submitting.TxHash()
	}

	ovm.GetHash = func(d uint64) *chainhash.Hash {
		var w bytes.Buffer
		err := common.BinarySerializer.PutUint64(&w, common.LittleEndian, d)
		if err != nil {
			return &chainhash.Hash{}
		}
		h, _ := chainhash.NewHash(chainhash.DoubleHashB(w.Bytes()))
		return h
	}

	ovm.BlockNumber = func() uint64 { return uint64(txHeight) }
	now := time.Now()
	ovm.Time        = func() time.Time { return now }

	steps := uint64(0)

	for i, txOut := range tx.MsgTx().TxOut {
		addr, param := parsePkScript(txOut.PkScript)

		if addr == nil {
			return nil, 0, txsparser.ScriptError(txsparser.ErrInternal, "Incorrect pkScript format.")
		}

		if zeroaddr(addr) {	// zero address, sys call
			_, err := syscall(nil, tx, uint32(i), nil, param)
			if err != nil {
				return nil, 0, err
			}
			continue
		}

		if !isContract(addr) {
			continue
		}

		step, err := ovm.Call(ovm.StateDB[addr], txOut.Token, params)
		// returning steps will be used by other miners to verify the contract call. they will execute exactly
		// that many steps regardless their policy setting.

		if err != nil {
			return nil, 0, err
		}
		steps += step

		var w bytes.Buffer
		common.BinarySerializer.PutUint32(&w, common.LittleEndian, uint32(steps))
		txOut.PkScript = append(txOut.PkScript, w.Bytes()[:]...)

		if spendPoint == nil || len(spendPoint) == 0 {
			continue
		}

		var sig [21]byte
		sig[0] = txsparser.OP_CONTRACTCALL
		copy(sig[1:], contract[:])

		wallet := make(map[uint64][]WalletItem, 0)

		err = ovm.StateDB.DB.View(func(dbTx database.Tx) error {
			// find out necessary spending
			bucket := dbTx.Metadata().Bucket([]byte("contract" + string(contract)))

			if err := json.Unmarshal(bucket.Get([]byte("Wallet")), &wallet); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return nil, 0, err
		}


		used := make(map[uint64]struct{}, 0)
		for _, t := range spendPoint {
			used[t.TokenType] = struct{}{}
		}

		rview := viewpoint.NewViewPointSet(&ovm.StateDB.DB).Rights

		for u,_ := range used {
			if u & 0x2 == 0 {
				// with no right
				need := uint64(0)
				for i, t := range spendPoint {
					if t.TokenType != u {
						continue
					}
					need += uint64(t.Value.(*token.NumToken).Val)
				}
				supply := uint64(0)
				for i,t := range wallet[u] {
					if t.Outpoint.Hash != *(tx.Hash()) {
						outtx.MsgTx().AddContractTxIn(wire.NewTxIn(&t.Outpoint, sig[:], nil))
						supply += t.Worth
					}
				}

				leftover := (*WalletItem)(nil)
				if supply < need {
					return nil, txsparser.ScriptError(txsparser.ErrInternal, "Insufficient fund in wallet.")
				} else if supply > need {
					to := wire.NewTxOut(u, &token.NumToken{Val: int64(supply - need) }, nil, sig[:])
					index := outtx.MsgTx().AddContractTxOut(to)
					leftover = &WalletItem {
						Outpoint:wire.OutPoint{ *tx.Hash(), uint32(index) },
						Worth:supply - need,
						Rights:nil,
					}
				}
				nb := make([]WalletItem, 0)
				for i,t := range wallet[u] {
					if t.Outpoint.Hash == *tx.Hash() {
						nb = append(nb, t)
					}
				}
				if leftover != nil {
					nb = append(nb, *leftover)
				}
				wallet[u] = nb
			} else {
				// with rights
				baseRightset := mkBaseRights(spendPoint, u)
				requirementAnalysis(rview, spendPoint, u, baseRightset)
				used, leftover := matchRequirement(wallet[u], baseRightset)

				for _,d := range used {
					outtx.MsgTx().AddContractTxIn(wire.NewTxIn(&d, sig[:], nil))
out1:
					for i,t := range wallet[u] {
						if t.Outpoint.Hash == d.Hash && t.Outpoint.Index == d.Index {
							wallet[u] = append(wallet[u][:i], wallet[u][i+1:]...)
							break out1
						}
					}
				}

				for _,tok := range leftover {
					to := wire.NewTxOut(u, tok.Value, tok.Rights, sig[:])
					index := outtx.MsgTx().AddContractTxOut(to)
					wallet[u] = append(wallet[u], WalletItem {
						Outpoint:wire.OutPoint{*tx.Hash(), uint32(index) },
						Worth: uint64(tok.Value.(*token.NumToken).Val),
						Rights:to.Rights,
					})
				}
			}
		}

		spendPoint = nil

		err = ovm.StateDB.DB.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("contract" + string(contract)))
			// update account balance (non-commit) in ovm
			r,err := json.Marshal(wallet)
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte("Wallet"), r); err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if submitting != nil {
		*outtx.MsgTx() = *submitting
	}

	return outtx, steps, nil
}

type basePoint struct {
	hash *chainhash.Hash
	amount uint64
}

func mkBaseRights(spendPoint []token.Token, u uint64) *map[chainhash.Hash]uint64 {
	res := make(map[chainhash.Hash]uint64, 0)
	for _,t := range spendPoint {
		if t.TokenType == u {
			for _, r := range t.Rights {
				if _, ok := res[r]; ok {
					res[r] += uint64(t.Value.(*token.NumToken).Val)
				} else {
					res[r] = uint64(t.Value.(*token.NumToken).Val)
				}
			}
		}
	}
	return &res
}

func requirementAnalysis(rview * viewpoint.RightViewpoint, spendPoint []token.Token, u uint64, baseRightset *map[chainhash.Hash]uint64) {

}

func matchRequirement(wallet []WalletItem, baseRightset *map[chainhash.Hash]uint64) ([]wire.OutPoint, []token.Token) {
	return nil,nil
}

type  efunc func(*stateDB, * btcutil.Tx, int) error

var sysFunc []efunc = []efunc {
	deployCode,
	directXfer,
}

func syscall(db *stateDB, fn uint32, tx * btcutil.Tx, seq uint32, param []byte) error {
	if sysFunc[fn] == nil {
		return txsparser.ScriptError(txsparser.ErrInternal, "Incorrect system function id.")
	}
	return sysFunc[fn](db, tx, seq, param)
}

func directXfer(db *stateDB, contract []byte, tx * btcutil.Tx, seq int) error {
	// do contract deployment
	tok := &tx.MsgTx().TxOut[seq].Token

	err := db.DB.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		// for each contract, create 2 buckets: "contract" + <address>, "storage" + <address>
		var err error

		mainbkt := []byte("contract" + string(contract))
		bucket := meta.Bucket(mainbkt)

		key := tok.TokenType
		coins := make(map[uint64][]WalletItem, 0)
		json.Unmarshal(bucket.Get([]byte("Wallet")), &coins)

		if w,ok := coins[key]; ok {
			if len(w) >= 2 {
				for _,c := range w {
					tx.MsgTx().AddTxIn(wire.NewTxIn(&c.Outpoint, []byte{}, [][]byte{}))
				}
			}
		} else {
			coins[key] = append(coins[key], WalletItem{wire.OutPoint{*tx.Hash(), uint32(seq) }, 0, nil} )
		}

		coins[tok.TokenType] = []WalletItem{WalletItem{wire.OutPoint{Hash: *tx.Hash(), Index: uint32(seq) }, 0, nil }}

		md, _ := json.Marshal(coins)

		if err := bucket.Put([]byte("Wallet"[:]), md); err != nil {
			return err
		}

		return nil
	})

	return err
}

func deployCode(db *stateDB, txOut * btcutil.Tx, seq uint32) error {
	// verify validity of paramenters
	tx := txOut.MsgTx().TxOut[seq]
	data := tx.PkScript[21:]

	var creation contractCreation

	if err := json.Unmarshal(data, &creation); err != nil {
		return err
	}

	sz, _ := creation.serialize()
	contract := txscript.Hash160(sz)

	// do contract deployment
	err := db.DB.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		// for each contract, create 2 buckets: "contract" + <address>, "storage" + <address>
		var err error

		mainbkt := []byte("contract" + string(contract))
		if _, err = meta.CreateBucket(mainbkt); err != nil {
			return err
		}

		if _, err = meta.CreateBucket([]byte("storage" + string(contract))); err != nil {
			meta.DeleteBucket([]byte("contract" + string(contract)))
			return err
		}

		collaterals := make(map[uint64][]WalletItem, 0)
		coins := make(map[uint64][]WalletItem, 0)

		worth := int64(0)
		if creation.Collateral || !tx.Token.IsNumeric() {
			worth = int64(creation.Mint)
			collaterals[tx.TokenType] = []WalletItem{WalletItem{wire.OutPoint{Hash: * txOut.Hash(), Index: seq },
				uint64(worth), creation.Rights }}
		} else {
			worth = tx.Value.(*token.NumToken).Val
			coins[tx.TokenType] = []WalletItem{WalletItem{wire.OutPoint{Hash: * txOut.Hash(), Index: seq },
				uint64(worth), tx.Rights }}
		}

		bucket := meta.Bucket(mainbkt)

		if creation.Mint != 0 {
			var key []byte
			var defaultVersion uint64

			if len(creation.Rights) == 0 {
				key = []byte("availNonRightTokenType")
				defaultVersion = 0x1FC
			} else {
				key = []byte("availRightTokenType")
				defaultVersion = 0x1FE
			}

			// the toktype value for numtoken available
			version := uint64(DbFetchVersion(dbTx, key))
			if version == 0 {
				version = defaultVersion
				err := DbPutVersion(dbTx, key, version)
				if err != nil {
					return err
				}
			} else {
				err := DbPutVersion(dbTx, key, version+0x100)
				if err != nil {
					return err
				}
			}

			var serialized [8]byte
			binary.LittleEndian.PutUint64(serialized[:], version)
			if err := bucket.Put([]byte("Currency"), serialized[:]); err != nil {
				return err
			}

			t := token.Token{
				TokenType: version,
				Value:     &token.NumToken{Val: int64(creation.Mint) },
			}
			if version & 2 != 0 {
				t.Rights = creation.Rights
			}

			pkScript := make([]byte, 21)
			pkScript[0] = txsparser.OP_CONTRACTCALL
			copy(pkScript[1:], contract)

			out := wire.NewTxOut(version, &token.NumToken{Val: int64(creation.Mint) }, creation.Rights, pkScript)

			if _, ok := coins[out.TokenType]; ok {
				coins[out.TokenType] = append(coins[out.TokenType], WalletItem{wire.OutPoint{ Hash: * txOut.Hash(), Index: uint32(txOut.MsgTx().AddTxOut(out)) }, creation.Mint, creation.Rights})
			} else {
				coins[out.TokenType] = []WalletItem{WalletItem{wire.OutPoint{Hash: * txOut.Hash(), Index: uint32(txOut.MsgTx().AddTxOut(out)) },
					creation.Mint, creation.Rights }}
			}
		}

		md,_ := json.Marshal(creation.Abi)

		if err := bucket.Put([]byte("Abi"), md); err != nil {
			return err
		}
		if err := bucket.Put([]byte("Code"), creation.Code); err != nil {
			return err
		}
		if err := bucket.Put([]byte("Owner"), []byte(creation.Owner)); err != nil {
			return err
		}
		col := byte(0)
		if creation.Collateral {
			col = 1
		}
		if err := bucket.Put([]byte("AllowNewIssue"), []byte{col}); err != nil {
			return err
		}
		md, _ = json.Marshal(coins)
		if err := bucket.Put([]byte("Wallet"), md); err != nil {
			return err
		}
		if len(collaterals) > 0 {
			md, _ = json.Marshal(collaterals)
			if err := bucket.Put([]byte("Collaterals"), md); err != nil {
				return err
			}
		}

		return nil
	})

	return err
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
