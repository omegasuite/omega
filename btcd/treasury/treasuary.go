// Copyright (c) 2024-2024 The Omegasuite developers
// Use of this source code is governed by applicable
// patent laws.

package treasury

import (
	"bytes"
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"github.com/omegasuite/famofchains/btcutil"

	"github.com/omegasuite/famofchains/btcd/chaincfg"
	"github.com/omegasuite/famofchains/btcd/txscript"
)

// here we record all assets trusted to us in BTC including those in collateral
type RPC interface {
	DoSendRawTransaction(tx *btcutil.Tx) (interface{}, error)
}

var Rpc RPC
var BTCParams *chaincfg.Params
var ActiveNetParams *chaincfg.Params

const (
	BITCOIN   = string("Bitcoin")
	OMNI      = string("Omni")
	BRC20     = string("BRC20")
	SRC20     = string("SRC20")
	feepolicy = int64(40)
)

type AssetType struct {
	Protocol string
	AssetID  uint32
}

func (t *AssetType) serialize() []byte {
	res := make([]byte, 4, 10)
	common.LittleEndian.PutUint32(res, t.AssetID)
	res = append(res, []byte(t.Protocol)...)
	return res
}

func (t *AssetType) deserialize(d []byte) (int, error) {
	t.AssetID = common.LittleEndian.Uint32(d)
	t.Protocol = string(d[4:])
	return len(d), nil
}

var typemap map[AssetType]uint64

var maptype map[uint64]AssetType

type Asset struct {
	Typeid   uint64 // type id in L2
	Amount   uint64 //
	Outpoint wire.OutPoint
	Owners   [][20]byte // signatures required
	Pkscript []byte
}

func (p *Asset) serialize() []byte {
	res := make([]byte, 56)

	common.LittleEndian.PutUint64(res[0:], p.Typeid)
	common.LittleEndian.PutUint64(res[8:], p.Amount)
	copy(res[16:], p.Outpoint.Hash[:])
	common.LittleEndian.PutUint32(res[48:], p.Outpoint.Index)

	common.LittleEndian.PutUint16(res[52:], uint16(len(p.Owners)*20))
	common.LittleEndian.PutUint16(res[54:], uint16(len(p.Pkscript)))

	for _, own := range p.Owners {
		res = append(res, own[:]...)
	}

	res = append(res, p.Pkscript...)

	return res
}

func (p *Asset) Deserialize(d []byte) (int, error) {
	if len(d) < 76 {
		return 0, fmt.Errorf("Insufficient asset data")
	}
	p.Typeid = common.LittleEndian.Uint64(d[0:])
	p.Amount = common.LittleEndian.Uint64(d[8:])
	copy(p.Outpoint.Hash[:], d[16:])
	p.Outpoint.Index = common.LittleEndian.Uint32(d[48:])

	n := common.LittleEndian.Uint16(d[52:])
	m := common.LittleEndian.Uint16(d[54:])
	k := 56

	if n == 0 {
		p.Owners = nil
	} else {
		p.Owners = make([][20]byte, n/20)
		for i, _ := range p.Owners {
			copy(p.Owners[i][:], d[k:])
			k += 20
		}
	}
	p.Pkscript = make([]byte, m)
	copy(p.Pkscript, d[k:])

	return k + int(m), nil
}

type server interface {
	SolicitSigs(tx *wire.MsgTx, hash *chainhash.Hash, height uint32)
	GetTxBlock(h int32) *btcutil.Block
}

var treasury map[wire.OutPoint]*Asset
var signers map[[20]byte]*Signers
var mydb database.DB
var totalOmg uint64
var collaterals *wire.Collaterals
var eldest *Signers
var Server server

func BtcIncome(haos uint64) {
	sum := uint64(0)
	last := (*Signers)(nil)
	for _, s := range signers {
		if s.Retiring {
			continue
		}
		t := haos * (uint64(s.Voting)) / 100
		if t > haos-sum {
			t = haos - sum
		}
		s.Btcprofit += t
		sum += t
		last = s
	}
	if haos > sum {
		last.Btcprofit += haos - sum
	}
}

func BtcSpend(haos uint64) {
	sum := uint64(0)
	last := (*Signers)(nil)
	for _, s := range signers {
		if s.Retiring {
			continue
		}
		t := haos * (uint64(s.Voting)) / 100
		if t > haos-sum {
			t = haos - sum
		}
		s.Btcprofit -= t
		sum += t
		last = s
	}
	if haos > sum {
		last.Btcprofit -= haos - sum
	}
}

func InTreasury(p *wire.OutPoint) bool {
	outp := wire.OutPoint{Index: p.Index}
	copy(outp.Hash[:], p.Hash[:])
	if _, ok := treasury[outp]; ok {
		return true
	}
	return false
}

func Boutp2l2outp(in *wire.OutPoint) *wire.OutPoint {
	r := wire.OutPoint{
		Index: in.Index,
	}
	copy(r.Hash[:], in.Hash[:])
	return &r
}

func HasSpend(p *wire.OutPoint) bool {
	r := false
	mydb.Update(func(tx database.Tx) error {
		spendbucket := tx.Metadata().Bucket([]byte(common.BTCSpendlog))
		var key [36]byte
		copy(key[:], p.Hash[:])
		common.LittleEndian.PutUint32(key[32:], p.Index)
		v := spendbucket.Get(key[:])
		if v != nil && len(v) != 0 {
			r = true
		}
		return nil
	})
	return r
}

func Restore(p *wire.OutPoint) {
	mydb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte(common.L2BTCPOOL))
		spendbucket := tx.Metadata().Bucket([]byte(common.BTCSpendlog))
		var key [36]byte
		copy(key[:], p.Hash[:])
		common.LittleEndian.PutUint32(key[32:], p.Index)
		v := spendbucket.Get(key[:])
		if v == nil || len(v) == 0 {
			return nil
		}
		ck := v[:4]

		d := wire.XchainData{}

		val := bucket.Get(ck)
		if val == nil || len(val) == 0 {
			d.Unserialize(v[4:])
			bucket.Put(ck, val)
		} else {
			d.Unserialize(val)
			txo := &wire.MsgXrossL2{}
			txo.UnSerialize(v[4:])
			d.Txs = append(d.Txs, txo)
		}
		item := d.Txs[len(d.Txs)-1]
		Intake(tx, Boutp2l2outp(p), &AssetType{BITCOIN, 0}, uint64(item.Value), item.PkScript)
		return nil
	})
}

func Spend(p *wire.OutPoint) {
	mydb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte(common.L2BTCPOOL))
		spendbucket := tx.Metadata().Bucket([]byte(common.BTCSpendlog))

		cursor := bucket.Cursor()

		for ok := cursor.First(); ok; ok = cursor.Next() {
			if len(cursor.Key()) != 4 {
				continue
			}
			d := wire.XchainData{}
			d.Unserialize(cursor.Value())
			for i, txo := range d.Txs {
				if txo.Utxo.Index == p.Index && bytes.Compare(txo.Utxo.Hash[:], p.Hash[:]) == 0 {
					delete(treasury, *(Boutp2l2outp(&txo.Utxo)))

					var key [36]byte
					copy(key[:], p.Hash[:])
					common.LittleEndian.PutUint32(key[32:], p.Index)

					data := make([]byte, 4)
					copy(data, cursor.Key())

					if len(d.Txs) == 1 {
						data = append(data, cursor.Value()...)
						spendbucket.Put(key[:], data)
						bucket.Delete(cursor.Key())
					} else {
						data = append(data, txo.Serialize()...)
						spendbucket.Put(key[:], data)
						if i == 0 {
							d.Txs = d.Txs[1:]
						} else if i == len(d.Txs)-1 {
							d.Txs = d.Txs[:i]
						} else {
							d.Txs = append(d.Txs[:i], d.Txs[i+1:]...)
						}
						bucket.Put(cursor.Key(), d.Serialize())
					}
					return nil
				}
			}
		}
		return nil
	})
}

func Joined(p *wire.OutPoint) uint32 {
	for _, s := range signers {
		for _, u := range s.Pledged {
			if p.Equal(&u.Utxo) {
				return u.Firstuse
			}
		}
	}
	return 0
}

func Load(db database.DB, coll *wire.Collaterals) error {
	mydb = db
	collaterals = coll
	treasury = make(map[wire.OutPoint]*Asset)

	signers = make(map[[20]byte]*Signers)
	totalOmg = 0
	eldest = nil

	typemap = make(map[AssetType]uint64)

	maptype = make(map[uint64]AssetType)

	return db.Update(func(tx database.Tx) error {
		fmt.Printf("INASSETS\n")

		bucket := tx.Metadata().Bucket([]byte(common.INASSETS))
		cursor := bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			var outp wire.OutPoint
			key := cursor.Key()
			v := cursor.Value()
			if len(key) == 8 {
				// it is typemap
				t := AssetType{}
				t.deserialize(v)
				id := common.LittleEndian.Uint64(key)
				maptype[id] = t
				typemap[t] = id

				fmt.Printf("AssetType: %d => %s\n", t.AssetID, t.Protocol)
				continue
			}
			outp.Hash.SetBytes(key[:32])
			outp.Index = common.LittleEndian.Uint32(key[32:])
			plg := &Asset{}
			_, err := plg.Deserialize(cursor.Value())
			if err != nil {
				return err
			}

			fmt.Printf("Asset: %s => Typeid: %x, Amount: %d, Outpoint: %s, Pkscript: %x, Owners: %d,", outp.String(), plg.Typeid, plg.Amount, plg.Outpoint.String(), plg.Pkscript, len(plg.Owners))
			if len(plg.Owners) > 0 {
				fmt.Printf(" Owners: ")
				for _, p := range plg.Owners {
					fmt.Printf(" %x\n", p)
				}
			}
			fmt.Printf("\n")
			treasury[outp] = plg
		}

		fmt.Printf("BRIDGESIGNERS\n")
		bucket = tx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
		cursor = bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			var addr [20]byte
			copy(addr[:], cursor.Key())

			t := &Signers{}
			copy(t.Address[:], addr[:])
			t.Pledged = make([]*PlgAsset, 0)

			_, err := t.Deserialize(cursor.Value())
			if err != nil {
				bucket.Delete(cursor.Key())
				continue
				//				return err
			}

			fmt.Printf("%x: Address: %x, Joined: %d, Retiring: %d, Voting: %d, Pubkey: %x, pledges： %d\n", addr, t.Address, t.Joined, t.Retiring, t.Voting, t.Pubkey, len(t.Pledged))
			for _, p := range t.Pledged {
				fmt.Printf("Pledged: Utxo: %s Firstuse: %d Amount: %d\n", p.Utxo.String(), p.Firstuse, p.Amount)
			}

			signers[addr] = t

			if !t.Retiring && (eldest == nil || t.Joined < eldest.Joined) {
				eldest = t
			}

			for _, plg := range t.Pledged {
				if !t.Retiring {
					totalOmg += plg.Amount
				}
				collaterals.Add(&plg.Utxo)
			}
		}
		return nil
	})
}

func Intake(tx database.Tx, utxo *wire.OutPoint, typeid *AssetType, amount uint64, script []byte) {
	asset := &Asset{
		Outpoint: wire.OutPoint{
			Index: utxo.Index,
		},
		Amount:   amount,
		Pkscript: script,
	}
	copy(asset.Outpoint.Hash[:], utxo.Hash[:])

	asset.Typeid = uint64(0)
	switch typeid.Protocol {
	case BITCOIN:
		asset.Typeid = 0xFFFFFF0000000000
		typeid.AssetID = 0
		ispledge, _, addresses, _ := matchsigners(script)
		if ispledge {
			return
		}
		asset.Owners = make([][20]byte, len(addresses))
		for i, addr := range addresses {
			copy(asset.Owners[i][:], addr.Address[:])
		}

	case OMNI:
		// check script for assetid
		asset.Typeid = 0xFFFFFF0000000000
	}
	treasury[*utxo] = asset

	bucket := tx.Metadata().Bucket([]byte(common.INASSETS))

	if _, ok := maptype[asset.Typeid]; !ok {
		// it's a new type
		maptype[asset.Typeid] = *typeid
		typemap[*typeid] = asset.Typeid
		var key [8]byte
		common.LittleEndian.PutUint64(key[:], asset.Typeid)
		bucket.Put(key[:], typeid.serialize())
	}
	bucket.Put(utxo.ToBytes(), asset.serialize())
}

func Putout(typeid *AssetType, amount int64) map[wire.OutPoint]uint64 {
	res := make(map[wire.OutPoint]uint64)
	assetid := uint64(0)

	switch typeid.Protocol {
	case BITCOIN:
		assetid = 0xFFFFFF0000000000

	case OMNI:
		// check script for assetid
	}

	// use assest that need Retiring signers to sign
	for utxo, t := range treasury {
		if t.Typeid != assetid {
			continue
		}
		ret := false
		for _, s := range t.Owners {
			u := signers[s]
			if u.Retiring {
				ret = true
				break
			}
		}
		if !ret {
			continue
		}
		amount -= int64(t.Amount)
		res[utxo] = t.Amount
		if amount <= 0 {
			return res
		}
	}

	for utxo, t := range treasury {
		if _, ok := res[utxo]; ok {
			continue
		}
		amount -= int64(t.Amount)
		res[utxo] = t.Amount
		if amount <= 0 {
			return res
		}
	}
	return nil
}

func MayRetire(who [20]byte) bool {
	// a signer is allowed to restire only if he is not
	// involved in any asset in treasury
	for _, t := range treasury {
		for _, s := range t.Owners {
			if bytes.Compare(who[:], s[:]) == 0 {
				return false
			}
		}
	}
	return true
}

func HandleL2BTC(height int32) {
	// a L2 notification call back. called when a L2 block is connected
	mydb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte(common.L2BTCPOOL))
		cursor := bucket.Cursor()

		// for all pending xfers from L2 to BTC, i.e. those in L2BTCPOOL

		for ok := cursor.First(); ok; ok = cursor.Next() {
			if len(cursor.Key()) != 4 {
				continue
			}
			// a pending L2=>BTC tx
			h := int32(common.LittleEndian.Uint32(cursor.Key()))
			if height-h < wire.MINER_RORATE_FREQ*2 {
				// not mature yet
				continue
			}
			d := wire.XchainData{}
			d.Unserialize(cursor.Value())
			if h != d.Height { // must
				continue
			}
			// if it is finalized, make a BTC tx and broadcast it
			btx := wire.NewMsgTx(wire.TxVersion)
			total := int64(0)
			for _, txo := range d.Txs {
				if txo.Value == 0 || bytes.Compare(txo.PkScript[22:25], []byte{0xFF, 0xFF, 0xFF}) != 0 {
					// no value or a xfer to other chains
					continue
				}
				if len(txo.Redeem) == 0 || txo.Redeem[0] == 0 {
					txo.Redeem = []byte{1}
				} else {
					// intentionally allow overflow from 255 to 0
					// prevent making tx repeatedly and yet allow creating a new tx
					// when no confirmation for long time
					txo.Redeem[0]++
					continue
				}
				total += txo.Value
				to := wire.NewTxOut(txo.Value, BtcScriptConvert(txo.PkScript, ActiveNetParams))
				btx.AddTxOut(to)
			}
			if total == 0 {
				continue
			}

			feereq := int64(btx.SerializeSize()) * feepolicy
			sum := total + feereq
			lastpks := ([]byte)(nil)
			for _, s := range treasury {
				if s.Typeid != 0xFFFFFF0000000000 {
					continue
				}
				if sum >= 0 {
					break
				}
				ti := wire.NewTxIn(&s.Outpoint, -1)
				btx.AddTxIn(ti)
				df := int64(ti.SerializeSize()) * feepolicy
				feereq += df
				sum -= int64(s.Amount) - df
				lastpks = s.Pkscript
			}
			/*
				fu, mu, mfu := int64(0), 0, int64(0)
				for i, txo := range btx.TxOut {
					u := feereq * txo.Value / total
					txo.Value -= u
					fu += u
					if u > mfu {
						mfu, mu = u, i
					}
				}
				if feereq > fu {
					btx.TxOut[mu].Value -= mfu
				}
			*/
			if sum < -feepolicy*int64(len(lastpks)+8+40) { // more than 2 txous (MS + PKH) left, claim it
				to := wire.NewTxOut(-sum-feepolicy*int64(len(lastpks)+8), lastpks)
				btx.AddTxOut(to)
			}
			bucket.Put(cursor.Key(), d.Serialize())
			m := &wire.MsgSolicitSigs{
				Tx:     btx,       // the BTC tx
				Height: uint32(h), // the L2 block height for txo sources
				Hash:   d.Hash,    // the L2 block hash for txo sources
			}
			Signtx(m)
		}
		return nil
	})
}

func validateL2Tx(d *wire.XchainData, tx *wire.MsgTx) bool {
	btx := wire.NewMsgTx(wire.TxVersion)
	total := int64(0)
	for _, txo := range d.Txs {
		if txo.Value == 0 || bytes.Compare(txo.PkScript[22:25], []byte{0xFF, 0xFF, 0xFF}) != 0 {
			continue
		}
		total += txo.Value
		to := wire.NewTxOut(txo.Value, BtcScriptConvert(txo.PkScript, ActiveNetParams))
		btx.AddTxOut(to)
	}
	if total == 0 {
		return false
	}

	// Fee Policy is 40 sat/vbyte
	feereq := int64(btx.SerializeSize()) * feepolicy
	sum := total + feereq
	lastpks := ([]byte)(nil)

	for _, txin := range tx.TxIn {
		outp := wire.OutPoint{Index: txin.PreviousOutPoint.Index}
		copy(outp.Hash[:], txin.PreviousOutPoint.Hash[:])
		if t, ok := treasury[outp]; !ok {
			return false
		} else {
			if t.Typeid != 0xFFFFFF0000000000 {
				return false
			}
			df := int64(txin.SerializeSize()) * feepolicy
			feereq += df
			sum -= int64(t.Amount) - df
			lastpks = t.Pkscript
		}
	}

	if sum > 0 {
		return false
	}

	/*
		// spread tx fees among outputs proportional to their amounts
		fu, mu, mfu := int64(0), 0, int64(0)
		for i, txo := range btx.TxOut {
			u := feereq * txo.Value / total
			txo.Value -= u
			fu += u
			if u > mfu {
				mfu, mu = u, i
			}
		}
		// make up discrepency from the largest output
		if feereq > fu {
			btx.TxOut[mu].Value -= mfu
		}
	*/
	if sum < -feepolicy*int64(len(lastpks)+8+40) {
		to := wire.NewTxOut(-sum-feepolicy*int64(len(lastpks)+8), lastpks)
		btx.AddTxOut(to)
	}
	// verify contents of msg.Tx
	if len(tx.TxOut) != len(btx.TxOut) {
		return false
	}
	txob := make(map[int]int)
	for i, txo := range btx.TxOut {
		for j, otx := range tx.TxOut {
			if txo.Value == otx.Value && bytes.Compare(txo.PkScript, otx.PkScript) == 0 {
				if _, ok := txob[j]; !ok {
					txob[j] = i
					break
				}
			}
		}
	}
	if len(tx.TxOut) != len(btx.TxOut) {
		return false
	}
	return true
}

func Signtx(msg *wire.MsgSolicitSigs) {
	l2blk := Server.GetTxBlock(int32(msg.Height))
	if l2blk == nil || !msg.Hash.IsEqual(l2blk.Hash()) {
		// we don't have the block, so broadcast it w/o signing
		Server.SolicitSigs(msg.Tx, &msg.Hash, msg.Height)
		return
	}

	mydb.View(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte(common.L2BTCPOOL))
		var h [4]byte

		copy(h[:], bucket.Get([]byte("ChainHeight")))
		ht := common.LittleEndian.Uint32(h[:])

		if msg.Height+wire.MINER_RORATE_FREQ*2 > ht {
			return nil
		}

		common.LittleEndian.PutUint32(h[:], msg.Height)

		d := common.BTCL2Data{}
		d.Unserialize(bucket.Get(h[:]))

		if !msg.Hash.IsEqual(Bhash2l2hash(d.Hash)) {
			return nil
		}

		if !validateL2Tx(&d, msg.Tx) {
			return nil
		}

		// sign it
		allsigned := true
		for i, txin := range msg.Tx.TxIn {
			outp := wire.OutPoint{Index: txin.PreviousOutPoint.Index}
			copy(outp.Hash[:], txin.PreviousOutPoint.Hash[:])
			asset := treasury[outp]

			r, _, snr, m := matchsigners(asset.Pkscript)
			if !r {
				return nil
			}

			t := enoughSigs(m, txin.SignatureScript)

			switch t {
			case 1:
				continue
			case 0: // need a MS sig
				if signed(msg.Tx, i, int64(asset.Amount), snr, txin.SignatureScript) {
					// already signed the txin
					allsigned = false
					continue
				}

				sig := signing(msg.Tx, i, asset, snr[1:])
				if sig != nil {
					if len(txin.SignatureScript) == 0 {
						txin.SignatureScript = []byte{0}
					}
					txin.SignatureScript = append(txin.SignatureScript, sig...)
				}
				allsigned = allsigned && enoughSigs(m, txin.SignatureScript) == 1
				/*
					case 2: // need eldest sig
						if signed(msg.Tx, i, int64(asset.Amount), snr, txin.SignatureScript) {
							// already signed the txin
							allsigned = false
							continue
						}

						sig := signing(msg.Tx, i, asset, snr[:1])
						if sig != nil {
							txin.SignatureScript = append(txin.SignatureScript, sig...)
						} else {
							allsigned = false
						}
				*/
			}
		}
		if allsigned {
			// all signed, add it to mempool and broadcast it
			btx := btcutil.NewTx(msg.Tx)
			Rpc.DoSendRawTransaction(btx)
		} else {
			Server.SolicitSigs(msg.Tx, &msg.Hash, msg.Height)
		}
		return nil
	})
}

func signing(tx *wire.MsgTx, idx int, input *Asset, snr []*Signers) []byte {
	for _, k := range PrivKeys {
		pubKey := k.PubKey()
		pkc := pubKey.SerializeCompressed()
		pkuc := pubKey.SerializeUncompressed()
		for _, s := range snr {
			if bytes.Compare(s.Pubkey, pkc) == 0 || bytes.Compare(s.Pubkey, pkuc) == 0 {
				sig, err := txscript.RawTxInSignature(tx, idx, input.Pkscript, txscript.SigHashAll, k)
				if err != nil {
					continue
				}
				return sig
			}
		}
	}
	return nil
}

func checkScripts(tx *wire.MsgTx, idx int, inputAmt int64, sigScript, pkScript []byte) bool {
	tx.TxIn[idx].SignatureScript = sigScript
	vm, err := txscript.NewEngine(pkScript, tx, idx,
		txscript.ScriptBip16|txscript.ScriptVerifyDERSignatures, nil, nil, inputAmt, nil)
	if err != nil {
		return false
	}

	err = vm.Execute()
	if err != nil {
		return false
	}

	return true
}

func signed(tx *wire.MsgTx, idx int, inputAmt int64, snr []*Signers, sigs []byte) bool {
	if len(sigs) == 0 {
		return false
	}
	for n := 1; n < len(sigs); {
		p := sigs[n]
		n += int(p) + 1
		sig := sigs[n+1 : n+1+int(p)]
		for _, k := range PrivKeys {
			pubKey := k.PubKey()
			pkc := pubKey.SerializeCompressed()
			for _, s := range snr {
				if bytes.Compare(s.Pubkey, pkc) == 0 {
					pks, _ := txscript.NewScriptBuilder().AddData(s.Pubkey).AddOp(txscript.OP_CHECKSIG).Script()
					valid := checkScripts(tx, idx, inputAmt, sig, pks)
					if valid {
						return true
					}
				}
			}
		}
	}
	return false
}

func enoughSigs(m byte, sig []byte) int {
	if len(sig) == 0 {
		return 0
	}
	if sig[0] != 0 {
		return -1
	}

	p := 1
	for m > 0 && len(sig) > p+btcec.PubKeyBytesLenCompressed+btcec.MinSigLen+2 {
		if sig[p] == btcec.PubKeyBytesLenCompressed {
			p += btcec.PubKeyBytesLenCompressed + 1
		} else {
			return -1
		}
		sl := sig[p]
		if len(sig) < p+int(sl)+1 {
			return -1
		}
		p += int(sl) + 1
		m--
	}
	if m == 0 {
		return 1
	}

	return 0
}

func BtcScriptConvert(script []byte, params *chaincfg.Params) []byte {
	builder := txscript.NewScriptBuilder()
	switch script[0] {
	case params.PubKeyHashAddrID:
		builder.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).AddData(script[1:21]).
			AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)

	case params.ScriptHashAddrID:
		builder.AddOp(txscript.OP_HASH160).AddData(script[1:21]).
			AddOp(txscript.OP_EQUAL)
	}
	r, _ := builder.Script()
	return r
}

func ScriptConvert(script []byte) []byte {
	// convert a BTC pk script to L2 pk script
	m := Matching(script)

	switch m {
	case 0: // BTC => L2
		res := []byte{ActiveNetParams.PubKeyHashAddrID}
		ln := len(script)
		res = append(res, script[ln-34:ln-14]...)
		res = append(res, []byte{0x41, 0, 0, 0}...)
		return res

	case 1: // Omni
		return nil
	case 2: // BRC
		return nil
	case 3: // SRC
		return nil
	case 10: // Pledge
		return nil
	}

	return nil
}
