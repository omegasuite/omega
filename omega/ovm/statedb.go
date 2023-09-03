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
	"errors"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	//	"encoding/json"
	//	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/omega"
	//	"github.com/omegasuite/omega/token"
	//	"github.com/omegasuite/omega/viewpoint"
	//	"math/big"
)

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.

type status uint8

// state Data entry. contract managed
type entry struct {
	olddata []byte
	data []byte
}

type dataMap map[string]*entry

type stateDB struct {
	// stateDB gives access to the underlying state (storage) of current account
	DB database.DB

	// contract address of current account
	contract [20]byte

	// contract state Data cache
	data dataMap
	meta dataMap

	// Suicide flag
	suicided bool

	// fresh flag. indicating this is a newly created contract
	fresh bool

	// only used in destruct, indicate whether to transfer mint
	transferrable bool

	// what are added to a tx as contract output
	spendables map[wire.OutPoint]struct{}
}

func NewStateDB(db database.DB, addr [20]byte) *stateDB {
	return &stateDB{
		DB:         db,
		contract:   addr,
		fresh:      false,
		data:       make(map[string]*entry),
		meta:       make(map[string]*entry),
		spendables: make(map[wire.OutPoint]struct{}),
	}
}

func (d *stateDB) Suicide() {
	d.data = make(map[string]*entry)
	d.meta = make(map[string]*entry)
	d.suicided = true
}

func (v *OVM) setMeta(contract [20]byte, key string, code []byte) {
	d := v.StateDB[contract]

	if d.suicided {
		return
	}

	if _, ok := d.meta[key]; !ok {
		m := d.GetMeta(key)
		t := make([]byte, len(code))
		copy(t, code)
		d.meta[key] = &entry{m, t}
	} else {
		if d.meta[key].data == nil {
			d.meta[key].data = make([]byte, len(code))
		}
		copy(d.meta[key].data, code)
		if len(d.meta[key].data) < len(code) {
			d.meta[key].data = append(d.meta[key].data, code[len(d.meta[key].data):]...)
		} else if len(d.meta[key].data) > len(code) {
			d.meta[key].data = d.meta[key].data[:len(code)]
		}
	}
}

func (v * OVM) GetMeta(contract [20]byte, key string) []byte {
	d := v.StateDB[contract]
	if d.suicided {
		return nil
	}

	if t, ok := d.meta[key]; ok {
		return t.data
	}

	m := d.GetMeta(key)
	if m == nil {
		if key == "creator" {
			// generate creator
			code := v.GetMeta(contract, "code")
			var txh chainhash.Hash
			copy(txh[:], code[:32])

			// fetch raw tx
			var creator [21]byte

			v.DB.View(func(dbTx database.Tx) error {
				blockRegion, _ := dbFetchTxIndexEntry(dbTx, &txh)
				txBytes, _ := dbTx.FetchBlockRegion(blockRegion)

				var msgTx wire.MsgTx
				msgTx.Deserialize(bytes.NewReader(txBytes))

				blockRegion, _ = dbFetchTxIndexEntry(dbTx, &msgTx.TxIn[0].PreviousOutPoint.Hash)
				txBytes, _ = dbTx.FetchBlockRegion(blockRegion)

				var msgTxprev wire.MsgTx
				msgTxprev.Deserialize(bytes.NewReader(txBytes))

				txo := msgTxprev.TxOut[msgTx.TxIn[0].PreviousOutPoint.Index]
				copy(creator[:], txo.PkScript[:21])

				return nil
			})
			m = creator[:]
		} else {
			return nil
		}
	}

	t := make([]byte, len(m))
	copy(t, m)
	d.meta[key] = &entry {m,  t}

	return t
}

func (v * OVM) NewUage(contract [20]byte) int32 {
	d := v.StateDB[contract]

	if d.suicided {
		return 0
	}

	return d.NewUage()
}

func (d *stateDB) NewUage() int32 {
	key := "quota"
	if k,ok := d.meta[key]; !ok {
		return 0
	} else {
		q := int32(binary.LittleEndian.Uint32(k.data))
		if k.olddata == nil {
			return q
		}
		p := int32(binary.LittleEndian.Uint32(k.olddata))
		return q - p
	}
}

func (d *stateDB) GetMeta(key string) []byte {
	if d.suicided || d.fresh {
		return nil
	}

	var code []byte
	d.DB.View(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))
		if bucket == nil {
			return nil
		}
		code = bucket.Get([]byte(key))
		return nil
	})
	return code
}

func dbFetchBlockHashBySerializedID(dbTx database.Tx, serializedID []byte) (*chainhash.Hash, error) {
	hashByIDIndexBucketName := []byte("hashbyididx")
	errNoBlockIDEntry := errors.New("no entry in the block ID index")

	idIndex := dbTx.Metadata().Bucket(hashByIDIndexBucketName)
	hashBytes := idIndex.Get(serializedID)
	if hashBytes == nil {
		return nil, errNoBlockIDEntry
	}

	var hash chainhash.Hash
	copy(hash[:], hashBytes)
	return &hash, nil
}

func dbFetchTxIndexEntry(dbTx database.Tx, txHash *chainhash.Hash) (*database.BlockRegion, error) {
	// Load the record from the database and return now if it doesn't exist.
	txIndexKey := []byte("txbyhashidx")

	txIndex := dbTx.Metadata().Bucket(txIndexKey)
	serializedData := txIndex.Get(txHash[:])
	if len(serializedData) == 0 {
		return nil, nil
	}

	// Ensure the serialized Data has enough bytes to properly deserialize.
	if len(serializedData) < 12 {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt transaction index "+
				"entry for %s", txHash),
		}
	}

	// Load the block hash associated with the block ID.
	hash, err := dbFetchBlockHashBySerializedID(dbTx, serializedData[0:4])
	if err != nil {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt transaction index "+
				"entry for %s: %v", txHash, err),
		}
	}

	// Deserialize the final entry.
	region := database.BlockRegion{Hash: &chainhash.Hash{}}
	copy(region.Hash[:], hash[:])
	region.Offset = byteOrder.Uint32(serializedData[4:8])
	region.Len = byteOrder.Uint32(serializedData[8:12])

	return &region, nil
}

func (d * OVM) GetCode(contract [20]byte) []byte {
	r := d.GetMeta(contract, "code")
	var h chainhash.Hash
	copy(h[:], r)

	var g *database.BlockRegion

	err := d.DB.View(func(dbTx database.Tx) error {
		var err error
		g, err = dbFetchTxIndexEntry(dbTx, &h)
		return err
	})
	if err != nil || g == nil {
		return nil
	}

	g.Len = common.LittleEndian.Uint32(r[36:])
	offset := common.LittleEndian.Uint32(r[32:])
	g.Offset += offset	// 324

	var codeBytes []byte
	d.DB.View(func(dbTx database.Tx) error {
		var err error
		codeBytes, err = dbTx.FetchBlockRegion(g)
		return err
	})

	return codeBytes
}

/*
func (d * OVM) SetInsts(contract [20]byte, insts []inst) {
	code := make([]byte, 0, len(insts))
	for _, d := range insts {
		code = append(code, byte(d.op))
		code = append(code, d.param...)
		code = append(code, byte(10))
	}
	d.setMeta(contract, "code", code)
}

func (d * OVM) SetCode(contract [20]byte, code []byte) {
	d.setMeta(contract, "code", code)
}

func (d *stateDB) GetCodeHash() chainhash.Hash {
	var codeHash chainhash.Hash

	if d.suicided {
		return codeHash
	}

	code := d.GetMeta("codeHash")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetCodeHash(contract [20]byte, code chainhash.Hash) {
	d.setMeta(contract, "codeHash", code[:])
}
 */

func (d *stateDB) GetMint() (int64, uint64) {
	c := d.GetMeta("mint")

	if c == nil {
		return -1, 0
	}

	tokenType := binary.LittleEndian.Uint64(c)
	issue := binary.LittleEndian.Uint64(c[8:])

	return int64(tokenType), issue
}

func (v * OVM) setMint(contract [20]byte, tokenType uint64, qty uint64) bool {
	d := v.StateDB[contract]
	if d.suicided {
		return false
	}

	t, issue := d.GetMint()

	if t != -1 && tokenType != uint64(t) {
		return false
	}

	c := make([]byte, 16)

	binary.LittleEndian.PutUint64(c, tokenType)
	binary.LittleEndian.PutUint64(c[8:], issue + qty)

	v.setMeta(contract, "mint", c[:])
	return true
}

func (v * OVM) GetQuota(contract [20]byte) int32 {
	c := v.GetMeta(contract, "quota")

	if c == nil {
		return 0
	}

	q := binary.LittleEndian.Uint32(c)

	return int32(q)
}

func (v * OVM) GetUsage(contract [20]byte) int32 {
	c := v.GetMeta(contract, "usage")

	if c == nil {
		return 0
	}

	q := binary.LittleEndian.Uint32(c)

	return int32(q)
}

func (d *stateDB) setQuota(q uint32) {
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], q)
	if d.suicided {
		return
	}

	key := "quota"
	if _, ok := d.meta[key]; !ok {
		m := d.GetMeta(key)
		d.meta[key] = &entry {m,  c[:]}
	} else {
		d.meta[key].data = c[:]
	}
}

func (d *stateDB) getQuota() uint32 {
	c := d.GetMeta("quota")

	if c == nil {
		return 0
	}

	q := binary.LittleEndian.Uint32(c)

	return q
}

func (d *stateDB) setUsage(q uint32) {
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], q)
	if d.suicided {
		return
	}

	key := "usage"
	if _, ok := d.meta[key]; !ok {
		m := d.GetMeta(key)
		d.meta[key] = &entry {m,  c[:]}
	} else {
		d.meta[key].data = c[:]
	}
}

func (d *stateDB) getUsage() uint32 {
	key := "usage"
	var m []byte
	if _, ok := d.meta[key]; !ok {
		m = d.GetMeta(key)
		if m == nil {
			return 0
		}
		d.meta[key] = &entry {m,  m[:]}
	} else {
		m = d.meta[key].data
	}

	q := binary.LittleEndian.Uint32(m)

	return q
}

func (d *stateDB) GetAddress() AccountRef {
	var codeHash AccountRef
	code := d.GetMeta("address")

	if code == nil {
		return codeHash
	}

	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) setAddress(contract [20]byte, code AccountRef) {
	d.setMeta(contract, "address", code[:])
}

func (r *entry) dup() *entry {
	e := entry{
		olddata: make([]byte, len(r.olddata)),
		data: make([]byte, len(r.data)),
	}
	if r.olddata == nil {
		e.olddata = nil
	} else {
		copy(e.olddata, r.olddata)
	}
	if r.data == nil {
		e.data = nil
	} else {
		copy(e.data, r.data)
	}
	return &e
}

func (d *stateDB) Copy() stateDB {
	s := stateDB{DB: d.DB,
		spendables: make(map[wire.OutPoint]struct{}),
	}

	if d.suicided {
		s.suicided = true
		return s
	}

	copy(s.contract[:], d.contract[:])
	s.data = make(map[string]*entry)
	for h, r := range d.data {
		s.data[h] = r.dup()
	}
	s.meta = make(map[string]*entry)
	for h, r := range d.meta {
		s.meta[h] = r.dup()
	}

	return s
}

func (v *OVM) GetState(contract [20]byte, loc string) []byte {
	d := v.StateDB[contract]
	if d.suicided {
		return nil
	}

	if t, ok := d.data[loc]; ok {
		return t.data
	}

	if v.DB == nil || d.fresh {
		return nil
	}
	var e []byte
	v.DB.View(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))
		if bucket == nil {
			return nil
		}
		e = bucket.Get([]byte(loc))
		return nil
	})

	if e == nil {
		return e
	}

	t := make([]byte, len(e))
	copy(t, e)
	d.data[loc] = &entry {e,  t}

	return t
}

func (v * OVM) SetState(contract [20]byte, key string, val []byte) {
	d := v.StateDB[contract]
	if d.suicided {
		return
	}
	q := d.getUsage()
	if _, ok := d.data[key]; !ok {
		m := v.GetState(contract, key)
		t := make([]byte, len(val))
		q += uint32(len(val))
		copy(t, val)
		d.data[key] = &entry {m,  t}
	} else {
		q = q + uint32(len(val)) - uint32(len(d.data[key].data))

		if d.data[key].data == nil {
			d.data[key].data = make([]byte, len(val))
		}
		copy(d.data[key].data, val)

		if len(d.data[key].data) < len(val) {
			d.data[key].data = append(d.data[key].data, val[len(d.data[key].data):]...)
		} else if len(d.data[key].data) > len(val) {
			d.data[key].data = d.data[key].data[:len(val)]
		}
	}
	if q > d.getQuota() {
		d.setQuota(q)
	}
	d.setUsage(q)
}

func (v * OVM) DeleteState(contract [20]byte, key string) {
	d := v.StateDB[contract]
	if d.suicided {
		return
	}
	if s, ok := d.data[key]; ok {
		q := d.getUsage()
		u := d.getQuota()
		q -= uint32(len(s.data))
		d.setUsage(q)
		if q < u {
			d.setQuota(q)
		}
		d.data[key].data = nil
		return
	}

	if v.GetState(contract, key) != nil {
		q := d.getUsage()
		u := d.getQuota()
		q -= uint32(len(d.data[key].data))
		d.setUsage(q)
		if q < u {
			d.setQuota(q)
		}
		d.data[key].data = nil
	}
}

func (d *stateDB) Exists(really bool) bool {
	if d.DB == nil {
		return false
	}
	err := d.DB.View(func(dbTx database.Tx) error {
		// find out necessary spending
		bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

		if bucket == nil {
			return omega.ScriptError(omega.ErrInternal, "Bucket not exist.")
		}

		if really {
			if bucket.Get([]byte("suicided")) != nil {
				return omega.ScriptError(omega.ErrInternal, "Bucket not exist.")
			}
		}

		return nil
	})
	return err == nil
}

func (d *stateDB) commit(blockHeight uint64) *PrevInfo {
	rollBack := &PrevInfo{
		NewContract: d.fresh,
		Data:        [2][]Rollback{make([]Rollback, 0), make([]Rollback,0)},
	}

	if d.suicided {
		d.DB.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

			if bucket == nil {
				return nil
			}

			if bucket.Get([]byte("suicided")) == nil {
				rollBack.Data[1] = []Rollback{{[]byte("suicided"), []byte{}}}
			}

			return bucket.Put([]byte("suicided"), []byte{1})
		})
		return rollBack
	}

	// for each block, it is called only once for each changed account
	for k,t := range d.data {
		if bytes.Compare(t.data, t.olddata) == 0 {
			delete(d.data, k)
		} else if t.olddata == nil {
			d.data[k].olddata = []byte{}
		}
	}

	for k,t := range d.meta {
		if bytes.Compare(t.data, t.olddata) == 0 {
			delete(d.data, k)
		} else if t.olddata == nil {
			d.meta[k].olddata = []byte{}
		}
	}

	if err := d.DB.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		// for each contract, create 2 buckets: "contract" + <address>, "storage" + <address>

		mainbkt := []byte("contract" + string(d.contract[:]))

		if meta.Bucket([]byte(mainbkt)) != nil {
			return nil
		}

		if _, err := meta.CreateBucket(mainbkt); err != nil {
			return err
		}

		if _, err := meta.CreateBucket([]byte("storage" + string(d.contract[:]))); err != nil {
			meta.DeleteBucket(mainbkt)
			return err
		}

		return nil
	}); err != nil {
		return rollBack
	}

	d.DB.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))

		for k,t := range d.data {
			rollBack.Data[0] = append(rollBack.Data[0], Rollback{[]byte(k), t.olddata})
			if len(t.data) == 0 {
				bucket.Delete([]byte(k))
				delete(d.data, k)
			} else if bytes.Compare(t.olddata, t.data) != 0 {
				key := []byte(k)
				if err := bucket.Put(key, t.data); err != nil {
					return err
				}
			}
		}

		bucket = dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

		for k, t := range d.meta {
			rollBack.Data[1] = append(rollBack.Data[1], Rollback{[]byte(k), t.olddata})
			if len(t.data) == 0 {
				bucket.Delete([]byte(k))
				delete(d.meta, k)
			} else if bytes.Compare(t.olddata, t.data) != 0 {
				key := []byte(k)
				if err := bucket.Put(key, t.data); err != nil {
					return err
				}
			}
		}

		return nil
	})

	return rollBack
}
