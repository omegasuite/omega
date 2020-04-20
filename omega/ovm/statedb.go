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
	"encoding/binary"
	"encoding/json"
	"bytes"
	//	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
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

const (
	dirtyFlag status = 1 << iota
	deleteFlag = 2
	inStoreFlag = 4		// we know it is in storage DB
	outStoreFlag = 8	// we know it is not in storage DB

	// for roll back
	putFlag = 16
	delFlag = 32
)

// state data entry. contract managed
type entry struct {
	data []byte
	flag status
}

type dataMap map[string]entry

type stateDB struct {
	// stateDB gives access to the underlying state (storage) of current account
	DB database.DB

	// contract address of current account
	contract [20]byte

	// contract state data cache
	data dataMap
	meta dataMap
	wallet WalletItems

	// Suicide flag
	suicided bool
}

func NewStateDB(db database.DB, addr [20]byte) * stateDB {
	return &stateDB{
		DB:       db,
		contract: addr,
		data:     make(map[string]entry),
		meta:     make(map[string]entry),
		wallet:   WalletItems {make(map[wire.OutPoint]token.Token)},
	}
}

func (d * stateDB) Suicide() {
	d.suicided = true
}

func (v * OVM) setMeta(contract [20]byte, key string, code []byte) {
	d := v.StateDB[contract]
	if _, ok := d.meta[key]; !ok {
		m := d.getMeta(key)
		if len(m) != 0 {
			d.meta[key] = entry {m, inStoreFlag }
		}
	}
	if t, ok := d.meta[key]; ok {
		if t.flag & dirtyFlag == 0 {
			v.GetTx().MsgTx().SetMeta(contract, key, t.data)
		}
		if len(t.data) != len(code) {
			t.data = make([]byte, len(code))
		}
		copy(t.data, code)
		t.flag |= dirtyFlag
		d.meta[key] = t
		return
	}

	v.GetTx().MsgTx().SetMeta(contract, key, nil)
	t := entry { make([]byte, len(code)), dirtyFlag | outStoreFlag }
	copy(t.data, code)
	d.meta[key] = t
}

func (v * OVM) getMeta(contract [20]byte, key string) []byte {
	d := v.StateDB[contract]
	if t, ok := d.meta[key]; ok {
		return t.data
	}

	m := d.getMeta(key)
	if len(m) != 0 {
		d.meta[key] = entry {m, inStoreFlag }
	}
	return m
}

func (d * stateDB) getMeta(key string) []byte {
	var code []byte
	d.DB.View(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))
		code = bucket.Get([]byte(key))
		return nil
	})
	return code
}

func (d * OVM) GetCode(contract [20]byte) []byte {
	return d.StateDB[contract].getMeta("code")
}

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

func (d * stateDB) GetCodeHash() chainhash.Hash {
	var codeHash chainhash.Hash
	code := d.getMeta("codeHash")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetCodeHash(contract [20]byte, code chainhash.Hash) {
	d.setMeta(contract, "codeHash", code[:])
}

func (d * stateDB) GetOwner() Address {
	var codeHash Address
	code := d.getMeta("owner")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetOwner(contract [20]byte, code Address) {
	d.setMeta(contract, "owner", code[:])
}

func (d * stateDB) GetMint() (uint64, uint64) {
	c := d.getMeta("mint")

	if c == nil {
		return 0, 0
	}

	tokenType := binary.LittleEndian.Uint64(c)
	issue := binary.LittleEndian.Uint64(c[8:])

	return tokenType, issue
}

func (d * OVM) SetMint(contract [20]byte, tokenType uint64, qty uint64) bool {
	t, issue := d.StateDB[contract].GetMint()

	if tokenType == 0 || (t != 0 && tokenType != t) {
		return false
	}

	c := make([]byte, 16)

	binary.LittleEndian.PutUint64(c, tokenType)
	binary.LittleEndian.PutUint64(c[8:], issue + qty)

	d.setMeta(contract, "mint", c[:])
	return true
}

func (d * stateDB) GetAddres() AccountRef {
	var codeHash AccountRef
	code := d.getMeta("address")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetAddres(contract [20]byte, code AccountRef) {
	d.setMeta(contract, "address", code[:])
}

// GetBlockNumberFunc returns the block numer of the block of current execution environment
func (d * stateDB)  GetCoins() []*token.Token {
	res := make([]*token.Token, len(d.wallet.Tokens))
	for _, w := range d.wallet.Tokens {
		tw := w
		res = append(res, &tw)
	}
	return res
}

func (d * stateDB) Copy() stateDB {
	s := stateDB { DB: d.DB }
	copy(s.contract[:], d.contract[:])
	s.data = make(map[string]entry)
	for h,r := range d.data {
		s.data[h] = r
	}
	for h,r := range d.meta {
		s.meta[h] = r
	}
	s.wallet.Tokens = make(map[wire.OutPoint]token.Token)
	for i, r := range d.wallet.Tokens {
		s.wallet.Tokens[i] = r
//		r.back.Copy(&s.wallet[i].back)
	}

	return s
}

/*
func (d * stateDB) GetWalletItems(tokenType uint64, right * chainhash.Hash) []token.Token {
	w := make([]token.Token, 0)
	for _, r := range d.wallet {
		if tokenType != r.Token.TokenType {
//		if r.flag & deleteFlag != 0 || tokenType != r.Token.TokenType {
			continue
		}
		if right == nil || (r.Token.Rights != nil &&  r.Token.Rights.IsEqual(right)) {
//		if right == nil || tokenType & 2 != 2 || r.Token.Rights.IsEqual(right) {
			w = append(w, r.Token)
		}
	}
	return w
}
 */

type wentry struct {
	right viewpoint.RightEntry
	qty uint64
}

func (v * OVM) GetState(contract [20]byte, loc string) []byte {
	d := v.StateDB[contract]
	if _,ok := d.data[loc]; ok {
		if d.data[loc].flag & deleteFlag != 0 {
			return nil
		}
	} else {
		if v.DB == nil {
			return nil
		}
		var e []byte
		v.DB.View(func (dbTx  database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))
			e = bucket.Get([]byte(loc))
			return nil
		})
		
		if e == nil {
			return nil
		}

		v.GetTx().MsgTx().SetMeta(contract, loc, e)

		d.data[loc] = entry { data: e, flag: inStoreFlag }
	}
	dt := d.data[loc].data
	return dt
}

func (v * OVM) SetState(contract [20]byte, loc string, val []byte) {
	d := v.StateDB[contract]
	if _,ok := d.data[loc]; ok {
		e := d.data[loc]
		if e.flag & deleteFlag != 0 {
			e.flag &^= deleteFlag
//			v.GetTx().MsgTx().SetState(contract, loc, nil)
		}

		if bytes.Compare(val, e.data) != 0 {
			if e.flag & dirtyFlag == 0 {
				v.GetTx().MsgTx().SetState(contract, loc, e.data)
			}
			e.data = val
			e.flag |= dirtyFlag
			d.data[loc] = e
		}
	} else {
		old := v.GetState(contract, loc)
		if old == nil {
			d.data[loc] = entry { data: val, flag: outStoreFlag | dirtyFlag }
			v.GetTx().MsgTx().SetState(contract, loc, nil)
		} else {
			dd := d.data[loc].data
			if bytes.Compare(val, dd) != 0 {
				e := d.data[loc]
				v.GetTx().MsgTx().SetState(contract, loc, dd)
				e.data = val
				e.flag |= dirtyFlag
				d.data[loc] = e
			}
		}
	}
}

func (v * OVM) DeleteState(contract [20]byte, loc string) {
	d := v.StateDB[contract]
	if v.GetState(contract, loc) != nil {
		e := d.data[loc]
		if e.flag & dirtyFlag == 0 {
			v.GetTx().MsgTx().SetState(contract, loc, e.data)
		}
		e.flag |= deleteFlag
		d.data[loc] = e
	}
}

func (d * stateDB) Exists() bool {
	if d.DB == nil {
		return false
	}
	err := d.DB.View(func(dbTx database.Tx) error {
		// find out necessary spending
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))

		if bucket == nil {
			return omega.ScriptError(omega.ErrInternal, "Bucket not exist.")
		}

		return nil
	})
	return err == nil
}

func (d * stateDB) Commit(block uint64) {
	// for each block, it is called only once for each changed account
	for k,t := range d.data {
		if t.flag & (outStoreFlag | deleteFlag) ==  (outStoreFlag | deleteFlag) {
			delete(d.data, k)
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
		return
	}

	d.DB.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))

		for k,t := range d.data {
			if t.flag & deleteFlag != 0 {
				bucket.Delete([]byte(k))
				delete(d.data, k)
			} else if t.flag & dirtyFlag == dirtyFlag {
				if err := bucket.Put([]byte(k), t.data[:]); err != nil {
					return err
				}
				t.flag = inStoreFlag
				t.flag &^= dirtyFlag | outStoreFlag
				d.data[k] = t
			}
		}

		wd, _ := json.Marshal(d.wallet.Tokens)
		bucket = dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))
		if err := bucket.Put([]byte("Wallet"[:]), wd); err != nil {
			return err
		}

		for k, t := range d.meta {
			if t.flag & deleteFlag != 0 {
				bucket.Delete([]byte(k[:]))
				delete(d.meta, k)
			} else if t.flag & dirtyFlag == dirtyFlag {
				if err := bucket.Put([]byte(k[:]), t.data[:]); err != nil {
					return err
				}
				t.flag = inStoreFlag
				t.flag &^= dirtyFlag | outStoreFlag
				d.meta[k] = t
			}
		}

		return nil
	})
}
