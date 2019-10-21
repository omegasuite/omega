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
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
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

type entry struct {
	data chainhash.Hash
	back chainhash.Hash
	flag uint8
}

type stateDB struct {
	// stateDB gives access to the underlying state (storage) of current account
	DB database.DB

	// contract address of current account
	contract [20]byte

	data map[chainhash.Hash]entry
}


func (d * stateDB) GetState(loc * chainhash.Hash) *chainhash.Hash {
	if _,ok := d.data[*loc]; ok {
		if d.data[*loc].flag & deleteFlag != 0 {
			return nil
		}
	} else {
		var e chainhash.Hash
		d.db.View(func (dbTx  database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract)))
			e = bucket.get((*loc)[:])
			return nil
		})
		
		if e == nil {
			return nil
		}

		d.data[*loc] = entry { data: e, back: e, flag: inStoreFlag }
	}
	return &d.data[*loc].data
}

func (d * stateDB) SetState(loc * chainhash.Hash, val chainhash.Hash) {
	if _,ok := d.data[*loc]; ok {
		if d.data[*loc].flag & deleteFlag != 0 {
			d.data[*loc].flag &= ^deleteFlag
		}

		if !val.IsEqual(&d.data[*loc].data) {
			d.data[*loc].data = val
			d.data[*loc].flag |= dirtyFlag
		}
	} else {
		if d.GetState(loc) == nil {
			d.data[*loc] = entry { data: e, flag: outStoreFlag | dirtyFlag }
		} else if !val.IsEqual(&d.data[*loc].data) {
			d.data[*loc].data = val
			d.data[*loc].flag |= dirtyFlag
		}
	}
}

func (d * stateDB) DeleteState(loc * chainhash.Hash) {
	if d.GetState(loc) != nil {
		d.data[*loc].flag |= deleteFlag
	}
}

type RollBackData struct {
	Key	chainhash.Hash
	Flag	uint8
	Data	chainhash.Hash
}

func (d * stateDB) Commit(block uint64) {
	// for each block, it is called only once for each changed account
	for k,t := range d.data {
		if t.flag & (outStoreFlag | deleteFlag) ==  (outStoreFlag | deleteFlag) {
			delete(d.data, k)
		}
	}

	// prepare data for roll back
	roll := make([]RollBackData, 0, len(d.data))
	for k,t := range d.data {
		if t.flag & outStoreFlag {
			roll = append(roll, RollBackData{Key: k, Flag: delFlag})
		} else {
			roll = append(roll, RollBackData{Key: k, Flag: putFlag, Data: t.back})
		}
	}

	var dirtyaccount []byte

	d.db.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract)))
		for k,t := range d.data {
			if t.flag & deleteFlag {
				bucket.Delete(k[:])
				delete(d.data, k)
			} else if t.flag & dirtyFlag == dirtyFlag {
				if err := bucket.Put(k[:], t.data[:]); err != nil {
					return err
				}
				t.flag = inStoreFlag
			}
		}
		if len(roll) > 0 {
			md, _ := json.Marshall(roll)
			bucket.Put([]byte(fmt.Sprintf("rollback%d", block)), md)

			bucket := dbTx.Metadata().Bucket([]byte("rollbacks"))
			key = []byte(fmt.Sprintf("block%d", block))

			dirtyaccount = bucket.Get(key)
			if dirtyaccount != nil {
				dirtyaccount = append(dirtyaccount, []byte(d.contract)...)
				bucket.Put(key, dirtyaccount)
			} else {
				bucket.Put(key, []byte(d.contract)) 
			}
		}
		bucket = dbTx.Metadata().Bucket([]byte("contract" + string(d.contract)))

		md, _ := json.Marshal(d.wallet)
		if err := bucket.Put([]byte("Wallet"[:]), md); err != nil {
			return err
		}
		md, _ = json.Marshal(d.collaterals)
		if err := bucket.Put([]byte("Collaterals"[:]), md); err != nil {
			return err
		}

		return nil
	})
}

func (d * stateDB) RollBack(block uint64) {
	d.db.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("rollbacks"))
		key := []byte(fmt.Sprintf("block%d", block))

		dirtyaccount = bucket.Get(key)

		key = []byte(fmt.Sprintf("rollback%d", block))
		for i := 0; i < len(dirtyaccount); i += 20 {
			account := dirtyaccount[i:i+20]
			bucket := dbTx.Metadata().Bucket([]byte("storage" + string(account)))
			rbd := bucket.Get(key)
			bucket.Delete(key)
			data := json.Unmarshall(rbd)
			for _,r := range data {
				if r.Flag & delFlag {
					bucket.Delete(r.Key)
				} else if r.Flag & putFlag {
					bucket.Put(r.Key, r.Data)
				}
			}
		}
	})
}

func (d * stateDB) Maintenance(block uint64, rollbacklimit uint32) {
	// keep number of rollback record for upto most recent rollbacklimit blocks
	d.db.Update(func (dbTx  database.Tx) error {
		var oldest uint32

		bucket := dbTx.Metadata().Bucket([]byte("rollbacks"))
		rollbackto = bucket.Get([]byte("oldest"))
		if rollbackto != nil {
			fmt.Scanf(string(rollbackto), "%d", &oldest)
		}

		if oldest >= block - rollbacklimit {
			return nil
		}

		for ; oldest < block - rollbacklimit; oldest++ {
			key := []byte(fmt.Sprintf("block%d", oldest))
			dirtyaccount = bucket.Get(key)
			bucket.Delete(key)

			key = []byte(fmt.Sprintf("rollback%d", oldest))
			for i := 0; i < len(dirtyaccount); i += 20 {
				account := dirtyaccount[i:i+20]
				dbTx.Metadata().Bucket([]byte("storage" + string(account))).Delete(key)
			}
		}
		bucket.Put([]byte("oldest"), oldest)
	})
}
