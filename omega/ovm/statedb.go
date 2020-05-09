package ovm

import (
	"bytes"
	"encoding/binary"
	//	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
//	"encoding/json"
	//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/omega"
	//	"github.com/btcsuite/omega/token"
	//	"github.com/btcsuite/omega/viewpoint"
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

// state data entry. contract managed
type entry struct {
	olddata []byte
	data []byte
}

type dataMap map[string]*entry

type rollback map[string][]byte

type stateDB struct {
	// stateDB gives access to the underlying state (storage) of current account
	DB database.DB

	// contract address of current account
	contract [20]byte

	// contract state data cache
	data dataMap
	meta dataMap

	// Suicide flag
	suicided bool
}

func NewStateDB(db database.DB, addr [20]byte) *stateDB {
	return &stateDB{
		DB:       db,
		contract: addr,
		data:     make(map[string]*entry),
		meta:     make(map[string]*entry),
	}
}

func (d *stateDB) Suicide() {
	d.data = make(map[string]*entry)
	d.meta = make(map[string]*entry)
	d.suicided = true
}

func (v * OVM) setMeta(contract [20]byte, key string, code []byte) {
	d := v.StateDB[contract]

	if d.suicided {
		return
	}

	if _, ok := d.meta[key]; !ok {
		m := d.getMeta(key)
		t := make([]byte, len(code))
		copy(t, code)
		d.meta[key] = &entry {m,  t}
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

func (v * OVM) getMeta(contract [20]byte, key string) []byte {
	d := v.StateDB[contract]
	if t, ok := d.meta[key]; ok {
		return t.data
	}

	m := d.getMeta(key)
	if m == nil {
		return m
	}

	t := make([]byte, len(m))
	copy(t, m)
	d.meta[key] = &entry {m,  t}

	return t
}

func (d *stateDB) getMeta(key string) []byte {
	if d.suicided {
		return nil
	}

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

func (d *stateDB) GetCodeHash() chainhash.Hash {
	var codeHash chainhash.Hash

	if d.suicided {
		return codeHash
	}

	code := d.getMeta("codeHash")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetCodeHash(contract [20]byte, code chainhash.Hash) {
	d.setMeta(contract, "codeHash", code[:])
}

func (d *stateDB) GetOwner() Address {
	var codeHash Address

	if d.suicided {
		return codeHash
	}

	code := d.getMeta("owner")
	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetOwner(contract [20]byte, code Address) {
	d.setMeta(contract, "owner", code[:])
}

func (d *stateDB) GetMint() (uint64, uint64) {
	c := d.getMeta("mint")

	if c == nil {
		return 0, 0
	}

	tokenType := binary.LittleEndian.Uint64(c)
	issue := binary.LittleEndian.Uint64(c[8:])

	return tokenType, issue
}

func (v * OVM) SetMint(contract [20]byte, tokenType uint64, qty uint64) bool {
	d := v.StateDB[contract]
	if d.suicided {
		return false
	}

	t, issue := d.GetMint()

	if tokenType == 0 || (t != 0 && tokenType != t) {
		return false
	}

	c := make([]byte, 16)

	binary.LittleEndian.PutUint64(c, tokenType)
	binary.LittleEndian.PutUint64(c[8:], issue + qty)

	v.setMeta(contract, "mint", c[:])
	return true
}

func (d *stateDB) GetAddres() AccountRef {
	var codeHash AccountRef
	code := d.getMeta("address")

	if code == nil {
		return codeHash
	}

	copy(codeHash[:], code)
	return codeHash
}

func (d * OVM) SetAddres(contract [20]byte, code AccountRef) {
	d.setMeta(contract, "address", code[:])
}

func (d *stateDB) Copy() stateDB {
	s := stateDB{ DB: d.DB }
	copy(s.contract[:], d.contract[:])
	s.data = make(map[string]*entry)
	for h,r := range d.data {
		s.data[h] = r
	}
	for h,r := range d.meta {
		s.meta[h] = r
	}
/*
	s.wallet.Tokens = make(map[wire.OutPoint]token.Token)
	for i, r := range d.wallet.Tokens {
		s.wallet.Tokens[i] = r
//		r.back.Copy(&s.wallet[i].back)
	}
 */

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

type wentry struct {
	right viewpoint.RightEntry
	qty uint64
}
*/

func (v * OVM) GetState(contract [20]byte, loc string) []byte {
	d := v.StateDB[contract]
	if t, ok := d.data[loc]; ok {
		return t.data
	}

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
		return e
	}

	t := make([]byte, len(e))
	copy(t, e)
	d.data[loc] = &entry {e,  t}

	return t
}

func (v * OVM) SetState(contract [20]byte, key string, val []byte) {
	d := v.StateDB[contract]
	if _, ok := d.data[key]; !ok {
		m := v.GetState(contract, key)
		t := make([]byte, len(val))
		copy(t, val)
		d.data[key] = &entry {m,  t}
	} else {
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
}

func (v * OVM) DeleteState(contract [20]byte, key string) {
	d := v.StateDB[contract]
	if _, ok := d.data[key]; ok {
		d.data[key].data = nil
		return
	}

	if v.GetState(contract, key) != nil {
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

func (d *stateDB) commit(blockHeight uint64) [2]rollback {
	rollBack := [2]rollback{
		make(map[string][]byte), make(map[string][]byte),
	}

	if d.suicided {
		d.DB.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

			if bucket == nil {
				return nil
			}

			if bucket.Get([]byte("suicided")) == nil {
				rollBack[1]["suicided"] = []byte{}
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
			rollBack[0][k] = t.olddata
			if len(t.data) == 0 {
				bucket.Delete([]byte(k))
				delete(d.data, k)
			} else if bytes.Compare(t.olddata, t.data) != 0 {
				if err := bucket.Put([]byte(k), t.data[:]); err != nil {
					return err
				}
			}
		}

		bucket = dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

		for k, t := range d.meta {
			rollBack[1][k] = t.olddata
			if len(t.data) == 0 {
				bucket.Delete([]byte(k))
				delete(d.meta, k)
			} else if bytes.Compare(t.olddata, t.data) != 0 {
				if err := bucket.Put([]byte(k), t.data[:]); err != nil {
					return err
				}
			}
		}

		return nil
	})

	return rollBack
}
