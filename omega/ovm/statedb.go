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
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"fmt"
	"encoding/json"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/token"
	"encoding/binary"
	"github.com/btcsuite/omega/viewpoint"
	"math/big"
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
	data chainhash.Hash
	back chainhash.Hash
	flag status
}

// wallet data. miner managed
type WalletItem struct {
	Token	token.Token		 `json:"token"`
	back    token.Token
	flag status
}

type stateDB struct {
	// stateDB gives access to the underlying state (storage) of current account
	DB database.DB

	// contract address of current account
	contract [20]byte

	// contract state data cache
	data map[chainhash.Hash]entry
	wallet []WalletItem
	meta map[string]struct{
		data []byte
		back []byte
		flag status }

	// Suicide flag
	suicided bool
}

func (d * stateDB) Suicide() {
	d.suicided = true
}

func (d * stateDB) setMeta(key string, code []byte) {
	if t, ok := d.meta[key]; ok {
		if len(t.data) != len(code) {
			t.data = make([]byte, len(code))
		}
		copy(t.data, code)
		t.flag |= dirtyFlag
		d.meta["code"] = t
		return
	}
	t := struct{
		data []byte
		back []byte
		flag status } { make([]byte, len(code)), make([]byte, len(code)), 0 }
	copy(t.data, code)
	copy(t.back, code)
	t.flag |= dirtyFlag | outStoreFlag
	d.meta[key] = t
}

func (d * stateDB) getMeta(key string) []byte {
	if t, ok := d.meta[key]; ok {
		return t.data
	}

	var code []byte
	d.DB.View(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))
		code = bucket.Get([]byte(key))
		t := struct{
			data []byte
			back []byte
			flag status } { make([]byte, len(code)), make([]byte, len(code)), 0 }
		copy(t.data, code)
		copy(t.back, code)
		d.meta[key] = t
		return nil
	})
	return code
}

func (d * stateDB) GetCode() []byte {
	return d.getMeta("code")
}

func (d * stateDB) SetCode(code []byte) {
	d.setMeta("code", code)
}

func (d * stateDB) GetCodeHash() chainhash.Hash {
	var codeHash chainhash.Hash
	code := d.getMeta("codeHash")
	copy(codeHash[:], code)
	return codeHash
}

func (d * stateDB) SetCodeHash(code chainhash.Hash) {
	d.setMeta("codeHash", code[:])
}

func (d * stateDB) GetOwner() Address {
	var codeHash Address
	code := d.getMeta("owner")
	copy(codeHash[:], code)
	return codeHash
}

func (d * stateDB) SetOwner(code Address) {
	d.setMeta("owner", code[:])
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

func (d * stateDB) SetMint(tokenType uint64, qty uint64) bool {
	t, issue := d.GetMint()

	if tokenType == 0 || (t != 0 && tokenType != t) {
		return false
	}

	c := make([]byte, 16)

	binary.LittleEndian.PutUint64(c, tokenType)
	binary.LittleEndian.PutUint64(c[8:], issue + qty)

	d.setMeta("mint", c[:])
	return true
}

func (d * stateDB) GetAddres() AccountRef {
	var codeHash AccountRef
	code := d.getMeta("address")
	copy(codeHash[:], code)
	return codeHash
}

func (d * stateDB) GetBalance(tokentype uint64, required uint64, h chainhash.Hash, r chainhash.Hash) *big.Int {
	sum := int64(0)
	for _, w := range d.wallet {
		if tokentype != w.Token.TokenType {
			continue
		}
		if required&1 == 1 && tokentype&1 == 1 && !w.Token.Value.(*token.HashToken).Hash.IsEqual(&h) {
			continue
		}
		if required&2 == 2 && tokentype&2 == 2  && !w.Token.Rights.IsEqual(&r) {
			continue
		}
		if tokentype & 1 == 0 {
			sum += w.Token.Value.(*token.NumToken).Val
		} else {
			sum++
		}
	}

	return big.NewInt(sum)
}

func (d * stateDB) SetAddres(code AccountRef) {
	d.setMeta("address", code[:])
}

// GetBlockNumberFunc returns the block numer of the block of current execution environment
func (d * stateDB)  GetCoins(tokentype uint64, required uint64, h chainhash.Hash, r chainhash.Hash) []byte {
	cbuf := new(bytes.Buffer)
	for _, w := range d.wallet {
		if tokentype != w.Token.TokenType {
			continue
		}
		if required&1 == 1 && tokentype&1 == 1 && !w.Token.Value.(*token.HashToken).Hash.IsEqual(&h) {
			continue
		}
		if required&2 == 2 && tokentype&2 == 2  && !w.Token.Rights.IsEqual(&r) {
			continue
		}
		w.Token.Write(cbuf, 0, 0)
	}
	return cbuf.Bytes()
}

func (d * stateDB) Copy() stateDB {
	s := stateDB { DB: d.DB }
	copy(s.contract[:], d.contract[:])
	s.data = make(map[chainhash.Hash]entry)
	for h,r := range d.data {
		s.data[h] = entry{ flag: r.flag	}
		tmp := s.data[h].data
		copy(tmp[:], r.data[:])
		tmp = s.data[h].back
		copy(tmp[:], r.back[:])
	}
	s.wallet = make([]WalletItem, len(d.wallet))
	for i, r := range d.wallet {
		s.wallet[i] = WalletItem{flag: r.flag}
		r.back.Copy(&s.wallet[i].back)
		r.Token.Copy(&s.wallet[i].Token)
	}

	return s
}

func (d * stateDB) GetWalletItems(tokenType uint64, right * chainhash.Hash) []token.Token {
	w := make([]token.Token, 0)
	for _, r := range d.wallet {
		if r.flag & deleteFlag != 0 || tokenType != r.Token.TokenType {
			continue
		}
		if right == nil || tokenType & 2 != 2 || r.Token.Rights.IsEqual(right) {
			w = append(w, r.Token)
		}
	}
	return w
}

func (d * stateDB) Credit(t token.Token) error {
	return credit(d.wallet, t)
}

func credit(wallet []WalletItem, t token.Token) error {
	for i, r := range wallet {
		if t.TokenType != r.Token.TokenType {
			continue
		}
		switch t.TokenType & 3 {
		case 0:
			if r.flag & deleteFlag == deleteFlag {
				r.Token.Value.(*token.NumToken).Val = t.Value.(*token.NumToken).Val
				r.flag ^= deleteFlag
				r.flag |= dirtyFlag
				wallet[i] = r
			} else {
				r.Token.Value.(*token.NumToken).Val += t.Value.(*token.NumToken).Val
				r.flag |= dirtyFlag
				wallet[i] = r
			}
			return nil
		case 1:
			if r.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				return omega.ScriptError(omega.ErrInternal, "Dupliucated hash token.")
			}
			break
		case 2:
			if t.Rights == nil {
				return omega.ScriptError(omega.ErrInternal, "Right token missing right data.")
			}
			if r.Token.Rights.IsEqual(t.Rights) {
				// TBD: right merge
				if r.flag & deleteFlag == deleteFlag {
					r.Token.Value.(*token.NumToken).Val = t.Value.(*token.NumToken).Val
					r.flag ^= deleteFlag
					r.flag |= dirtyFlag
					wallet[i] = r
				} else {
					r.Token.Value.(*token.NumToken).Val += t.Value.(*token.NumToken).Val
					r.flag |= dirtyFlag
					wallet[i] = r
				}
				return nil
			}
			break
		case 3:
			if t.Rights == nil {
				return omega.ScriptError(omega.ErrInternal, "Right token missing right data.")
			}
			if r.Token.Rights.IsEqual(t.Rights) {
				if r.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
					return omega.ScriptError(omega.ErrInternal, "Dupliucated hash token.")
				}
				// TBD: right merge
				if r.flag & deleteFlag == deleteFlag {
					r.Token.Value.(*token.NumToken).Val = t.Value.(*token.NumToken).Val
					r.flag ^= deleteFlag
					r.flag |= dirtyFlag
					wallet[i] = r
				} else {
					r.Token.Value.(*token.NumToken).Val += t.Value.(*token.NumToken).Val
					r.flag |= dirtyFlag
					wallet[i] = r
				}
				return nil
			}
			break
		}
	}
	wallet = append(wallet, WalletItem{Token:t, flag: outStoreFlag | dirtyFlag })
	return nil
}

func (d * stateDB) Debt(t token.Token) error {
	for i, r := range d.wallet {
		if t.TokenType != r.Token.TokenType || r.flag & deleteFlag == deleteFlag {
			continue
		}
		switch t.TokenType & 3 {
		case 0:
			if r.Token.Value.(*token.NumToken).Val <  t.Value.(*token.NumToken).Val {
				return omega.ScriptError(omega.ErrInternal, "Insufficient fund.")
			}
			r.Token.Value.(*token.NumToken).Val -=  t.Value.(*token.NumToken).Val
			r.flag |= dirtyFlag
			d.wallet[i] = r
			return nil
		case 1:
			if r.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				r.flag |= deleteFlag
				d.wallet[i] = r
				return nil
			}
			break
		case 2:
			if t.Rights == nil {
				return omega.ScriptError(omega.ErrInternal, "Right token missing right data.")
			}
			if r.Token.Rights.IsEqual(t.Rights) {
				// TBD: right merge
				r.Token.Value.(*token.NumToken).Val +=  t.Value.(*token.NumToken).Val
				r.flag |= dirtyFlag
				d.wallet[i] = r
				return nil
			}
			break
		case 3:
			if t.Rights == nil {
				return omega.ScriptError(omega.ErrInternal, "Right token missing right data.")
			}
			if r.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				// check right
				if r.Token.Rights.IsEqual(t.Rights) {
					r.flag |= deleteFlag
					d.wallet[i] = r
					return nil
				}
			}
			break
		}
	}

	return omega.ScriptError(omega.ErrInternal, "Unable to find a matching item to debt.")
}

type wentry struct {
	right viewpoint.RightEntry
	qty uint64
}

func (d * stateDB) DebtWithReorg(views *viewpoint.ViewPointSet, t token.Token) error {
	// reorganize wallet for the purpose of maximize matching of right
	if t.TokenType&2 == 0 || t.Rights == nil {
		return omega.ScriptError(omega.ErrInternal, "DebtWithReorg is only for token with rights.")
	}

	quantity := uint64(1)

	if t.TokenType&1 == 0 {
		quantity = uint64(t.Value.(*token.NumToken).Val)
	}

	r, err := views.Rights.FetchEntry(d.DB, t.Rights)
	if err != nil {
		return err
	}

	required := make(map[chainhash.Hash]wentry)
	switch r.(type) {
	case *viewpoint.RightEntry:
		required[*t.Rights] = wentry{*(r.(*viewpoint.RightEntry)), quantity}
		break
	case *viewpoint.RightSetEntry:
		for _, p := range r.(*viewpoint.RightSetEntry).Rights {
			s, _ := views.Rights.FetchEntry(d.DB, &p)
			required[p] = wentry{*(s.(*viewpoint.RightEntry)), quantity}
		}
		break
	}

	reswallet := make([]WalletItem, 0, len(d.wallet))
	sup := make(map[chainhash.Hash]wentry)
	for _, r := range d.wallet {
		if t.TokenType != r.Token.TokenType || r.flag&deleteFlag == deleteFlag {
			reswallet = append(reswallet, r)
			continue
		}
		q := uint64(1)
		if t.TokenType&1 == 1 {
			if !r.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				reswallet = append(reswallet, r)
				continue
			}
		} else {
			q = uint64(t.Value.(*token.NumToken).Val)
		}

		u, _ := views.Rights.FetchEntry(d.DB, r.Token.Rights)
		switch u.(type) {
		case *viewpoint.RightEntry:
			if _, ok := sup[*r.Token.Rights]; !ok {
				sup[*r.Token.Rights] = wentry{*(u.(*viewpoint.RightEntry)),q}
			} else {
				sup[*r.Token.Rights] = wentry{*(u.(*viewpoint.RightEntry)), q + sup[*r.Token.Rights].qty}
			}
			break
		case *viewpoint.RightSetEntry:
			for _, p := range u.(*viewpoint.RightSetEntry).Rights {
				v, _ := views.Rights.FetchEntry(d.DB, &p)
				if _, ok := sup[*r.Token.Rights]; !ok {
					sup[*r.Token.Rights] = wentry{*(v.(*viewpoint.RightEntry)), q}
				} else {
					sup[*r.Token.Rights] = wentry{*(v.(*viewpoint.RightEntry)), q + sup[*r.Token.Rights].qty}
				}
			}
			break
		}
	}

	for expd := true; expd; {
		for h, r := range required {
			if _, ok := sup[h]; ok {
				if sup[h].qty > r.qty {
					sup[h] = wentry{sup[h].right, sup[h].qty - r.qty}
					delete(required, h)
				} else if sup[h].qty == r.qty {
					delete(required, h)
					delete(sup, h)
				} else {
					required[h] = wentry{r.right, r.qty - sup[h].qty}
					delete(sup, h)
				}
			}
		}

		if len(required) == 0 {
			for h, r := range sup {
				tt := token.Token{TokenType: t.TokenType, Rights: &h}
				if t.TokenType & 1 == 0 {
					tt.Value = &token.NumToken{ int64(r.qty) }
				} else {
					tt.Value = &token.HashToken{t.Value.(*token.HashToken).Hash}
				}
				credit(reswallet, tt)
			}
			d.wallet = reswallet
			d.OptimizeWallet(views, t)
			return nil
		}
		if len(sup) == 0 {
			return omega.ScriptError(omega.ErrInternal, "Unable to find a matching items to debt.")
		}

		expd = false
		for hh, rr := range sup {
			rel := false
			for h, r := range required {
				if rr.right.Root.IsEqual(&r.right.Root) {
					if rr.right.Depth > r.right.Depth {
						if ancester(views, &rr.right, rr.right.Depth-r.right.Depth-1).Father.IsEqual(&h) {
							rel = true
							expaninto(views, required, h, &rr.right, hh, rr.right.Depth-r.right.Depth)
						}
					} else if ancester(views, &r.right, r.right.Depth-rr.right.Depth-1).Father.IsEqual(&hh) {
						rel = true
						expaninto(views, sup, hh, &r.right, h, r.right.Depth-rr.right.Depth)
					}
				}
			}
			if rel {
				expd = true
			} else {
				tt := token.Token{TokenType: t.TokenType, Rights: &hh}
				if t.TokenType & 1 == 0 {
					tt.Value = &token.NumToken{Val: int64(rr.qty)}
				} else {
					tt.Value = &token.HashToken{t.Value.(*token.HashToken).Hash}
				}
				credit(reswallet, tt)
				delete(sup, hh)
				continue
			}
		}
	}
	return omega.ScriptError(omega.ErrInternal, "Unable to find a matching items to debt.")
}

func expaninto(views *viewpoint.ViewPointSet, data map[chainhash.Hash]wentry, h chainhash.Hash, p * viewpoint.RightEntry, ph chainhash.Hash, d int32) {
	if d > 1 {
		u, _ := views.Rights.FetchEntry(views.Db, &p.Father)
		f := u.(*viewpoint.RightEntry)
		expaninto(views, data, h, f, p.Father, d - 1)
	}
	r := data[p.Father]
	delete(data, p.Father)
	data[p.Father] = wentry{ right: *p, qty: r.qty}

	sib := p.Sibling()
	s, _ := views.Rights.FetchEntry(views.Db, &sib)
	data[p.Sibling()] = wentry{ right: *(s.(* viewpoint.RightEntry)), qty: r.qty}
}

func ancester(views *viewpoint.ViewPointSet, p * viewpoint.RightEntry, d int32) * viewpoint.RightEntry {
	for ; d != 0; d-- {
		u, _ := views.Rights.FetchEntry(views.Db, &p.Father)
		p = u.(*viewpoint.RightEntry)
	}
	return p
}

func (d * stateDB) OptimizeWallet(views *viewpoint.ViewPointSet, t token.Token) {
	tokenType := t.TokenType
	if tokenType & 2 == 0 {
		return
	}
	m := make([]int, 0, len(d.wallet))
	entry := make(map[chainhash.Hash]*viewpoint.RightEntry)
	for i, r := range d.wallet {
		if r.Token.TokenType != tokenType || r.flag & deleteFlag == deleteFlag {
			continue
		}

		u, _ := views.Rights.FetchEntry(views.Db, r.Token.Rights)
		switch u.(type) {
		case *viewpoint.RightEntry:
			m = append(m, i)
			entry[*r.Token.Rights] = u.(*viewpoint.RightEntry)
			break
		case *viewpoint.RightSetEntry:
			continue
		}
	}

	for merge := true; merge; {
		merge = false
		for ii,i := range m {
			if d.wallet[i].flag & deleteFlag == deleteFlag {
				continue
			}
			r := d.wallet[i].Token.Rights
			sib := entry[*r].Sibling()
			if _, ok := entry[sib]; !ok {
				continue
			}
			for jj,j := range m {
				if d.wallet[j].flag & deleteFlag == deleteFlag {
					continue
				}
				if i != j && d.wallet[j].Token.Rights.IsEqual(&sib) {
					if tokenType & 1 == 0 {
						merge = true
						fv := int64(0)
						if d.wallet[i].Token.Value.(*token.NumToken).Val == d.wallet[j].Token.Value.(*token.NumToken).Val {
							if ii > jj {
								m = append(m[:ii], m[ii+1:]...)
								m = append(m[:jj], m[jj+1:]...)
							} else {
								m = append(m[:jj], m[jj+1:]...)
								m = append(m[:ii], m[ii+1:]...)
							}
							fv = d.wallet[i].Token.Value.(*token.NumToken).Val
							d.wallet[i].flag |= deleteFlag
							d.wallet[j].flag |= deleteFlag
						} else if d.wallet[i].Token.Value.(*token.NumToken).Val > d.wallet[j].Token.Value.(*token.NumToken).Val {
							m = append(m[:jj], m[jj+1:]...)
							fv = d.wallet[j].Token.Value.(*token.NumToken).Val
							d.wallet[i].Token.Value.(*token.NumToken).Val -= fv
							d.wallet[j].flag |= deleteFlag
						} else {
							m = append(m[:ii], m[ii+1:]...)
							fv = d.wallet[i].Token.Value.(*token.NumToken).Val
							d.wallet[j].Token.Value.(*token.NumToken).Val -= fv
							d.wallet[i].flag |= deleteFlag
						}
						if _, ok := entry[entry[*r].Father]; !ok {
							u, _ := views.Rights.FetchEntry(views.Db, &entry[*r].Father)
							entry[entry[*r].Father] = u.(*viewpoint.RightEntry)
						}
						m = append(m, len(d.wallet))
						tk := d.wallet[i].Token
						tk.Value.(*token.NumToken).Val = fv
						tk.Rights = &entry[*r].Father
						d.wallet = append(d.wallet, WalletItem{
							flag:outStoreFlag | dirtyFlag,
							Token: tk,
						})
					} else if d.wallet[i].Token.Value.(*token.HashToken).Hash.IsEqual(&d.wallet[j].Token.Value.(*token.HashToken).Hash) {
						merge = true
						m = append(m[:jj], m[jj+1:]...)
						d.wallet[j].flag |= deleteFlag
						d.wallet[i].Token.Rights = &entry[*r].Father
						if _, ok := entry[entry[*r].Father]; !ok {
							u, _ := views.Rights.FetchEntry(views.Db, &entry[*r].Father)
							entry[entry[*r].Father] = u.(*viewpoint.RightEntry)
						}
					}
				}
			}
		}
	}

	r := views.Rights.LookupEntry(*t.Rights)
	switch r.(type) {
	case *viewpoint.RightSetEntry:
		req := make(map[chainhash.Hash]bool)
		for _, p := range r.(*viewpoint.RightSetEntry).Rights {
			if _, ok := entry[p]; !ok {
				return
			}
			req[p] = false
		}
		min := int64(0x7fffffffffffffff)
		for _, p := range d.wallet {
			if p.Token.TokenType != tokenType || p.flag & deleteFlag == deleteFlag {
				continue
			}
			if tokenType & 1 == 0 {
				if p.Token.Value.(*token.NumToken).Val < min {
					min = p.Token.Value.(*token.NumToken).Val
				}
			} else if !p.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				continue
			} else {
				min = 1
			}
			req[*p.Token.Rights] = true
		}
		for _, p := range req {
			if !p {
				return
			}
		}
		for _, p := range d.wallet {
			if p.Token.TokenType != tokenType || p.flag & deleteFlag == deleteFlag {
				continue
			}
			if tokenType & 1 == 0 {
				if p.Token.Value.(*token.NumToken).Val > min {
					p.Token.Value.(*token.NumToken).Val -= min
				} else {
					p.flag |= deleteFlag
				}
			} else if !p.Token.Value.(*token.HashToken).Hash.IsEqual(&t.Value.(*token.HashToken).Hash) {
				continue
			} else {
				p.flag |= deleteFlag
			}
		}
		tk := t
		if tokenType & 1 == 0 {
			tk.Value.(*token.NumToken).Val = min
		}
		d.wallet = append(d.wallet, WalletItem{
			flag:outStoreFlag | dirtyFlag,
			Token: tk,
		})
	}
}

func (d * stateDB) GetState(loc * chainhash.Hash) *chainhash.Hash {
	if _,ok := d.data[*loc]; ok {
		if d.data[*loc].flag & deleteFlag != 0 {
			return nil
		}
	} else {
		var e []byte
		d.DB.View(func (dbTx  database.Tx) error {
			bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))
			e = bucket.Get((*loc)[:])
			return nil
		})
		
		if e == nil {
			return nil
		}

		d.data[*loc] = entry { flag: inStoreFlag }
		tmp := d.data[*loc].data
		copy(tmp[:], e)
		tmp = d.data[*loc].back
		copy(tmp[:], e)
	}
	dt := d.data[*loc].data
	return &dt
}

func (d * stateDB) SetState(loc * chainhash.Hash, val chainhash.Hash) {
	if _,ok := d.data[*loc]; ok {
		e := d.data[*loc]
		if e.flag & deleteFlag != 0 {
			e.flag ^= deleteFlag
			d.data[*loc] = e
		}

		if !val.IsEqual(&e.data) {
			e.data = val
			e.flag |= dirtyFlag
			d.data[*loc] = e
		}
	} else {
		if d.GetState(loc) == nil {
			d.data[*loc] = entry { data: val, flag: outStoreFlag | dirtyFlag }
		} else {
			dd := d.data[*loc].data
			if !val.IsEqual(&dd) {
				e := d.data[*loc]
				e.data = val
				e.flag |= dirtyFlag
				d.data[*loc] = e
			}
		}
	}
}

func (d * stateDB) DeleteState(loc * chainhash.Hash) {
	if d.GetState(loc) != nil {
		e := d.data[*loc]
		e.flag |= deleteFlag
		d.data[*loc] = e
	}
}

type RollBackData struct {
	Key	[]byte
	Flag	uint8
	Data	[]byte
}

func (d * stateDB) Exists() bool {
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

func (d * stateDB) LoadWallet() error {
	err := d.DB.View(func(dbTx database.Tx) error {
		// find out necessary spending
		bucket := dbTx.Metadata().Bucket([]byte("contract" + string(d.contract[:])))

		if bucket == nil {
			return omega.ScriptError(omega.ErrInternal, "Account not exist.")
		}

		if err := json.Unmarshal(bucket.Get([]byte("Wallet")), &d.wallet); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (d * stateDB) Commit(block uint64) {
	// for each block, it is called only once for each changed account
	for k,t := range d.data {
		if t.flag & (outStoreFlag | deleteFlag) ==  (outStoreFlag | deleteFlag) {
			delete(d.data, k)
		}
	}

	// prepare data for roll back
	roll := make([]RollBackData, 0, len(d.data) + 1)

	pwd := make([]WalletItem, 0, len(d.wallet))
	for _,w := range d.wallet {
		if w.flag & outStoreFlag ==  outStoreFlag {
			continue
		}
		pwd = append(pwd, WalletItem{ Token: w.back, flag: 0 } )
	}
	wd, _ := json.Marshal(pwd)

	roll = append(roll, RollBackData{Key: []byte("Wallet"), Flag: putFlag, Data: wd})

	for k,t := range d.data {
		if t.flag & outStoreFlag != 0  {
			roll = append(roll, RollBackData{Key: k[:], Flag: delFlag})
		} else {
			roll = append(roll, RollBackData{Key: k[:], Flag: putFlag, Data: t.back[:]})
		}
	}

	for k,t := range d.meta {
		if t.flag & outStoreFlag != 0  {
			roll = append(roll, RollBackData{Key: []byte(k[:]), Flag: delFlag})
		} else {
			roll = append(roll, RollBackData{Key: []byte(k[:]), Flag: putFlag, Data: t.back[:]})
		}
	}

	var dirtyaccount []byte

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

		if meta.Bucket([]byte("rollbacks")) == nil {
			if _, err := meta.CreateBucket([]byte("rollbacks")); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return
	}

	d.DB.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("storage" + string(d.contract[:])))

		for k,t := range d.data {
			if t.flag & deleteFlag != 0 {
				bucket.Delete(k[:])
				delete(d.data, k)
			} else if t.flag & dirtyFlag == dirtyFlag {
				if err := bucket.Put(k[:], t.data[:]); err != nil {
					return err
				}
				t.flag = inStoreFlag
				t.flag ^= dirtyFlag | outStoreFlag
				d.data[k] = t
			}
		}

		pwd = make([]WalletItem, 0, len(d.wallet))
		for _,w := range d.wallet {
			if w.flag & deleteFlag ==  deleteFlag {
				continue
			}
			pwd = append(pwd, w)
		}
		wd, _ := json.Marshal(pwd)
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
				t.flag ^= dirtyFlag | outStoreFlag
				d.meta[k] = t
			}
		}

		md, _ := json.Marshal(roll)
		bucket.Put([]byte(fmt.Sprintf("rollback%d", block)), md)

		bucket = dbTx.Metadata().Bucket([]byte("rollbacks"))
		key := []byte(fmt.Sprintf("block%d", block))

		dirtyaccount = bucket.Get(key)
		if dirtyaccount != nil {
			dirtyaccount = append(dirtyaccount, []byte(d.contract[:])...)
			bucket.Put(key, dirtyaccount)
		} else {
			bucket.Put(key, []byte(d.contract[:]))
		}

		rollbackto := bucket.Get([]byte("oldest"))
		if rollbackto == nil {
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], block)
			bucket.Put([]byte("oldest"), b[:])
		}

		return nil
	})
}

func RollBack(db database.DB, block uint64) {
	db.Update(func (dbTx  database.Tx) error {
		bucket := dbTx.Metadata().Bucket([]byte("rollbacks"))
		key := []byte(fmt.Sprintf("block%d", block))

		dirtyaccount := bucket.Get(key)
		bucket.Delete(key)

		key = []byte(fmt.Sprintf("rollback%d", block))
		for i := 0; i < len(dirtyaccount); i += 20 {
			account := dirtyaccount[i:i+20]

			bucket := dbTx.Metadata().Bucket([]byte("contract" + string(account)))
			rbd := bucket.Get(key)
			bucket.Delete(key)

			var data []RollBackData
			if err := json.Unmarshal(rbd, &data); err != nil {
				return err
			}

			for _,r := range data {
				switch string(r.Key) {
				case "Wallet", "code", "codeHash", "owner", "addres":
					bucket.Put([]byte(r.Key), r.Data[:])
					break
				}
			}

			bucket = dbTx.Metadata().Bucket([]byte("storage" + string(account)))
			for _,r := range data {
				switch string(r.Key) {
				case "Wallet", "code", "codeHash", "owner", "addres":
					break
				default:
					if r.Flag & delFlag != 0 {
						bucket.Delete(r.Key[:])
					} else if r.Flag & putFlag != 0 {
						bucket.Put(r.Key[:], r.Data[:])
					}
				}
			}
		}
		return nil
	})
}

func (d * stateDB) Maintenance(block uint64, rollbacklimit uint32) {
	// keep number of rollback record for upto most recent rollbacklimit blocks
	d.DB.Update(func (dbTx  database.Tx) error {
		var oldest int64

		bucket := dbTx.Metadata().Bucket([]byte("rollbacks"))
		rollbackto := bucket.Get([]byte("oldest"))
		if rollbackto != nil {
			oldest = int64(binary.LittleEndian.Uint64(rollbackto))
		} else {
			return nil
		}

		if oldest >= int64(block) - int64(rollbacklimit) {
			return nil
		}

		for ; oldest < int64(block) - int64(rollbacklimit); oldest++ {
			key := []byte(fmt.Sprintf("block%d", oldest))
			dirtyaccount := bucket.Get(key)
			bucket.Delete(key)

			key = []byte(fmt.Sprintf("rollback%d", oldest))
			for i := 0; i < len(dirtyaccount); i += 20 {
				account := dirtyaccount[i:i+20]
				dbTx.Metadata().Bucket([]byte("contract" + string(account))).Delete(key)
			}
		}
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(oldest))
		bucket.Put([]byte("oldest"), buf[:])
		return nil
	})
}
