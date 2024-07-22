// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"sort"
	"sync"
)

type ChainId uint32
type Features struct {
	Version uint32
	Feature []int32
}

type FuncId uint32

const ( // Functionality ids
	FuncNothing = FuncId(0)
)

var allFuncs = map[ChainId]map[uint32]map[FuncId]struct{}{}
var featureLock sync.Mutex

func (ch ChainId) Enabled(version uint32, feature FuncId) bool {
	featureLock.Lock()
	defer featureLock.Unlock()

	if _, ok := allFuncs[ch]; !ok {
		return false
	}
	if _, ok := allFuncs[ch][version]; !ok {
		return false
	}
	_, ok := allFuncs[ch][version][feature]
	return ok
}

func (ch ChainId) DelVersion(db database.DB, version uint32) {
	featureLock.Lock()
	defer featureLock.Unlock()

	delete(allFuncs[ch][version], FuncId(version))

	db.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte("functionality"))

		var h [4]byte
		common.LittleEndian.PutUint32(h[:], uint32(ch))
		bucket2 := bucket.Bucket(h[:])

		common.LittleEndian.PutUint32(h[:], version)
		bucket2.Delete(h[:])
		return nil
	})

	allFuncs = map[ChainId]map[uint32]map[FuncId]struct{}{}
	LoadFunctionalityTable(db)
}

func (ch ChainId) AddFunctionalityVersion(db database.DB, version uint32, funcs []int32) bool {
	featureLock.Lock()
	defer featureLock.Unlock()

	t := allFuncs[ch]
	u := make(map[FuncId]struct{})
	m := uint32(0)
	for v, w := range t {
		if v > m {
			m, u = v, w
		}
	}
	if m >= version {
		return false
	}
	accum := make(map[FuncId]struct{})
	for k, f := range u {
		accum[k] = f
	}
	for _, f := range funcs {
		if f < 0 {
			delete(accum, FuncId(f))
		} else {
			accum[FuncId(f)] = struct{}{}
		}
	}
	allFuncs[ch][version] = accum

	db.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte("functionality"))
		if bucket == nil {
			bucket, _ = tx.Metadata().CreateBucket([]byte("functionality"))
		}

		chains := bucket.Get([]byte("chainids"))

		for i := 0; i < len(chains); i += 4 {
			b := common.LittleEndian.Uint32(chains[i : i+4])
			bucket2 := bucket.Bucket(chains[i : i+4])

			if bucket2 == nil {
				bucket2, _ = bucket.CreateBucket(chains[i : i+4])
			}
			cursor := bucket2.Cursor()
			fl := make([]Features, 0)
			for ok := cursor.First(); ok; ok = cursor.Next() {
				v := common.LittleEndian.Uint32(cursor.Key())
				f := cursor.Value()
				fs := make([]int32, len(f)/4)
				for j := 0; j < len(f); j += 4 {
					fs[j/4] = int32(common.LittleEndian.Uint32(f[j : j+4]))
				}
				fl = append(fl, Features{
					Version: v,
					Feature: fs,
				})
			}

			sort.Slice(fl, func(i, j int) bool {
				return fl[i].Version < fl[j].Version
			})
			res := make(map[uint32]map[FuncId]struct{})
			accum := make(map[FuncId]struct{})
			for _, f := range fl {
				for _, g := range f.Feature {
					if g > 0 {
						accum[FuncId(g)] = struct{}{}
					} else {
						delete(accum, FuncId(g))
					}
				}
				dup := make(map[FuncId]struct{})
				for k, v := range accum {
					dup[k] = v
				}
				res[f.Version] = dup
			}
			allFuncs[ChainId(b)] = res
		}

		return nil
	})

	return true
}

func LoadFunctionalityTable(db database.DB) {
	db.View(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte("functionality"))
		chains := bucket.Get([]byte("chainids"))

		for i := 0; i < len(chains); i += 4 {
			b := common.LittleEndian.Uint32(chains[i : i+4])
			bucket2 := bucket.Bucket(chains[i : i+4])
			cursor := bucket2.Cursor()
			fl := make([]Features, 0)
			for ok := cursor.First(); ok; ok = cursor.Next() {
				v := common.LittleEndian.Uint32(cursor.Key())
				f := cursor.Value()
				fs := make([]int32, len(f)/4)
				for j := 0; j < len(f); j += 4 {
					fs[j/4] = int32(common.LittleEndian.Uint32(f[j : j+4]))
				}
				fl = append(fl, Features{
					Version: v,
					Feature: fs,
				})
			}

			sort.Slice(fl, func(i, j int) bool {
				return fl[i].Version < fl[j].Version
			})
			res := make(map[uint32]map[FuncId]struct{})
			accum := make(map[FuncId]struct{})
			for _, f := range fl {
				for _, g := range f.Feature {
					if g > 0 {
						accum[FuncId(g)] = struct{}{}
					} else {
						delete(accum, FuncId(g))
					}
				}
				dup := make(map[FuncId]struct{})
				for k, v := range accum {
					dup[k] = v
				}
				res[f.Version] = dup
			}
			allFuncs[ChainId(b)] = res
		}

		return nil
	})
}
