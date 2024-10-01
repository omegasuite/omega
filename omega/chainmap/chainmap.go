/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package chainmap

import (
	"encoding/hex"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcd/wire/common"
)

// chainmap is a map of blockchains in FOC.
const (
	ROOT = 1 // Chain ID of root blockchain, i.e. the Omega
)

type ChainDescriptor wire.ChainDescriptor

var ChainMap map[uint32]*ChainDescriptor

func (t *ChainDescriptor) Decendant(cid uint32) bool {
	d, ok := ChainMap[cid]
	if !ok {
		return false
	}
	if t.ChainID == cid {
		return false
	}
	for d.Parent != t.ChainID && d.Parent != 0 {
		d, _ = ChainMap[d.Parent]
	}
	return d.Parent == t.ChainID
}

func (t *ChainDescriptor) PassThru(src, dest uint32) bool {
	sd := t.Decendant(src)
	dd := t.Decendant(dest)
	if sd != dd {
		return true
	}
	if ChainMap[src].Decendant(dest) {
		return false
	}
	if ChainMap[dest].Decendant(src) {
		return false
	}
	return sd
}

var RootMeta = &ChainDescriptor{
	Magic:          0x956ca476,  // 0x956ca366,
	Dns:            "localhost", // "omegasuite.org",
	DefaultPort:    "8788",
	DefaultRPCPort: "8789",
	MRChain:        true,
	Parent:         0,
	ChainID:        ROOT,
	// Genesis: 0000000fca59d9ceb85d0c076c211bc84391d8de5352597e825c453a2f5be963
	// MrGenesis: 0000003c37c434f066dfed9f8569803dfcde9b318fc22b6b1fac11b32623a826
}

func LoadChainMap(db database.DB) {
	ChainMap = make(map[uint32]*ChainDescriptor)

	db.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		meta := tx.Metadata()
		bucket := meta.Bucket(bucketname)
		if bucket == nil {
			bucket, _ = meta.CreateBucket(bucketname)
		}
		cursor := bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			t := &wire.ChainDescriptor{}
			t.Deserialize(cursor.Value())
			k := common.LittleEndian.Uint32(cursor.Key())
			ChainMap[k] = (*ChainDescriptor)(t)
		}

		bad := false

		for i, m := range ChainMap {
			if i != m.ChainID {
				bad = true
				break
			}
			if m.Parent == 0 && i != ROOT {
				bad = true
				break
			}
			if _, ok := ChainMap[m.Parent]; m.Parent != 0 && !ok {
				bad = true
				break
			}
		}

		if _, ok := ChainMap[ROOT]; !ok || bad {
			ChainMap = map[uint32]*ChainDescriptor{}
			h, _ := hex.DecodeString("0000000fca59d9ceb85d0c076c211bc84391d8de5352597e825c453a2f5be963")
			RootMeta.Genesis.SetBytes(h)
			h, _ = hex.DecodeString("0000003c37c434f066dfed9f8569803dfcde9b318fc22b6b1fac11b32623a826")
			RootMeta.MrGenesis.SetBytes(h)
			ChainMap[ROOT] = RootMeta

			meta.DeleteBucket(bucketname)
			bucket, _ = meta.CreateBucket(bucketname)
			bucket.Put([]byte{1, 0, 0, 0}, (*wire.ChainDescriptor)(RootMeta).Serialize())
		}
		return nil
	})
}

func AddChain(db database.DB, c *ChainDescriptor) bool {
	if _, ok := ChainMap[c.ChainID]; ok {
		return true
	}

	for _, d := range ChainMap {
		if d.Magic == c.Magic || d.Dns == c.Dns || d.Genesis.IsEqual(&c.Genesis) || (c.MRChain && d.MRChain && d.MrGenesis.IsEqual(&c.MrGenesis)) {
			return false
		}
	}

	if c.ChainID != ROOT && c.Parent == 0 {
		return false
	}

	if _, ok := ChainMap[c.Parent]; c.Parent != 0 && !ok {
		return false
	}

	db.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(c).Serialize())
		ChainMap[c.ChainID] = c

		return nil
	})
	return true
}

func RemoveChain(db database.DB, c uint32) {
	if _, ok := ChainMap[c]; !ok {
		return
	}

	if c == ROOT {
		return
	}

	db.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c)

		bucket.Delete(cid[:])
		delete(ChainMap, c)

		return nil
	})
}
