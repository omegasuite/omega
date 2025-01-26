/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package chainmap

import (
	"encoding/json"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
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
	if t.ChainID == src || t.ChainID == dest {
		return true
	}
	sd := t.Decendant(src)
	dd := t.Decendant(dest)
	if sd != dd {
		return true
	}
	if !sd {
		return false
	}
	p := src
	for ChainMap[p].Parent != t.ChainID {
		p = ChainMap[p].Parent
	}
	q := dest
	for ChainMap[q].Parent != t.ChainID {
		q = ChainMap[q].Parent
	}
	return p != q
}

var RootMeta = &ChainDescriptor{
	Magic:          uint32(common.MainNet), // 0x956ca366,
	Dns:            "omegasuite.org",       // "omegasuite.org",
	DefaultPort:    "8788",
	DefaultRPCPort: "8789",
	MRChain:        true,
	Parent:         0,
	ChainID:        ROOT,
	Genesis:        "0000000fca59d9ceb85d0c076c211bc84391d8de5352597e825c453a2f5be963",
	MrGenesis:      "0000003c37c434f066dfed9f8569803dfcde9b318fc22b6b1fac11b32623a826",
}

var ParentChain = &ChainDescriptor{
	Magic:          0,  // 0x956ca366,
	Dns:            "", // "omegasuite.org",
	DefaultPort:    "",
	DefaultRPCPort: "",
	MRChain:        false,
	Parent:         0,
	ChainID:        0,
	Genesis:        "",
	MrGenesis:      "",
}

var dmdb database.DB

func LoadChainMap(db database.DB, isroot bool) {
	dmdb = db
	ChainMap = make(map[uint32]*ChainDescriptor)

	db.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		meta := tx.Metadata()

		meta.DeleteBucket(bucketname)

		bucket := meta.Bucket(bucketname)
		if bucket == nil {
			bucket, _ = meta.CreateBucket(bucketname)
		}
		cursor := bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			t := &wire.ChainDescriptor{}
			if !t.Deserialize(cursor.Value()) {
				break
			}
			k := common.LittleEndian.Uint32(cursor.Key())
			ChainMap[k] = (*ChainDescriptor)(t)
			s, _ := json.Marshal(t)
			fmt.Printf("chain data: %s\n", s)
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

		if _, ok := ChainMap[ROOT]; isroot && (!ok || bad) {
			ChainMap = map[uint32]*ChainDescriptor{}
			RootMeta.Genesis = "0000000fca59d9ceb85d0c076c211bc84391d8de5352597e825c453a2f5be963"
			RootMeta.MrGenesis = "0000003c37c434f066dfed9f8569803dfcde9b318fc22b6b1fac11b32623a826"
			ChainMap[ROOT] = RootMeta

			meta.DeleteBucket(bucketname)
			bucket, _ = meta.CreateBucket(bucketname)
			bucket.Put([]byte{1, 0, 0, 0}, (*wire.ChainDescriptor)(RootMeta).Serialize())
		}
		return nil
	})
}

func AddChain(c *ChainDescriptor) bool {
	if c.ChainID != ROOT && c.Parent == 0 {
		return false
	}
	if c.ChainID == ROOT && c.Parent != 0 {
		return false
	}

	if _, ok := ChainMap[c.ChainID]; ok {
		return true
	}

	for _, d := range ChainMap {
		if d.Magic == c.Magic || (d.Dns == c.Dns && d.DefaultPort == c.DefaultRPCPort) || d.Genesis == c.Genesis || (c.MRChain && d.MRChain && d.MrGenesis == c.MrGenesis) {
			return false
		}
	}

	params := &chaincfg.GlobalParams{}
	err := json.Unmarshal([]byte(c.GlobalParams), params)
	if err != nil {
		panic("bad GlobalParams data")
	}

	dmdb.Update(func(tx database.Tx) error {
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

func RemoveChain(c uint32) {
	if _, ok := ChainMap[c]; !ok {
		return
	}

	if c == ROOT {
		return
	}

	dmdb.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c)

		bucket.Delete(cid[:])
		delete(ChainMap, c)

		return nil
	})
}

func Close() {
	dmdb.Close()
}
