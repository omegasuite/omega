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
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire/common"
)

// chainmap is a map of blockchains in FOC.
const (
	ROOT = 1 // Chain ID of root blockchain, i.e. the Omega
)

type ChainDescriptor struct {
	Magic          uint32
	MRChain        bool
	Genesis        chainhash.Hash
	MrGenesis      chainhash.Hash
	Parent         uint32
	ChainID        uint32
	Mature         uint32
	Dns            string
	DefaultPort    string
	DefaultRPCPort string
}

var ChainMap map[uint32]*ChainDescriptor

func (t *ChainDescriptor) Serialize() []byte {
	res := make([]byte, 81+12)
	common.LittleEndian.PutUint32(res[:], t.Magic)
	if t.MRChain {
		res[4] = 1
	} else {
		res[4] = 0
	}
	copy(res[5:], t.Genesis[:])
	copy(res[37:], t.MrGenesis[:])
	common.LittleEndian.PutUint32(res[69:], t.Parent)
	common.LittleEndian.PutUint32(res[73:], t.ChainID)
	common.LittleEndian.PutUint32(res[77:], t.Mature)
	common.LittleEndian.PutUint32(res[81:], uint32(len(t.Dns)))
	common.LittleEndian.PutUint32(res[85:], uint32(len(t.DefaultPort)))
	common.LittleEndian.PutUint32(res[89:], uint32(len(t.DefaultRPCPort)))
	res = append(res, []byte(t.Dns)...)
	res = append(res, []byte(t.DefaultPort)...)
	res = append(res, []byte(t.DefaultRPCPort)...)
	return res
}

func (t *ChainDescriptor) Deserialize(res []byte) bool {
	ln := len(res)
	if ln < 81+12 {
		return false
	}
	t.Magic = common.LittleEndian.Uint32(res[:])
	if res[4] == 1 {
		t.MRChain = true
	} else {
		t.MRChain = false
	}

	copy(t.Genesis[:], res[5:])
	copy(t.MrGenesis[:], res[37:])
	t.Parent = common.LittleEndian.Uint32(res[69:])
	t.ChainID = common.LittleEndian.Uint32(res[73:])
	t.Mature = common.LittleEndian.Uint32(res[77:])
	n := common.LittleEndian.Uint32(res[81:])
	m := common.LittleEndian.Uint32(res[85:])
	k := common.LittleEndian.Uint32(res[89:])
	if uint32(ln) != 93+n+m+k {
		return false
	}

	t.Dns = string(res[93 : 93+n])
	t.DefaultPort = string(res[93+n : 93+n+m])
	t.DefaultRPCPort = string(res[93+n+m : 93+n+m+k])

	return true
}

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

var RootMeta = ChainDescriptor{
	Magic:          0x956ca366,
	Dns:            "omegasuite.org",
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
		bucket := tx.Metadata().Bucket(bucketname)
		cursor := bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			t := &ChainDescriptor{}
			t.Deserialize(cursor.Value())
			k := common.LittleEndian.Uint32(cursor.Key())
			ChainMap[k] = t
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
			ChainMap[ROOT] = &RootMeta

			tx.Metadata().DeleteBucket(bucketname)
			bucket, _ = tx.Metadata().CreateBucket(bucketname)
			bucket.Put([]byte{1, 0, 0, 0}, RootMeta.Serialize())
		}
		return nil
	})
}
