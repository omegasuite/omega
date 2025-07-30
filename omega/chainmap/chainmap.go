/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package chainmap

import (
	"btcd/chaincfg"
	"btcd/database"
	"btcd/wire"
	"btcd/wire/common"
	"encoding/json"
	"fmt"
	"omega/ovm"
)

// chainmap is a map of blockchains in FOC.
const (
	ROOT                    = 1 // Chain ID of root blockchain, i.e. the Omega
	CrossChainTxFeePerChain = 1e5
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

func (t *ChainDescriptor) CtxFees(dest uint32) (path [][]byte, fees []int64) {
	srctoroot := make([]*ChainDescriptor, 1)
	d := t
	srctoroot[0] = d
	for d.Parent != 0 {
		d, _ = ChainMap[d.Parent]
		srctoroot = append(srctoroot, d)
	}
	d = ChainMap[dest]
	if d == nil {
		return nil, nil
	}
	desttoroot := make([]*ChainDescriptor, 1)
	desttoroot[0] = d
	for d.Parent != 0 {
		d, _ = ChainMap[d.Parent]
		desttoroot = append(desttoroot, d)
	}
	// reverse path
	trm := false
	for i, j := len(srctoroot), len(desttoroot); i > 0 && j > 0; {
		nt := srctoroot[i-1].ChainID == desttoroot[j-1].ChainID
		if trm && nt {
			srctoroot = srctoroot[:len(srctoroot)-1]
			desttoroot = desttoroot[:len(desttoroot)-1]
		}
		if trm && !nt {
			break
		}
		trm = nt
		i--
		j--
	}

	if trm {
		desttoroot = desttoroot[:len(desttoroot)-1]
	}

	for i := len(desttoroot) - 1; i >= 0; i-- {
		srctoroot = append(srctoroot, desttoroot[i])
	}

	path, fees = make([][]byte, 0), make([]int64, 0)
	for i := 0; i < len(srctoroot); i++ {
		path, fees = append(path, srctoroot[i].FeeScript()), append(fees, srctoroot[i].FeeAmount())
	}
	return path, fees
}

func (t *ChainDescriptor) FeeScript() []byte {
	var s [26]byte
	for i := 0; i < 25; i++ {
		s[i] = 0
	}
	s[1] = 1
	common.LittleEndian.PutUint32(s[22:], t.ChainID)
	s[21] = ovm.OP_PAYMINER
	return s[:25]
}

func (t *ChainDescriptor) FeeAmount() int64 {
	// for now, flat 100 Satoshi. in the future, it would be chain dependent
	return CrossChainTxFeePerChain
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

var RootMeta = map[common.OmegaNet]*ChainDescriptor{
	common.MainNet: &ChainDescriptor{
		Magic:          0x4e585553,  // 0x956ca366,
		Dns:            "localhost", // "omegasuite.org",
		DefaultPort:    "8788",
		DefaultRPCPort: "8789",
		MRChain:        true,
		Parent:         0,
		ChainID:        ROOT,
		Genesis:        "0000000fca59d9ceb85d0c076c211bc84391d8de5352597e825c453a2f5be963",
		MrGenesis:      "0000003c37c434f066dfed9f8569803dfcde9b318fc22b6b1fac11b32623a826",
	},
	common.TestNet: &ChainDescriptor{
		Magic:          0x4e585574,  // test net
		Dns:            "localhost", // "omegasuite.org",
		DefaultPort:    "7788",
		DefaultRPCPort: "7789",
		MRChain:        true,
		Parent:         0,
		ChainID:        ROOT,
		Genesis:        "003b7c24ab8d47386f6acb9ce1ac87c8861db46340747f50b83ca3f2f8de6585",
		MrGenesis:      "000634587726987c5624c4f6b0b952499c03983a245df6ad83a8bc88b6e89d61",
	},
}

var useNet = common.MainNet

var dmdb database.DB

func LoadChainMap(db database.DB, isroot bool, net common.OmegaNet) {
	dmdb = db
	useNet = net
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
			ChainMap[ROOT] = RootMeta[useNet]

			meta.DeleteBucket(bucketname)
			bucket, _ = meta.CreateBucket(bucketname)
			bucket.Put([]byte{1, 0, 0, 0}, (*wire.ChainDescriptor)(RootMeta[useNet]).Serialize())
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
