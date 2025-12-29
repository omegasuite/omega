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

var RootMeta = []*ChainDescriptor{
	&ChainDescriptor{
		Magic:          0x4e585553,       // 0x956ca366,
		Dns:            "omegasuite.org", // "omegasuite.org",
		DefaultPort:    "9788",
		DefaultRPCPort: "9789",
		MRChain:        true,
		Parent:         0,
		ChainID:        ROOT,
		Genesis:        "00000035d7d4fe64711fc0737c4fba314a75884c02b64db7032537c8ddc774d7",
		MrGenesis:      "0000000efcf76ce079cedeccaa5cde15fff96db1aedcd85a7c3271a29b017966",
		GlobalParams:   "{\"Name\":\"mainnet\",\"Net\":1314411859,\"DefaultPort\":\"9788\",\"RpcPort\":\"9789\",\"DNSSeeds\":[{\"Host\":\"omegasuite.org\",\"HasFiltering\":false}],\"PowLimitBits\":503320560,\"CoinbaseMaturity\":20000,\"SubsidyReductionInterval\":42048000,\"MinimalAward\":0,\"TargetTimespan\":1209600000000000,\"TargetTimePerBlock\":60000000000,\"RetargetAdjustmentFactor\":4,\"RuleChangeActivationThreshold\":19160,\"MinerConfirmationWindow\":20160,\"Forfeit\":{\"Contract\":[136,26,82,15,169,77,142,7,59,11,70,121,67,91,85,9,165,198,132,125,179],\"Opening\":[124,239,138,115],\"Filing\":[178,24,22,90],\"Claim\":[68,144,2,248]},\"ViolationReportDeadline\":100,\"ChainID\":1}",
	},
	&ChainDescriptor{
		Magic:          0x4e585574,       // test net
		Dns:            "omegasuite.org", // "omegasuite.org",
		DefaultPort:    "7788",
		DefaultRPCPort: "7789",
		MRChain:        true,
		Parent:         0,
		ChainID:        ROOT,
		Genesis:        "00008fe8e80659516de85859541a664e8cf6e2303f7114a5e9116fd87f1828f4",
		MrGenesis:      "00034329829c304386050584e979589148d3540f665d5075b268377b20b5d9bc",
		GlobalParams:   "{\"Name\":\"testnet\",\"Net\":1314411892,\"DefaultPort\":\"7788\",\"RpcPort\":\"7789\",\"DNSSeeds\":[{\"Host\":\"omegasuite.org\",\"HasFiltering\":false}],\"PowLimitBits\":521142271,\"CoinbaseMaturity\":10,\"SubsidyReductionInterval\":42048000,\"MinimalAward\":0,\"TargetTimespan\":7200000000000,\"TargetTimePerBlock\":60000000000,\"RetargetAdjustmentFactor\":4,\"RuleChangeActivationThreshold\":75,\"MinerConfirmationWindow\":100,\"Forfeit\":{\"Contract\":[136,235,165,125,186,142,136,62,150,43,31,19,231,176,243,127,109,59,72,72,252],\"Opening\":[124,239,138,115],\"Filing\":[178,24,22,90],\"Claim\":[68,144,2,248]},\"ViolationReportDeadline\":10,\"ChainID\":1}",
	},
}

type FOCMap struct {
	ChainMap map[uint32]*ChainDescriptor
	dmdb     database.DB
}

var AllChains map[uint32]*FOCMap

func (m *FOCMap) Decendant(t *ChainDescriptor, cid uint32) bool {
	d, ok := m.ChainMap[cid]
	if !ok {
		return false
	}
	if t.ChainID == cid {
		return false
	}
	for d.Parent != t.ChainID && d.Parent != 0 {
		d, _ = m.ChainMap[d.Parent]
	}
	return d.Parent == t.ChainID
}

func (m *FOCMap) CtxFees(t *ChainDescriptor, dest uint32) (path [][]byte, fees []int64) {
	srctoroot := make([]*ChainDescriptor, 1)
	d := t
	srctoroot[0] = d
	for d.Parent != 0 {
		d, _ = m.ChainMap[d.Parent]
		srctoroot = append(srctoroot, d)
	}
	d = m.ChainMap[dest]
	if d == nil {
		return nil, nil
	}
	desttoroot := make([]*ChainDescriptor, 1)
	desttoroot[0] = d
	for d.Parent != 0 {
		d, _ = m.ChainMap[d.Parent]
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

func (m *FOCMap) PassThru(tid, src, dest uint32) bool {
	t, ok := m.ChainMap[tid]
	if !ok {
		return false
	}
	if tid == src || tid == dest {
		return true
	}
	sd := m.Decendant(t, src)
	dd := m.Decendant(t, dest)
	if sd != dd {
		return true
	}
	if !sd {
		return false
	}
	p := src
	for m.ChainMap[p].Parent != tid {
		p = m.ChainMap[p].Parent
	}
	q := dest
	for m.ChainMap[q].Parent != tid {
		q = m.ChainMap[q].Parent
	}
	return p != q
}

func LoadChainMap(db database.DB, testnet bool, chainid uint32) {
	if AllChains == nil {
		AllChains = make(map[uint32]*FOCMap)
	}

	m := FOCMap{}
	m.dmdb = db
	m.ChainMap = make(map[uint32]*ChainDescriptor)

	AllChains[chainid] = &m

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
			m.ChainMap[k] = (*ChainDescriptor)(t)
			s, _ := json.Marshal(t)
			fmt.Printf("chain data: %s\n", s)
		}

		bad := false

		for i, n := range m.ChainMap {
			if i != n.ChainID {
				bad = true
				break
			}
			if n.Parent == 0 && i != ROOT {
				bad = true
				break
			}
			if _, ok := m.ChainMap[n.Parent]; n.Parent != 0 && !ok {
				bad = true
				break
			}
		}

		if _, ok := m.ChainMap[ROOT]; !ok || bad {
			m.ChainMap = map[uint32]*ChainDescriptor{}
			net := 0
			if testnet {
				net = 1
			}
			m.ChainMap[ROOT] = RootMeta[net]

			meta.DeleteBucket(bucketname)
			bucket, _ = meta.CreateBucket(bucketname)
			bucket.Put([]byte{ROOT, 0, 0, 0}, (*wire.ChainDescriptor)(m.ChainMap[ROOT]).Serialize())
		}
		return nil
	})
}

func (m *FOCMap) AddChain(c *ChainDescriptor) bool {
	if c.ChainID != ROOT && c.Parent == 0 {
		return false
	}
	if c.ChainID == ROOT && c.Parent != 0 {
		return false
	}

	if _, ok := m.ChainMap[c.ChainID]; ok {
		return false
	}

	for _, d := range m.ChainMap {
		if d.Magic == c.Magic || (d.Dns == c.Dns && d.DefaultPort == c.DefaultRPCPort) || d.Genesis == c.Genesis || (c.MRChain && d.MRChain && d.MrGenesis == c.MrGenesis) {
			return false
		}
	}

	params := &chaincfg.GlobalParams{}
	err := json.Unmarshal([]byte(c.GlobalParams), params)
	if err != nil {
		panic("bad GlobalParams data")
	}

	m.dmdb.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(c).Serialize())
		m.ChainMap[c.ChainID] = c

		return nil
	})

	return true
}

func (m *FOCMap) RemoveChain(c uint32) {
	if _, ok := m.ChainMap[c]; !ok {
		return
	}

	if c == ROOT {
		return
	}

	m.dmdb.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c)

		bucket.Delete(cid[:])
		delete(m.ChainMap, c)

		return nil
	})
}

func Close() {
	// m.dmdb.Close()
}
