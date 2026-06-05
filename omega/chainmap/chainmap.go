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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"slices"
)

// chainmap is a map of blockchains in FOC.
const (
	ROOT                    = 1 // Chain ID of root blockchain, i.e. the Omega
	BOVM                    = 4
	CrossChainTxFeePerChain = 1e5
)

type ChainDescriptor wire.ChainDescriptor

var RootMeta = []*ChainDescriptor{
	&ChainDescriptor{
		Version:        0x10000,
		Magic:          0x4e585553, // 0x956ca366,
		MRChain:        true,
		Genesis:        "00000035d7d4fe64711fc0737c4fba314a75884c02b64db7032537c8ddc774d7",
		MrGenesis:      "0000000efcf76ce079cedeccaa5cde15fff96db1aedcd85a7c3271a29b017966",
		Parent:         0,
		ChainID:        ROOT,
		Dns:            "omegasuite.org", // "omegasuite.org",
		DefaultPort:    "9788",
		DefaultRPCPort: "9789",
		Height:         0,
		GlobalParams:   "{\"Name\":\"mainnet\",\"Net\":1314411859,\"DefaultPort\":\"9788\",\"RpcPort\":\"9789\",\"DNSSeeds\":[{\"Host\":\"omegasuite.org\",\"HasFiltering\":false}],\"PowLimitBits\":503320560,\"CoinbaseMaturity\":20000,\"SubsidyReductionInterval\":42048000,\"MinimalAward\":0,\"TargetTimespan\":1209600000000000,\"TargetTimePerBlock\":60000000000,\"RetargetAdjustmentFactor\":4,\"RuleChangeActivationThreshold\":19160,\"MinerConfirmationWindow\":20160,\"Forfeit\":{\"Contract\":[136,26,82,15,169,77,142,7,59,11,70,121,67,91,85,9,165,198,132,125,179],\"Opening\":[124,239,138,115],\"Filing\":[178,24,22,90],\"Claim\":[68,144,2,248]},\"ViolationReportDeadline\":100,\"ChainID\":1}",
		Legacy:         false,
		Final:          21,
	},
	&ChainDescriptor{
		Version:        0x10000,
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
		Legacy:         false,
		Final:          21,
	},
}

type FOCMap struct {
	ChainMap map[uint32]*ChainDescriptor
	Params   map[uint32]*chaincfg.GlobalParams
	dmdb     database.DB
}

var AllChains map[uint32]*FOCMap

var ChainmapBucketname = []byte("ChainMap")

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
	srctoroot := make([]*ChainDescriptor, 0)
	d := t
	if d.Legacy {
		return [][]byte{}, []int64{}
	}
	srctoroot = append(srctoroot, d)
	for d.Parent != 0 {
		d, _ = m.ChainMap[d.Parent]
		srctoroot = append(srctoroot, d)
	}
	d = m.ChainMap[dest]
	if d == nil {
		return nil, nil
	}
	desttoroot := make([]*ChainDescriptor, 0)
	if !d.Legacy {
		desttoroot = append(desttoroot, d)
	}
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
		// if srctoroot[i].Legacy {
		//	continue
		// }
		path, fees = append(path, srctoroot[i].FeeScript()), append(fees, int64(m.Params[srctoroot[i].ChainID].MinCCTXFee))
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
	s[21] = 0x44 // ovm.OP_PAYMINER
	return s[:25]
}

var LegacyXChainFee func(chainid uint32, native bool) int64

func (m *FOCMap) findPath(src, dest uint32) []uint32 {
	path1, path2 := []uint32{}, []uint32{}

	for t := src; t != 0; {
		path1 = append(path1, t)
		t = m.ChainMap[t].Parent
	}
	for t := dest; t != 0; {
		path2 = append(path2, t)
		t = m.ChainMap[t].Parent
	}
	mm, n := len(path1)-1, len(path2)-1
	for mm >= 0 && n >= 0 && path1[mm] == path2[n] {
		mm--
		n--
	}
	path1 = path1[:mm+2]
	path2 = path2[:n+1]

	slices.Reverse(path2)

	return append(path1, path2...)
}

func (m *FOCMap) Permission(asset, src, dest uint32) bool {
	// whether it is a pemissible cross chain xfer
	path1 := m.findPath(asset, src)
	path2 := m.findPath(src, dest)

	if slices.Index(path1, path2[1]) < 0 {
		return true
	}

	for i := 1; i < len(path2); i++ {
		if slices.Index(path1, path2[i]) < 0 {
			return false
		}
	}
	return true
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

func LoadChainMap(db database.DB, testnet bool, chainid uint32, legacyXChainFee func(chainid uint32, native bool) int64) {
	LegacyXChainFee = legacyXChainFee
	if AllChains == nil {
		AllChains = make(map[uint32]*FOCMap)
	}

	m := FOCMap{}
	m.dmdb = db
	m.ChainMap = make(map[uint32]*ChainDescriptor)
	m.Params = make(map[uint32]*chaincfg.GlobalParams)

	AllChains[chainid] = &m

	db.Update(func(tx database.Tx) error {
		meta := tx.Metadata()
		bucket := meta.Bucket(ChainmapBucketname)
		if bucket == nil {
			bucket, _ = meta.CreateBucket(ChainmapBucketname)
		}
		cursor := bucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			t := &wire.ChainDescriptor{
				Version: 0x10000,
				Legacy:  false,
				Final:   21,
			}
			k := common.LittleEndian.Uint32(cursor.Key())
			v := cursor.Value()
			if !t.Deserialize(v) {
				if chainid != ROOT {
					if tt, ok := AllChains[ROOT].ChainMap[k]; ok {
						bucket.Put(cursor.Key(), (*wire.ChainDescriptor)(tt).Serialize())
						*t = *((*wire.ChainDescriptor)(tt))
					} else {
						continue
					}
				} else {
					continue
				}
			}

			gp := chaincfg.GlobalParams{}
			json.Unmarshal([]byte(t.GlobalParams), &gp)
			if gp.MinCCTXFee == 0 && !t.Legacy {
				gp.MinCCTXFee = CrossChainTxFeePerChain
				m, _ := json.Marshal(&gp)
				t.GlobalParams = string(m)
				bucket.Put(cursor.Key(), t.Serialize())
			}
			if gp.CommitteeSize == 0 {
				gp.CommitteeSize = 3
				gp.POWRotate = 2
				gp.CommitteeSigs = 2
			}

			m.ChainMap[k] = (*ChainDescriptor)(t)
			m.Params[k] = &gp
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

			meta.DeleteBucket(ChainmapBucketname)
			bucket, _ = meta.CreateBucket(ChainmapBucketname)
			bucket.Put([]byte{ROOT, 0, 0, 0}, (*wire.ChainDescriptor)(m.ChainMap[ROOT]).Serialize())
		}
		return nil
	})
}

func (m *FOCMap) ChgParam(cd *ChainDescriptor) bool {
	if m.ChainMap[cd.ChainID].Version+0x10000 != cd.Version {
		return false
	}
	m.ChainMap[cd.ChainID].Version = cd.Version

	s := chaincfg.GlobalParams{}
	json.Unmarshal([]byte(m.ChainMap[cd.ChainID].GlobalParams), &s)

	t := chaincfg.GlobalParams{}
	json.Unmarshal([]byte(cd.GlobalParams), &t)

	if len(t.DNSSeeds) > 0 {
		s.DNSSeeds = append(s.DNSSeeds, t.DNSSeeds...)
	}

	if t.PowLimitBits != 0 {
		s.PowLimitBits ^= t.PowLimitBits
	}
	if t.CoinbaseMaturity != 0 {
		s.CoinbaseMaturity ^= t.CoinbaseMaturity
	}
	if t.SubsidyReductionInterval != 0 {
		s.SubsidyReductionInterval ^= t.SubsidyReductionInterval
	}
	if t.MinimalAward != 0 {
		s.MinimalAward ^= t.MinimalAward
	}
	if t.TargetTimespan != 0 {
		s.TargetTimespan ^= t.TargetTimespan
	}
	if t.TargetTimePerBlock != 0 {
		s.TargetTimePerBlock ^= t.TargetTimePerBlock
	}
	if t.RetargetAdjustmentFactor != 0 {
		s.RetargetAdjustmentFactor ^= t.RetargetAdjustmentFactor
	}
	if t.RuleChangeActivationThreshold != 0 {
		s.RuleChangeActivationThreshold ^= t.RuleChangeActivationThreshold
	}
	if t.MinerConfirmationWindow != 0 {
		s.MinerConfirmationWindow ^= t.MinerConfirmationWindow
	}
	if t.ViolationReportDeadline != 0 {
		s.ViolationReportDeadline ^= t.ViolationReportDeadline
	}
	if bytes.Compare(t.Forfeit.Contract[:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
		for i, d := range t.Forfeit.Contract {
			s.Forfeit.Contract[i] ^= d
		}
		for i, d := range t.Forfeit.Claim {
			s.Forfeit.Claim[i] ^= d
		}
		for i, d := range t.Forfeit.Filing {
			s.Forfeit.Filing[i] ^= d
		}
		for i, d := range t.Forfeit.Opening {
			s.Forfeit.Opening[i] ^= d
		}
	}
	if t.CommitteeSize != 0 {
		s.CommitteeSize ^= t.CommitteeSize
	}
	if t.CommitteeSigs != 0 {
		s.CommitteeSigs ^= t.CommitteeSigs
	}
	if t.POWRotate != 0 {
		s.POWRotate ^= t.POWRotate
	}
	if t.MinBorderFee != 0 {
		s.MinBorderFee ^= t.MinBorderFee
	}
	if t.MinContractDeployFee != 0 {
		s.MinContractDeployFee ^= t.MinContractDeployFee
	}
	if t.MinRelayTxFee != 0 {
		s.MinRelayTxFee ^= t.MinRelayTxFee
	}
	if t.ContractExecFee != 0 {
		s.ContractExecFee ^= t.ContractExecFee
	}
	if t.MinBorderFee != 0 {
		s.MinBorderFee ^= t.MinBorderFee
	}
	if t.MinCCTXFee != 0 {
		s.MinCCTXFee ^= t.MinCCTXFee
	}

	if len(t.Checkpoints) > 0 {
		s.Checkpoints = append(s.Checkpoints, t.Checkpoints...)
	}

	ms, _ := json.Marshal(s)

	m.ChainMap[cd.ChainID].GlobalParams = string(ms)
	m.ChainMap[cd.ChainID].Version += 0x10000

	m.dmdb.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], cd.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(m.ChainMap[cd.ChainID]).Serialize())

		return nil
	})
	return true
}

func (m *FOCMap) RevertParam(cd *ChainDescriptor) bool {
	if m.ChainMap[cd.ChainID].Version != cd.Version {
		return false
	}

	m.ChainMap[cd.ChainID].Version -= 0x10000
	s := chaincfg.GlobalParams{}
	json.Unmarshal([]byte(m.ChainMap[cd.ChainID].GlobalParams), &s)

	t := chaincfg.GlobalParams{}
	json.Unmarshal([]byte(cd.GlobalParams), &t)

	if len(t.DNSSeeds) > 0 {
		s.DNSSeeds = s.DNSSeeds[:len(s.DNSSeeds)-len(t.DNSSeeds)]
	}

	if t.PowLimitBits != 0 {
		s.PowLimitBits ^= t.PowLimitBits
	}
	if t.CoinbaseMaturity != 0 {
		s.CoinbaseMaturity ^= t.CoinbaseMaturity
	}
	if t.SubsidyReductionInterval != 0 {
		s.SubsidyReductionInterval ^= t.SubsidyReductionInterval
	}
	if t.MinimalAward != 0 {
		s.MinimalAward ^= t.MinimalAward
	}
	if t.TargetTimespan != 0 {
		s.TargetTimespan ^= t.TargetTimespan
	}
	if t.TargetTimePerBlock != 0 {
		s.TargetTimePerBlock ^= t.TargetTimePerBlock
	}
	if t.RetargetAdjustmentFactor != 0 {
		s.RetargetAdjustmentFactor ^= t.RetargetAdjustmentFactor
	}
	if t.RuleChangeActivationThreshold != 0 {
		s.RuleChangeActivationThreshold ^= t.RuleChangeActivationThreshold
	}
	if t.MinerConfirmationWindow != 0 {
		s.MinerConfirmationWindow ^= t.MinerConfirmationWindow
	}
	if t.ViolationReportDeadline != 0 {
		s.ViolationReportDeadline ^= t.ViolationReportDeadline
	}
	if bytes.Compare(t.Forfeit.Contract[1:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
		for i, d := range t.Forfeit.Contract {
			s.Forfeit.Contract[i] ^= d
		}
		for i, d := range t.Forfeit.Claim {
			s.Forfeit.Claim[i] ^= d
		}
		for i, d := range t.Forfeit.Filing {
			s.Forfeit.Filing[i] ^= d
		}
		for i, d := range t.Forfeit.Opening {
			s.Forfeit.Opening[i] ^= d
		}
	}
	if t.CommitteeSize != 0 {
		s.CommitteeSize ^= t.CommitteeSize
	}
	if t.CommitteeSigs != 0 {
		s.CommitteeSigs ^= t.CommitteeSigs
	}
	if t.POWRotate != 0 {
		s.POWRotate ^= t.POWRotate
	}
	if t.MinBorderFee != 0 {
		s.MinBorderFee ^= t.MinBorderFee
	}
	if t.MinContractDeployFee != 0 {
		s.MinContractDeployFee ^= t.MinContractDeployFee
	}
	if t.MinRelayTxFee != 0 {
		s.MinRelayTxFee ^= t.MinRelayTxFee
	}
	if t.ContractExecFee != 0 {
		s.ContractExecFee ^= t.ContractExecFee
	}
	if t.MinBorderFee != 0 {
		s.MinBorderFee ^= t.MinBorderFee
	}
	if t.MinCCTXFee != 0 {
		s.MinCCTXFee ^= t.MinCCTXFee
	}
	if len(t.Checkpoints) > 0 {
		s.Checkpoints = s.Checkpoints[:len(s.Checkpoints)-len(t.Checkpoints)]
	}

	ms, _ := json.Marshal(t)

	m.ChainMap[cd.ChainID].GlobalParams = string(ms)

	m.dmdb.Update(func(tx database.Tx) error {
		bucketname := []byte("ChainMap")
		bucket := tx.Metadata().Bucket(bucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], cd.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(m.ChainMap[cd.ChainID]).Serialize())

		return nil
	})
	return true
}

func (m *FOCMap) AddDns(cd *ChainDescriptor) bool {
	param := chaincfg.GlobalParams{}
	param.CommitteeSize, param.CommitteeSigs, param.POWRotate = 3, 2, 2

	json.Unmarshal([]byte(m.ChainMap[cd.ChainID].GlobalParams), &param)
	exist := false
	for _, d := range param.DNSSeeds {
		if d.Host == cd.Dns {
			exist = true
		}
	}
	if !exist {
		param.DNSSeeds = append(param.DNSSeeds, chaincfg.DNSSeed{Host: cd.Dns, HasFiltering: false})
		md, err := json.Marshal(param)
		if err == nil {
			m.ChainMap[cd.ChainID].GlobalParams = string(md)

			m.dmdb.Update(func(tx database.Tx) error {
				bucketname := []byte("ChainMap")
				bucket := tx.Metadata().Bucket(bucketname)

				var cid [4]byte
				common.LittleEndian.PutUint32(cid[:], cd.ChainID)

				bucket.Put(cid[:], (*wire.ChainDescriptor)(m.ChainMap[cd.ChainID]).Serialize())

				return nil
			})
		}
	}
	return true
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
	params.CommitteeSize = 3
	params.CommitteeSigs = 2
	params.POWRotate = 2
	if !c.Legacy {
		params.MinCCTXFee = CrossChainTxFeePerChain
	}

	err := json.Unmarshal([]byte(c.GlobalParams), params)
	if err != nil {
		panic("bad GlobalParams data")
	}

	m.dmdb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket(ChainmapBucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(c).Serialize())
		m.ChainMap[c.ChainID] = c
		m.Params[c.ChainID] = params

		return nil
	})

	return true
}

func (m *FOCMap) RemoveDns(c *ChainDescriptor) {
	param := chaincfg.GlobalParams{}
	param.CommitteeSize = 3
	param.CommitteeSigs = 2
	param.POWRotate = 2

	json.Unmarshal([]byte(m.ChainMap[c.ChainID].GlobalParams), &param)
	for i, d := range param.DNSSeeds {
		if d.Host == c.Dns {
			param.DNSSeeds = append(param.DNSSeeds[:i], param.DNSSeeds[i+1:]...)
		}
	}
	t, _ := json.Marshal(param)
	m.ChainMap[c.ChainID].GlobalParams = string(t)
	m.dmdb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket(ChainmapBucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c.ChainID)

		bucket.Put(cid[:], (*wire.ChainDescriptor)(m.ChainMap[c.ChainID]).Serialize())

		return nil
	})
}

func (m *FOCMap) RemoveChain(c uint32) {
	if _, ok := m.ChainMap[c]; !ok {
		return
	}

	if c == ROOT {
		return
	}

	fmt.Printf("Remove chain %d from chainmap", c)

	m.dmdb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket(ChainmapBucketname)

		var cid [4]byte
		common.LittleEndian.PutUint32(cid[:], c)

		bucket.Delete(cid[:])
		delete(m.ChainMap, c)

		return nil
	})
}

func Close() {
	for _, m := range AllChains {
		m.dmdb.Close()
	}
}

func FromLegacy(tx *wire.MsgTx) bool { // whether it is a TX from BTC to L2 xfer
	f := len(tx.TxIn) == 1 &&
		!tx.TxIn[0].PreviousOutPoint.Hash.IsEqual(&chainhash.Hash{}) &&
		(tx.TxIn[0].PreviousOutPoint.Index&wire.CrossChainFalg != 0)
	if !f {
		return false
	}
	if t, ok := AllChains[ROOT].ChainMap[tx.TxIn[0].PreviousOutPoint.Index&^wire.CrossChainFalg]; ok {
		return t.Legacy
	}

	return false
}
