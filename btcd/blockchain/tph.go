// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"time"
)

const maxRcdPerMiner = 10		// max records we keep for each miner
const CONTRACTTXRATIO = 30		// when calculating TPS, every 30 contract exec steps = 1 sig

// TPHRecord houses information about miners's TPS record.
//
type TphPocket struct {
	StartTime		time.Time
	EndTime			time.Time
	StartBlock		uint32
	EndBlock		uint32
	TxTotal			uint32
}

type TPHRecord struct {
	// data to be stored in DB @ exit
	TPHscore uint32      // TPS score: tx per hour
	History  []TphPocket // upto maxRcdPerMiner records

	// on-going state
	current TphPocket
}

func (b *BlockChain) GetMinerTPS(miner [20]byte) *TPHRecord {
	if t,ok := b.MinerTPH[miner]; ok {
		return t
	}

	tps := &TPHRecord{
		TPHscore: 0,
		History:  make([]TphPocket, 0, maxRcdPerMiner),
	}
	tps.current.TxTotal, tps.current.StartBlock, tps.current.EndBlock = 0,0,0

	b.db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(minerTPSBucketName)
		serialized := bucket.Get(miner[:])
		if serialized == nil || len(serialized) == 0 {
			return nil
		}
		tps.TPHscore = byteOrder.Uint32(serialized)
		n := serialized[4]
		pos := 5
		for i := byte(0); i < n; i++ {
			p := TphPocket{}
			p.StartTime = time.Unix(int64(byteOrder.Uint32(serialized[pos:])), 0)
			pos += 4
			p.EndTime = time.Unix(int64(byteOrder.Uint32(serialized[pos:])), 0)
			pos += 4
			p.StartBlock = byteOrder.Uint32(serialized[pos:])
			pos += 4
			p.EndBlock = byteOrder.Uint32(serialized[pos:])
			pos += 4
			p.TxTotal = byteOrder.Uint32(serialized[pos:])
			pos += 4
			tps.History = append(tps.History, p)
		}
		return nil
	})

	b.MinerTPH[miner] = tps

	return tps
}

func (b *BlockChain) updateTPS(miner [20]byte, t *TPHRecord) {
	tm := int64(0)
	tx := uint32(0)
	idealtime := int64(0)
	for _, p := range t.History {
		tm += p.EndTime.Unix() - p.StartTime.Unix()
		tx += p.TxTotal
		idealtime += 3 * int64(p.EndBlock-p.StartBlock)
	}

	f := int64(10)
	if tm > idealtime {
		f = tm * 10 / idealtime
	}
	// if less than 3 sec/block, take it as if 3 sec/block.
	// we don't want it faster than block/3 sec

	if tm < 3600 {
		t.TPHscore = tx * 10 / uint32(f)
	} else {
		t.TPHscore = tx * 36000 / uint32(tm*f)
		if t.TPHscore == 0 {
			t.TPHscore = 1
		}
	}

	serialized := make([]byte, 5 + len(t.History) * 20)
	byteOrder.PutUint32(serialized, t.TPHscore)
	serialized[4] = byte(len(t.History))
	pos := 5
	for _,p := range t.History {
		byteOrder.PutUint32(serialized[pos:], uint32(p.StartTime.Unix()))
		pos += 4
		byteOrder.PutUint32(serialized[pos:], uint32(p.EndTime.Unix()))
		pos += 4
		byteOrder.PutUint32(serialized[pos:], p.StartBlock)
		pos += 4
		byteOrder.PutUint32(serialized[pos:], p.EndBlock)
		pos += 4
		byteOrder.PutUint32(serialized[pos:], p.TxTotal)
		pos += 4
	}

	b.db.Update(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(minerTPSBucketName)
		bucket.Put(miner[:], serialized)
		return nil
	})
}

func (b *BlockChain) TphNotice(t *Notification) {
	if t.Type != NTBlockConnected && t.Type != NTBlockDisconnected {
		return
	}

	if !b.IsCurrent() {
		// if not current, we are syncing chain, it does not reflect real TPS
		return
	}

	switch t.Data.(type) {
	case *btcutil.Block:
		block := t.Data.(*btcutil.Block)

		h := uint32(block.Height())
		rot := b.Rotation(block.MsgBlock().Header.PrevBlock)
		if rot <= wire.CommitteeSize {
			return
		}

		if block.MsgBlock().Header.Nonce > 0 {
			prev := b.NodeByHash(&block.MsgBlock().Header.PrevBlock)
			if prev.Data.GetNonce() > 0 {
				return
			}

			punishable := make([][20]uint8, 0, wire.CommitteeSize)

			if prev.Data.GetNonce() < -wire.MINER_RORATE_FREQ {
				// if stall immediately after a rotation, we blame the new committee member
				mb, _ := b.Miners.BlockByHeight(-prev.Data.GetNonce() - wire.MINER_RORATE_FREQ)
				punishable = append(punishable, mb.MsgBlock().Miner)
			} else {
				// if interrupted by a POW node, it mean the committee is stalling.
				// all members gets lowest score as punishment
				for i := 0; i < wire.CommitteeSize; i++ {
					mb, _ := b.Miners.BlockByHeight(rot)
					rot--

					punishable = append(punishable, mb.MsgBlock().Miner)
				}
			}

			for _, miner := range punishable {
				p := b.GetMinerTPS(miner)
				if len(p.History) > 0 {
					p.History[len(p.History)-1].TxTotal = 1
					p.current.TxTotal = 0
					p.current.StartBlock = 0

					b.updateTPS(miner, p)
				}
			}
			return
		}

		for i := 0; i < wire.CommitteeSize; i++ {
			mb, _ := b.Miners.BlockByHeight(rot)
			rot--

			miner := mb.MsgBlock().Miner

			p := b.GetMinerTPS(miner)
			switch t.Type {
			case NTBlockConnected:
				if p.current.TxTotal == 0 && p.current.StartBlock == 0 {
					p.current.StartBlock, p.current.StartTime, p.current.EndBlock = h, time.Now(), h
				} else if p.current.EndBlock+1 == h {
					p.current.EndBlock, p.current.EndTime = h, time.Now()
					var sigs = 1 // coinbase counts as 1, all other sigs counts as 10
					for _, tx := range block.MsgBlock().Transactions[1:] {
						sigs += 10 * len(tx.SignatureScripts)
					}
					p.current.TxTotal += uint32(sigs) + 10*uint32(block.MsgBlock().Header.ContractExec/CONTRACTTXRATIO)
				} else if p.current.EndBlock != h {
					if p.current.TxTotal != 0 {
						p.History = append(p.History, p.current)
						if len(p.History) > maxRcdPerMiner {
							p.History = p.History[len(p.History)-maxRcdPerMiner:]
						}
						b.updateTPS(miner, p)
					}
					p.current.StartBlock, p.current.EndBlock, p.current.StartTime = h, h, time.Now()
					p.current.TxTotal = 0
				}

			case NTBlockDisconnected:
				if p.current.StartBlock <= h && h <= p.current.EndBlock {
					p.current.TxTotal, p.current.StartBlock, p.current.EndBlock = 0, 0, 0
				} else {
					k := len(p.History) - 1
					if k >= 0 && p.History[k].StartBlock <= h && h <= p.History[k].EndBlock {
						p.History = p.History[:k]
						b.updateTPS(miner, p)
					}
				}
			}
		}
	}
}
