// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcutil"
	"time"
)

type blockData struct {
	action int32	// positive: height of signed block; negative: height of POW block; 0 = nil
	txs    int		// txs in the blocks
	timestamp time.Time	// block timestamp
}

var blockwindow [2 * chaincfg.BlockSizeEvalWindow]blockData		// circular window of blocks

func (b *BlockChain) GetBlockLimit(ht int32) uint32 {
	return 5000		// no need to control block rate by adjusting block size
					// we now use TPS to do that. it's better.

	// block limit in number of tx
	if ht < chaincfg.BlockSizeEvalWindow {
		return chaincfg.BlockBaseSize
	}

	h := ht - ht % chaincfg.BlockSizeEvalPeriod

	b.blockSizer.mtx.Lock()
	z, ok := b.blockSizer.knownLimits[h]
	b.blockSizer.mtx.Unlock()

	if ok {
		return z
	}

	s := h - chaincfg.BlockSizeEvalWindow
	e := h - chaincfg.SkipBlocks

	blockCount := 0
	sizeSum := int(0)
	timeSum := int64(0)
	k := timeSum

	for t := s; t < e; t++ {
		n := t % (2*chaincfg.BlockSizeEvalWindow)
		if blockwindow[n].action == 0 || (blockwindow[n].action > 0 && blockwindow[n].action != t) ||
			(blockwindow[n].action < 0 && blockwindow[n].action != -t) {
			// load block
			blk, _ := b.BlockByHeight(t)
			blockwindow[n].txs = len(blk.MsgBlock().Transactions)
			blockwindow[n].timestamp = blk.MsgBlock().Header.Timestamp

			if blk.MsgBlock().Header.Nonce > 0 {
				blockwindow[n].action = -t
			} else {
				blockwindow[n].action = t
			}
		}

		if k > 0 && blockwindow[n].action > 0 {
			blockCount++
			sizeSum += blockwindow[n].txs
			timeSum += blockwindow[n].timestamp.Unix() - k
		}
		k = blockwindow[n].timestamp.Unix()
	}

	if blockCount == 0 {
		b.blockSizer.knownLimits[h] = chaincfg.BlockBaseSize
		return chaincfg.BlockBaseSize
	}

	// conclude calculation for a batch
	avgSize := int64(sizeSum / blockCount)
	if avgSize <= chaincfg.BlockBaseSize {
		b.blockSizer.knownLimits[h] = chaincfg.BlockBaseSize
		return chaincfg.BlockBaseSize
	}

	avgTime := timeSum / int64(blockCount)

	csz := int64(chaincfg.BlockBaseSize)
	if avgTime >= chaincfg.TargetBlockRate {
		avgSize = (avgSize * chaincfg.TargetBlockRate) / avgTime
	}

	for csz < avgSize {
		csz <<= 1
	}

	if avgSize * 10 > csz * 6 {		// 60% full. increase size
		csz <<= 1
	}
	b.blockSizer.knownLimits[h] = uint32(csz)
	return uint32(csz)
}

func (b *BlockChain) BlockSizerNotice(notification *Notification) {
	return

	switch notification.Data.(type) {
	case *btcutil.Block:
		block := notification.Data.(*btcutil.Block)
		height := block.Height()

		switch notification.Type {
		case NTBlockConnected:
			n := height % (2 * chaincfg.BlockSizeEvalWindow)
			if block.MsgBlock().Header.Nonce > 0 {
				height = - height
			}
			blockwindow[n].action = height
			blockwindow[n].timestamp = block.MsgBlock().Header.Timestamp
			blockwindow[n].txs = len(block.MsgBlock().Transactions)

		case NTBlockDisconnected:
			blockwindow[height % (2 * chaincfg.BlockSizeEvalWindow)].action = 0

			if height % chaincfg.BlockSizeEvalPeriod == 0 {
				delete(b.blockSizer.knownLimits, height + chaincfg.SkipBlocks)
			}
		}
	}
}

func (b *sizeCalculator) RollBackTo(h int32) {
	return

	b.mtx.Lock()
	defer b.mtx.Unlock()

	for i,_ := range b.knownLimits {
		if h <= i - chaincfg.SkipBlocks {
			// most likely it would never happend, because it require roll back of 2000 blks
			delete(b.knownLimits, i)
		}
	}
}
