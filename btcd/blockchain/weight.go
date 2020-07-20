// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/viewpoint"
)

// GetBlockWeight computes the value of the weight metric for a given block.
// Currently the weight metric is simply the sum of the block's serialized size
// without any witness data scaled proportionally by the WitnessScaleFactor,
// and the block's serialized size including any witness data.
func GetBlockWeight(blk *btcutil.Block) int64 {
	msgBlock := blk.MsgBlock()

	totalSize := msgBlock.SerializeSize()
	return int64(totalSize)

//	baseSize := msgBlock.SerializeSizeStripped()
//	totalSize := msgBlock.SerializeSize()

	// (baseSize * 3) + totalSize
//	return int64((baseSize * (chaincfg.WitnessScaleFactor - 1)) + totalSize)
}

// GetTransactionWeight computes the value of the weight metric for a given
// transaction. Currently the weight metric is simply the sum of the
// transactions's serialized size without any witness data scaled
// proportionally by the WitnessScaleFactor, and the transaction's serialized
// size including any witness data.
func GetTransactionWeight(tx *btcutil.Tx) int64 {
	msgTx := tx.MsgTx()

	totalSize := int64(msgTx.SerializeSize())
	return totalSize
}

// GetSigOpCost returns the unified sig op cost for the passed transaction
// respecting current active soft-forks which modified sig op cost counting.
// The unified sig op cost for a transaction is computed as the sum of: the
// legacy sig op count scaled according to the WitnessScaleFactor, the sig op
// count for all p2sh inputs scaled by the WitnessScaleFactor, and finally the
// unscaled sig op count for any inputs spending witness programs.
func GetSigOpCost(tx *btcutil.Tx, isCoinBaseTx bool, utxoView *viewpoint.UtxoViewpoint, bip16, segWit bool) (int, error) {
	return CountSigOps(tx), nil
/*
	numSigOps := CountSigOps(tx) * chaincfg.WitnessScaleFactor
	if bip16 {
		numP2SHSigOps, err := CountP2SHSigOps(tx, isCoinBaseTx, utxoView)
		if err != nil {
			return 0, nil
		}
		numSigOps += (numP2SHSigOps * chaincfg.WitnessScaleFactor)
	}

	if segWit && !isCoinBaseTx {
		msgTx := tx.MsgTx()
		for txInIndex, txIn := range msgTx.TxIn {
			// Ensure the referenced output is available and hasn't
			// already been spent.
			utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
			if utxo == nil || utxo.IsSpent() {
				str := fmt.Sprintf("output %v referenced from "+
					"transaction %s:%d either does not "+
					"exist or has already been spent",
					txIn.PreviousOutPoint, tx.Hash(),
					txInIndex)
				return 0, ruleError(ErrMissingTxOut, str)
			}

			witness := txIn.Witness
			sigScript := txIn.SignatureScript
			pkScript := utxo.PkScript()
			numSigOps += GetWitnessSigOpCount(sigScript, pkScript, witness)
		}

	}

	return numSigOps, nil
*/
}

func (b *BlockChain) GetBlockLimit(h int32) uint32 {
	// block limit in number of tx
	if h < 0 {
		return 0
	}
	if h < chaincfg.BlockSizeEvalPeriod {
		return chaincfg.BlockBaseSize
	}

	h = h + chaincfg.BlockSizeEvalPeriod - 1
	h -= h % chaincfg.BlockSizeEvalPeriod

	b.blockSizer.mtx.Lock()
	defer b.blockSizer.mtx.Unlock()
	
	if z, ok := b.blockSizer.knownLimits[h]; ok {
		return z
	}

	start := h - chaincfg.SkipBlocks
	stop := int32(1)
	if start > chaincfg.BlockSizeEvalPeriod {
		stop = start - chaincfg.BlockSizeEvalPeriod
	}

	if b.blockSizer.target != h {
		b.blockSizer.reset(h)
	}
	if b.blockSizer.lastNode != nil {
		start = b.blockSizer.lastNode.Height - 1
	}

	log.Infof("blockSizer accounting at %d", start)

	p := b.BestChain.NodeByHeight(start)
	for i := start; i >= stop && p != nil; i-- {
		if i % 1000 == 0 {
			log.Infof("blockSizer handling block %d", i)
		}
		if b.blockSizer.lastNode != nil && b.blockSizer.lastNode.Height == i + 1 &&
			p.Data.GetNonce() < 0 {
			q,_ := b.BlockByHash(&p.Hash)
			b.blockSizer.blockCount++
			b.blockSizer.sizeSum += int64(len(q.MsgBlock().Transactions))
			b.blockSizer.timeSum += b.blockSizer.lastNode.Data.TimeStamp() - p.Data.TimeStamp()
		}
		b.blockSizer.lastNode = p
		p = p.Parent
	}

	log.Infof("blockSizer stats: blockCount = %d, sizeSum = %d timeSum = %d",
		b.blockSizer.blockCount, b.blockSizer.sizeSum, b.blockSizer.timeSum)

	b.blockSizer.conclude()
	b.blockSizer.reset(0)

	if len(b.blockSizer.knownLimits) >= 5 {
		delete(b.blockSizer.knownLimits, h - 4 * chaincfg.BlockSizeEvalPeriod)
	}

	return b.blockSizer.knownLimits[h]
}

func (b *sizeCalculator) RollBackTo(h int32) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for i,_ := range b.knownLimits {
		if h <= i - chaincfg.SkipBlocks {
			// most likely it would never happend, because it require roll back of 2000 blks
			delete(b.knownLimits, i)
		}
	}
}

func (b *sizeCalculator) reset(h int32) {
	b.lastNode = nil
	b.blockCount = 0
	b.sizeSum = 0
	b.timeSum = 0
	b.target = h
}

func (b *sizeCalculator) conclude() {
	h := b.target

	if b.blockCount == 0 {
		b.knownLimits[h] = chaincfg.BlockBaseSize
		return
	}

	// conclude calculation for a batch
	avgSize := b.sizeSum / int64(b.blockCount)
	if avgSize <= chaincfg.BlockBaseSize {
		b.knownLimits[h] = chaincfg.BlockBaseSize
		b.reset(0)
		return
	}

	avgTime := b.timeSum / int64(b.blockCount)

	csz := int64(chaincfg.BlockBaseSize)
	if avgTime >= chaincfg.TargetBlockRate {
		avgSize = (avgSize * chaincfg.TargetBlockRate) / avgTime
	}

	for csz < avgSize {
		csz <<= 1
	}

	b.reset(0)

	if avgSize * 10 > csz * 6 {		// 60% full. increase size
		csz <<= 1
	}
	b.knownLimits[h] = uint32(csz)
}

func (b *BlockChain) take(block *btcutil.Block) {
	h := block.Height()
	if h % chaincfg.BlockSizeEvalPeriod < chaincfg.BlockSizeEvalPeriod - chaincfg.StartEvalBlocks {
		return
	}

	h += chaincfg.BlockSizeEvalPeriod - 1
	h -= h % chaincfg.BlockSizeEvalPeriod

	b.blockSizer.mtx.Lock()
	defer b.blockSizer.mtx.Unlock()

	if _,ok := b.blockSizer.knownLimits[h]; ok {
		return
	}

	// spread calculation over a period of time to smooth server
	if b.blockSizer.target != h {
		b.blockSizer.reset(h)
	}

	start := h - chaincfg.SkipBlocks
	end := int32(1)
	if start > chaincfg.BlockSizeEvalPeriod {
		end = start - chaincfg.BlockSizeEvalPeriod
	}

	if b.blockSizer.lastNode != nil {
		start = b.blockSizer.lastNode.Height - 1
		if end >= start {
			return
		}
	}

	stop := start - 100
	if stop < end {
		stop = end
	}

	p := b.BestChain.NodeByHeight(start)

	for i := start; i >= stop && p != nil; i-- {
		if b.blockSizer.lastNode != nil && b.blockSizer.lastNode.Height == i + 1 &&
			p.Data.GetNonce() < 0 {
			b.blockSizer.blockCount++
			q, _ := b.BlockByHash(&p.Hash)
//			s, _ := q.Bytes()
			b.blockSizer.sizeSum += int64(len(q.MsgBlock().Transactions))	// s))
			b.blockSizer.timeSum += b.blockSizer.lastNode.Data.TimeStamp() - p.Data.TimeStamp()
		}
		b.blockSizer.lastNode = p
		p = p.Parent
	}
	if stop == end {
		b.blockSizer.conclude()
		b.blockSizer.reset(0)
	}
}

func (b *BlockChain) untake(block *btcutil.Block) {
	h := block.Height()
	if h % chaincfg.BlockSizeEvalPeriod < chaincfg.BlockSizeEvalPeriod - chaincfg.StartEvalBlocks {
		return
	}

	t := h + chaincfg.BlockSizeEvalPeriod - 1
	t -= t % chaincfg.BlockSizeEvalPeriod

	b.blockSizer.mtx.Lock()
	defer b.blockSizer.mtx.Unlock()

	if _,ok := b.blockSizer.knownLimits[t]; !ok {
		return
	}

	if h % chaincfg.BlockSizeEvalPeriod <= chaincfg.BlockSizeEvalPeriod - chaincfg.SkipBlocks {
		delete(b.blockSizer.knownLimits, t)
		b.blockSizer.reset(0)
	}
}

func (b *BlockChain) BlockSizerNotice(notification *Notification) {
	switch notification.Data.(type) {
	case *btcutil.Block:
		block := notification.Data.(*btcutil.Block)

		switch notification.Type {
		case NTBlockConnected:
			b.take(block)

		case NTBlockDisconnected:
			b.untake(block)
		}
	}
}
