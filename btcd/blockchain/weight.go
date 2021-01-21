// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
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
}
