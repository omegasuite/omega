// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
)

// maybeAcceptBlock potentially accepts a block into the block chain and, if
// accepted, returns whether or not it is on the main chain.  It performs
// several validation checks which depend on its position within the block chain
// before adding it.  The block is expected to have already gone through
// ProcessBlock before calling this function with it.
//
// The flags are also passed to checkBlockContext and connectBestChain.  See
// their documentation for how the flags modify their behavior.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) maybeAcceptBlock(block *btcutil.Block, flags BehaviorFlags) (bool, error, int32) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &block.MsgBlock().Header.PrevBlock
	prevNode := b.NodeByHash(prevHash)

	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	err := b.checkBlockContext(block, prevNode, flags)
	if err != nil {
		return false, err, -1
	}

	if flags&BFNoConnect == BFNoConnect {
		// now we have passed all the tests
		return true, nil, -1
	}

	if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
		// make sure the rotate in Miner block is there
		if prevNode.Data.GetNonce() != -wire.MINER_RORATE_FREQ+1 {
			return false, fmt.Errorf("this is a rotation node and previous nonce is not %d", -wire.MINER_RORATE_FREQ+1), -1
		}
		if mb, err := b.Miners.BlockByHeight(-block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ); err != nil || mb == nil {
			return false, err, -block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ
		}
	}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := &block.MsgBlock().Header

	newNode := b.NodeByHash(block.Hash())

	// Insert the block into the database if it's not already there.
	// This is necessary since it allows block download to be decoupled
	// from the much more expensive connection logic.  It is also
	// necessary to blocks that never become part of the main chain or
	// blocks that fail to connect available for forfeture and compensation.
	err = b.db.Update(func(dbTx database.Tx) error {
		return dbStoreBlock(dbTx, block)
	})

	if err != nil {
		return false, err, -1
	}

	if newNode == nil {
		newNode = NewBlockNode(blockHeader, prevNode)
		newNode.Status = chainutil.StatusDataStored
		b.index.AddNode(newNode)
	} else {
		newNode.Height = block.Height()
		if newNode.Height <= 0 {
			return false, err, -1
		}
		b.index.UnsetStatusFlags(newNode, chainutil.BlockStatus(0xFF))
		b.index.SetStatusFlags(newNode, chainutil.StatusDataStored)
		newNode.Parent = prevNode
		b.index.AddNodeDirect(newNode)

		flags |= BFAlreadyInChain
	}
	err = b.index.FlushToDB(dbStoreBlockNode)
	if err != nil {
		return false, err, -1
	}

	if flags & BFAlreadyInChain == BFAlreadyInChain {
		return false, nil, -1
	}

	isMainChain := false

	if block.Height() > b.BestChain.Height() {
		// if it is a POW block and we are in committee, we keep the committee going
		// until the POW block is followed by signed block
		if block.MsgBlock().Header.Nonce < 0 || block.Height() > b.ConsensusRange[1] {
			// Connect the passed block to the chain while respecting proper chain
			// selection according to the chain with the most proof of work.  This
			// also handles validation of the transaction scripts.
			isMainChain, err = b.connectBestChain(newNode, block, flags)
			if err != nil {
				return false, err, -1
			}
		}
	}

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	b.ChainLock.Unlock()
	b.SendNotification(NTBlockAccepted, block)
	b.ChainLock.Lock()

	return isMainChain, nil, -1
}
