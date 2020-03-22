/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
 */

package minerchain

import (
	"fmt"
	"math/big"
	"net"
	"time"

	"encoding/hex"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/blockchain/chainutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)

// blockExists determines whether a block with the given hash exists either in
// the main chain or any side chains.
//
// This function is safe for concurrent access.
func (b *MinerChain) blockExists(hash *chainhash.Hash) (bool, error) {
	// Check block index first (could be main chain or side chain blocks).
	if b.index.HaveBlock(hash) {
		return true, nil
	}

	// Check in the database.
	var exists bool
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		exists, err = dbTx.HasBlock(hash)
		if err != nil || !exists {
			return err
		}

		// Ignore side chain blocks in the database.  This is necessary
		// because there is not currently any record of the associated
		// block index data such as its block height, so it's not yet
		// possible to efficiently load the block and do anything useful
		// with it.
		//
		// Ultimately the entire block index should be serialized
		// instead of only the current main chain so it can be consulted
		// directly.
		_, err = blockchain.DbFetchHeightByHash(dbTx, hash)
		if blockchain.IsNotInMainChainErr(err) {
			exists = false
			return nil
		}
		return err
	})
	return exists, err
}

func (b *MinerChain) TryConnectOrphan(hash *chainhash.Hash) bool {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	block := b.Orphans.GetOrphanBlock(hash).(*wire.MingingRightBlock)
	n := b.index.LookupNode(&block.PrevBlock)

	if n == nil {
		return false
	}

	return b.ProcessOrphans(&block.PrevBlock, blockchain.BFNone) == nil
}

// processOrphans determines if there are any orphans which depend on the passed
// block hash (they are no longer orphans if true) and potentially accepts them.
// It repeats the process for the newly accepted blocks (to detect further
// orphans which may no longer be orphans) until there are no more.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to maybeAcceptBlock.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) ProcessOrphans(hash *chainhash.Hash, flags blockchain.BehaviorFlags) error {
	b.Orphans.ProcessOrphans(hash, func(processHash *chainhash.Hash, blk interface{}) bool {
		parent := b.index.LookupNode(processHash)
		block := (*wire.MinerBlock)(blk.(*orphanBlock))
		if !b.blockChain.SameChain(block.MsgBlock().BestBlock, NodetoHeader(parent).BestBlock) {
			return true
		}

		// Potentially accept the block into the block chain.
		_, err := b.maybeAcceptBlock(block, flags)
		return err != nil
	})

	return nil
}

func (b *MinerChain) CheckSideChain(hash *chainhash.Hash) {
	node := b.index.LookupNode(hash)

	if node == nil {
		return
	}

	tip := b.BestChain.Tip()
	if node.Height <= tip.Height {
		return
	}

	detachNodes, attachNodes, txdetachNodes, txattachNodes := b.getReorganizeNodes(node)

	if attachNodes.Len() == 0 {
		return
	}

	// Reorganize the chain.
	log.Infof("miner REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches", node.Hash, detachNodes.Len(), attachNodes.Len())
	if err := b.reorganizeChain(detachNodes, attachNodes); err != nil {
		return
	}
	if err := b.blockChain.ReorganizeChain(txdetachNodes, txattachNodes); err != nil {
		b.reorganizeChain(attachNodes, detachNodes)
		return
	}

	b.index.FlushToDB(dbStoreBlockNode)
}

// ProcessBlock is the main workhorse for handling insertion of new blocks into
// the block chain.  It includes functionality such as rejecting duplicate
// blocks, ensuring blocks follow all rules, orphan handling, and insertion into
// the block chain along with best chain selection and reorganization.
//
// When no errors occurred during processing, the first return value indicates
// whether or not the block is on the main chain and the second indicates
// whether or not the block is an orphan.
//
// This function is safe for concurrent access.
func (b *MinerChain) ProcessBlock(block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, bool, error, *chainhash.Hash) {
//	log.Infof("MinerChain.ProcessBlock: ChainLock.RLock")
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	blockHash := block.Hash()

	log.Infof("miner Block hash %s\nprevhash %s", blockHash.String(), block.MsgBlock().PrevBlock.String())

	// The block must not already exist in the main chain or side chains.
	exists, err := b.blockExists(blockHash)
	if err != nil {
		return false, false, err, nil
	}
	if exists {
		str := fmt.Sprintf("already have block %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str), nil
	}

	// The block must not already exist as an orphan.
	if !b.Orphans.CheckOrphan(blockHash, (*orphanBlock)(block)) {
		str := fmt.Sprintf("already have block (orphan) %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str), nil
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = CheckBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err, nil
	}

	if b.blockChain.Blacklist.IsGrey(block.MsgBlock().Miner) {
		return false, false, fmt.Errorf("Blacklised Miner"), nil
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = b.blockChain.CheckCollateral(block, flags)
	if err != nil {
		return false, false, err, nil
	}

	// Find the previous checkpoint and perform some additional checks based
	// on the checkpoint.  This provides a few nice properties such as
	// preventing old side chain blocks before the last checkpoint,
	// rejecting easy to mine, but otherwise bogus, blocks that could be
	// used to eat memory, and ensuring expected (versus claimed) proof of
	// work requirements since the previous checkpoint are met.
	blockHeader := block.MsgBlock()

	// Handle orphan blocks.
	prevHash := &blockHeader.PrevBlock
	prevHashExists, err := b.blockExists(prevHash)
	if err != nil {
		return false, false, err, nil
	}
	if !prevHashExists {
		log.Infof("block prevHash does not Exists Adding orphan block %s with parent %s", blockHash.String(), prevHash.String())
		b.Orphans.AddOrphanBlock((*orphanBlock)(block))

		return false, true, nil, nil
	}

	parent := b.index.LookupNode(prevHash)
	if have,_ := b.blockChain.HaveBlock(&block.MsgBlock().BestBlock); !have {
		return false, true, nil, &block.MsgBlock().BestBlock
	}
	if !b.blockChain.SameChain(block.MsgBlock().BestBlock, NodetoHeader(parent).BestBlock) {
		log.Infof("block and parent tx reference not in the same chain.")
		b.Orphans.AddOrphanBlock((*orphanBlock)(block))
		return false, true, nil, nil
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	isMainChain, err := b.maybeAcceptBlock(block, flags)
	if err != nil {
		return false, false, err, nil
	}

	if isMainChain {
		b.blockChain.OnNewMinerNode()
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err = b.ProcessOrphans(blockHash, flags)
	if err != nil {
//		log.Infof("b.ProcessOrphans error %s", err)
		return false, false, err, nil
	}

	log.Infof("miner.ProcessBlock finished with height = %d (%d) tx height = %d orphans = %d",
		b.BestSnapshot().Height, block.Height(),
		b.blockChain.BestSnapshot().Height, b.Orphans.Count())

	return isMainChain, false, nil, nil
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
func CheckBlockSanity(header *wire.MinerBlock, powLimit *big.Int, timeSource chainutil.MedianTimeSource, flags blockchain.BehaviorFlags) error {
	// Ensure the proof of work bits in the block header is in min/max range
	// and the block hash is less than the target value described by the
	// bits.
	err := checkProofOfWork(header.MsgBlock(), powLimit, flags)
	if err != nil {
		return err
	}

	// A block timestamp must not have a greater precision than one second.
	// This check is necessary because Go time.Time values support
	// nanosecond precision whereas the consensus rules only apply to
	// seconds and it's much nicer to deal with standard Go time values
	// instead of converting to seconds everywhere.
	if !header.MsgBlock().Timestamp.Equal(time.Unix(header.MsgBlock().Timestamp.Unix(), 0)) {
		str := fmt.Sprintf("block timestamp of %v has a higher "+
			"precision than one second", header.MsgBlock().Timestamp)
		return ruleError(ErrInvalidTime, str)
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := timeSource.AdjustedTime().Add(time.Second *
		blockchain.MaxTimeOffsetSeconds)
	if header.MsgBlock().Timestamp.After(maxTimestamp) {
		str := fmt.Sprintf("block timestamp of %v is too far in the "+
			"future", header.MsgBlock().Timestamp)
		return ruleError(ErrTimeTooNew, str)
	}

	if len(header.MsgBlock().Connection) < 128 {
		_, err := net.ResolveTCPAddr("", string(header.MsgBlock().Connection))
		if err != nil {
			return err
		}
	} else if len(header.MsgBlock().Connection) != 128 {
		return fmt.Errorf("The connect information is neither a RSA key nor an IP address",
			hex.EncodeToString(header.MsgBlock().Connection))
	}

	return nil
}
