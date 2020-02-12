// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcutil"
)

// BehaviorFlags is a bitmask defining tweaks to the normal behavior when
// performing chain processing and consensus rules checks.
type BehaviorFlags uint32

const (
	// BFFastAdd may be set to indicate that several checks can be avoided
	// for the block since it is already known to fit into the chain due to
	// already proving it correct links into the chain up to a known
	// checkpoint.  This is primarily used for headers-first mode.
	BFFastAdd BehaviorFlags = 1 << iota

	// BFNoPoWCheck may be set to indicate the proof of work check which
	// ensures a block hashes to a value less than the required target will
	// not be performed.
	BFNoPoWCheck

	BFAddAsOrphan

	BFSubmission

	BFNoConnect

	BFNoReorg

	// BFNone is a convenience value to specifically indicate no flags.
	BFNone BehaviorFlags = 0
)

// blockExists determines whether a block with the given hash exists either in
// the main chain or any side chains.
//
// This function is safe for concurrent access.
func (b *BlockChain) blockExists(hash *chainhash.Hash) (bool, error) {
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
		_, err = dbFetchHeightByHash(dbTx, hash)
		if isNotInMainChainErr(err) {
			exists = false
			return nil
		}
		return err
	})
	return exists, err
}

func (b *BlockChain) TryConnectOrphan(hash *chainhash.Hash) bool {
	block := b.orphans[*hash].block
	n := b.index.LookupNode(&block.MsgBlock().Header.PrevBlock)
	if n == nil {
		return false
	}

	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	return b.ProcessOrphans(&block.MsgBlock().Header.PrevBlock, BFNone) == nil
}

// ProcessOrphans determines if there are any orphans which depend on the passed
// block hash (they are no longer orphans if true) and potentially accepts them.
// It repeats the process for the newly accepted blocks (to detect further
// orphans which may no longer be orphans) until there are no more.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to maybeAcceptBlock.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) ProcessOrphans(hash *chainhash.Hash, flags BehaviorFlags) error {
	// Start with processing at least the passed hash.  Leave a little room
	// for additional orphan blocks that need to be processed without
	// needing to grow the array in the common case.
	processHashes := make([]*chainhash.Hash, 0, 10)
	processHashes = append(processHashes, hash)
	for len(processHashes) > 0 {
		// Pop the first hash to process from the slice.
		processHash := processHashes[0]
		processHashes[0] = nil // Prevent GC leak.
		processHashes = processHashes[1:]

		// Look up all orphans that are parented by the block we just
		// accepted.  This will typically only be one, but it could
		// be multiple if multiple blocks are mined and broadcast
		// around the same time.  The one with the most proof of work
		// will eventually win out.  An indexing for loop is
		// intentionally used over a range here as range does not
		// reevaluate the slice on each iteration nor does it adjust the
		// index for the modified slice.
		for i := 0; i < len(b.prevOrphans[*processHash]); i++ {
			orphan := b.prevOrphans[*processHash][i]
			if orphan == nil {
				log.Warnf("Found a nil entry at index %d in the "+
					"orphan dependency list for block %v", i,
					processHash)
				continue
			}

			if prevNode := b.index.LookupNode(&orphan.block.MsgBlock().Header.PrevBlock); prevNode != nil {
				orphan.block.SetHeight(prevNode.height + 1)
				// Potentially accept the block into the block chain.
				err, mkorphan := b.checkProofOfWork(orphan.block, prevNode, b.chainParams.PowLimit, flags)
				if err != nil || mkorphan {
					continue
				}

				_, err = b.maybeAcceptBlock(orphan.block, flags)
				if err != nil {
					continue
				}
			} else {
				continue
			}

			// Remove the orphan from the orphan pool.
			orphanHash := orphan.block.Hash()

			b.removeOrphanBlock(orphan)
			i--

			// Add this block to the list of blocks to process so
			// any orphan blocks that depend on this block are
			// handled too.
			processHashes = append(processHashes, orphanHash)
		}
	}
	return nil
}

func (b *BlockChain) OnNewMinerNode() {
	added := false
	root := make(map[chainhash.Hash]struct{}, 0)
	for q,_ := range b.orphans {
		r := b.GetOrphanRoot(&q)
		if _,ok := root[*r]; ok {
			continue
		}
		root[*r] = struct{}{}
		p := b.orphans[*r]
		f := p.block.MsgBlock().Header.PrevBlock
		if b.index.LookupNode(&f) != nil {
			b.ProcessOrphans(&f, BFNone)
		}
		if !added && b.index.LookupNode(r) != nil {
			added = true
		}
	}

	if added {
		high := b.index.Highest()
		b.CheckSideChain(&high.hash)
	}
}

func (b *BlockChain) CheckSideChain(hash *chainhash.Hash) {
	node := b.index.LookupNode(hash)

	if node == nil {
		return
	}

	tip := b.BestChain.Tip()
	if node.height <= tip.height {
		return
	}

	detachNodes, attachNodes := b.getReorganizeNodes(node)

	if detachNodes.Len() == 0 && attachNodes.Len() == 0 {
		return
	}

	// Reorganize the chain.
	b.ReorganizeChain(detachNodes, attachNodes)
	log.Infof("CheckSideChain: tx REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches. New chain height = %d", node.hash, detachNodes.Len(), attachNodes.Len(), b.BestSnapshot().Height)

	b.index.flushToDB()
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
func (b *BlockChain) ProcessBlock(block *btcutil.Block, flags BehaviorFlags) (bool, bool, error) {
//	log.Infof("ProcessBlock: ChainLock.RLock")
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()
/*
	func () {
		b.ChainLock.Unlock()
		log.Infof("ProcessBlock: ChainLock.Unlock")
	} ()
*/
	blockHeader := &block.MsgBlock().Header
	prevHash := &blockHeader.PrevBlock
	prevHashExists, err := b.blockExists(prevHash)
	if err != nil {
		return false, false, err
	}
	if !prevHashExists {
		log.Infof("block %s: prevHash block %s does not exist", block.Hash().String(), prevHash.String())
		if flags & BFNoConnect == 0 {
			log.Infof("Adding orphan block %s with parent %s height appear %d", block.Hash().String(), prevHash.String(), block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index)
			b.AddOrphanBlock(block)
		}
		return false, true, nil
	}

	prevNode := b.index.LookupNode(prevHash)

	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	block.SetHeight(blockHeight)

	if blockHeight != int32(block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index) {
		return false, false, ruleError(ErrInvalidAncestorBlock, "Block height inconsistent with ostensible height")
	}

//	fastAdd := flags&BFFastAdd == BFFastAdd

	blockHash := block.Hash()
	log.Tracef("Processing block %v", blockHash)

	// The block must not already exist in the main chain or side chains.
	exists, err := b.blockExists(blockHash)
	if err != nil {
		return false, false, err
	}

	if exists {
		return false, false, ruleError(ErrDuplicateBlock, errorCodeStrings[ErrDuplicateBlock])
	}

	// The block must not already exist as an orphan.
	if p, exists := b.orphans[*blockHash]; exists {
		// check if the orphan is a pre-consus block and this is a consensus block
		if len(block.MsgBlock().Transactions[0].SignatureScripts) > len(p.block.MsgBlock().Transactions[0].SignatureScripts) {
			b.removeOrphanBlock(p)
		} else {
			str := fmt.Sprintf("already have block (orphan) %v", blockHash)
			return false, true, ruleError(ErrDuplicateBlock, str)
		}
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = checkBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err
	}

	// Find the previous checkpoint and perform some additional checks based
	// on the checkpoint.  This provides a few nice properties such as
	// preventing old side chain blocks before the last checkpoint,
	// rejecting easy to mine, but otherwise bogus, blocks that could be
	// used to eat memory, and ensuring expected (versus claimed) proof of
	// work requirements since the previous checkpoint are met.
	checkpointNode, err := b.findPreviousCheckpoint()
	if err != nil {
		return false, false, err
	}
	if checkpointNode != nil {
		// Ensure the block timestamp is after the checkpoint timestamp.
		checkpointTime := time.Unix(checkpointNode.timestamp, 0)
		if blockHeader.Timestamp.Before(checkpointTime) {
			str := fmt.Sprintf("block %v has timestamp %v before "+
				"last checkpoint timestamp %v", blockHash,
				blockHeader.Timestamp, checkpointTime)
			return false, false, ruleError(ErrCheckpointTimeTooOld, str)
		}
	}

	// Handle orphan blocks.
/*
	requiredRotate := b.BestSnapshot().LastRotation
	header := &block.MsgBlock().Header
	if header.Nonce > 0 {
		requiredRotate += wire.CommitteeSize / 2 + 1
	} else if header.Nonce == -(wire.MINER_RORATE_FREQ - 1){
		requiredRotate++
	}
*/

	isMainChain := false

	if flags & BFNoConnect == BFNoConnect {
		// this mark an pre-consus block
//		b.AddOrphanBlock(block)
		return isMainChain, false, nil
	}

	state := b.BestSnapshot()
	if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
		mstate := b.Miners.BestSnapshot()
		if int32(state.LastRotation)+1-wire.CommitteeSize > mstate.Height {
			log.Infof("Next Rotation exceeds miner chain %d in a rotation block %s. Make it an orphan!!!", state.LastRotation, block.Hash().String())
			b.AddOrphanBlock(block)
			return true, true, nil
		}
	}

	// don't check POW if we are to extending a side chain and this is a comittee block
	// leave the work to reorg
	err, mkorphan := b.checkProofOfWork(block, prevNode, b.chainParams.PowLimit, flags)
	if err != nil {
		return isMainChain, true, err
	}
	if mkorphan {
		log.Infof("checkProofOfWork failed. Make block %s an orphan at %d", block.Hash().String(), block.Height())
		b.AddOrphanBlock(block)
		return isMainChain, true, nil
	}

//	if block.MsgBlock().Header.Nonce < 0 && wire.CommitteeSize > 1 && len(block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSize/2 + 1 {
//		return isMainChain, false, fmt.Errorf("Insufficient signatures")
//	}

//	if block.MsgBlock().Header.Nonce > 0 || b.BestChain.FindFork(prevNode) == nil {
//	}

	//	if b.Miners.BestSnapshot().Height >= int32(requiredRotate) {
		isMainChain, err = b.maybeAcceptBlock(block, flags)
		if err != nil {
			return false, false, err
		}
//	} else {
		// add it as an orphan. whenever a miner block is added,
		// we shall call ProcessOrphans with tip of best tx chain hash as param.
//		b.AddOrphanBlock(block)
//		return false, true, nil
//	}

	if isMainChain {
		b.Miners.ProcessOrphans(&b.Miners.BestSnapshot().Hash, BFNone)
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err = b.ProcessOrphans(blockHash, BFNone)	// flags)
//	if err != nil {
//		return false, false, err
//	}

	log.Debugf("Accepted block %v", blockHash)
//	log.Infof("ProcessBlock: Tx chian = %d Miner chain = %d", b.BestSnapshot().Height, b.Miners.BestSnapshot().Height)

	log.Infof("ProcessBlock finished with height = %d miner height = %d orphans = %d", b.BestSnapshot().Height,
		b.Miners.BestSnapshot().Height, len(b.orphans))

	return isMainChain, false, nil
}
