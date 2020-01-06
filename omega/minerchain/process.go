// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package minerchain

import (
	"fmt"
	"math/big"
	"net"
	"time"

	"encoding/hex"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)
/*
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

	// BFNone is a convenience value to specifically indicate no flags.
	BFNone BehaviorFlags = 0
)
*/

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
		_, err = dbFetchHeightByHash(dbTx, hash)
		if isNotInMainChainErr(err) {
			exists = false
			return nil
		}
		return err
	})
	return exists, err
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
//				log.Warnf("Found a nil entry at index %d in the "+
//					"orphan dependency list for block %v", i,
//					processHash)
				continue
			}

			// Remove the orphan from the orphan pool.
			orphanHash := orphan.block.Hash()
			b.removeOrphanBlock(orphan)
			i--

			// Potentially accept the block into the block chain.
			_, err := b.maybeAcceptBlock(orphan.block, flags)
			if err != nil {
				return err
			}

			// Add this block to the list of blocks to process so
			// any orphan blocks that depend on this block are
			// handled too.
			processHashes = append(processHashes, orphanHash)
		}
	}
	return nil
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
func (b *MinerChain) ProcessBlock(block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, bool, error) {
	log.Infof("MinerChain.ProcessBlock: ChainLock.RLock")
	b.chainLock.Lock()
	defer b.chainLock.Unlock()
/*
	func () {
		b.chainLock.Unlock()
		log.Infof("MinerChain.ProcessBlock: ChainLock.Unlock")
	} ()
*/

	blockHash := block.Hash()

	// The block must not already exist in the main chain or side chains.
	exists, err := b.blockExists(blockHash)
	if err != nil {
		return false, false, err
	}
	if exists {
		str := fmt.Sprintf("already have block %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str)
	}

	// The block must not already exist as an orphan.
	if _, exists := b.orphans[*blockHash]; exists {
		str := fmt.Sprintf("already have block (orphan) %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str)
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = checkBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err
	}

	log.Infof("checkBlockSanity pass")

	var name[20]byte
	copy(name[:], block.MsgBlock().Miner)
	if b.blockChain.Blacklist.IsGrey(name) {
		return false, false, fmt.Errorf("Blacklised Miner")
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
		return false, false, err
	}
	if !prevHashExists {
//		log.Infof("Adding orphan block %v with parent %v", blockHash, prevHash)
		b.addOrphanBlock(block)

		return false, true, nil
	}

	height1,_ := b.blockChain.BlockHeightByHash(&block.MsgBlock().ReferredBlock)
	ref := b.blockChain.BestChain.NodeByHeight(height1)
	height2,_ := b.blockChain.BlockHeightByHash(&block.MsgBlock().BestBlock)
	best := b.blockChain.BestChain.NodeByHeight(height2)

	eq1 := block.MsgBlock().ReferredBlock.IsEqual(ref.Hash())
	eq2 := block.MsgBlock().BestBlock.IsEqual(best.Hash())

	if ref == nil || !eq1 || best == nil || !eq2 {
		log.Infof("Adding orphan block %v (%d, %d)", blockHash, height1, height2)
		b.addOrphanBlock(block)

		return false, true, nil
	}

	log.Infof("maybeAcceptBlock ready")

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	isMainChain, err := b.maybeAcceptBlock(block, flags)
	if err != nil {
		return false, false, err
	}

	if isMainChain {
		log.Infof("b.blockChain.ProcessOrphans ready")
		b.blockChain.ProcessOrphans(&b.blockChain.BestSnapshot().Hash, blockchain.BFNone)
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err = b.ProcessOrphans(blockHash, flags)
	if err != nil {
		log.Infof("b.ProcessOrphans error %s", err)
		return false, false, err
	}

	log.Infof("miner.ProcessBlock finished with height = %d tx height = %d orphans = %d", b.BestSnapshot().Height,
		b.blockChain.BestSnapshot().Height, len(b.orphans))

	return isMainChain, false, nil
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
func checkBlockSanity(header *wire.MinerBlock, powLimit *big.Int, timeSource blockchain.MedianTimeSource, flags blockchain.BehaviorFlags) error {
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
