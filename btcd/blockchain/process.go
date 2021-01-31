// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/wire"
	"time"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcutil"
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

	BFSideChain

	BFWatingFactor

	// BFNone is a convenience value to specifically indicate no flags.
	BFNone BehaviorFlags = 0
)

// blockExists determines whether a block with the given hash exists either in
// the main chain or any side chains.
//
// This function is safe for concurrent access.
func (b *BlockChain) blockExists(hash *chainhash.Hash) (bool, error) {
	// Check block index first (could be main chain or side chain blocks).
	if b.index.HaveBlock(hash) {	// index includes only the most recent blocks
		return true, nil
	}

	// Check in the database.
	var exists bool
	err := b.db.View(func(dbTx database.Tx) error {
		// if not in index, it might still be a valid block
		bucket := dbTx.Metadata().Bucket(hashIndexBucketName)
		if bucket.Get((*hash)[:]) != nil {
			exists = true
			return nil
		}

		// it might be in cache
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
		_, err = DbFetchHeightByHash(dbTx, hash)
		if IsNotInMainChainErr(err) {
			exists = false
			return nil
		}
		return err
	})
	return exists, err
}

func (b *BlockChain) TryConnectOrphan(hash *chainhash.Hash) bool {
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	m := b.Orphans.GetOrphanBlock(hash)
	if m == nil {
		return true
	}

	block := m.(*wire.MsgBlock)

	n := b.NodeByHash(&block.Header.PrevBlock)
	if n == nil {
		return false
	}

	return b.ProcessOrphans(&block.Header.PrevBlock, BFNone) == nil
}

// ProcessOrphans determines if there are any Orphans which depend on the passed
// block hash (they are no longer Orphans if true) and potentially accepts them.
// It repeats the process for the newly accepted blocks (to detect further
// Orphans which may no longer be Orphans) until there are no more.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to maybeAcceptBlock.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) ProcessOrphans(hash *chainhash.Hash, flags BehaviorFlags) error {
	b.Orphans.ProcessOrphans(hash, func(_ *chainhash.Hash, blk interface{}) bool {
		block := (*btcutil.Block)(blk.(*orphanBlock))
		if prevNode := b.NodeByHash(&block.MsgBlock().Header.PrevBlock); prevNode != nil {
			block.SetHeight(prevNode.Height + 1)
			// Potentially accept the block into the block chain.
			err, mkorphan := b.checkProofOfWork(block, prevNode, b.ChainParams.PowLimit, flags)
			if err != nil || mkorphan {
				return true
			}

			_, err, _ = b.maybeAcceptBlock(block, flags)
			return err != nil
		}
		return true
	})

	return nil
}

func (b *BlockChain) OnNewMinerNode() {
	if b.Orphans.OnNewMinerNode(func (f * chainhash.Hash, r *chainhash.Hash, added bool) bool {
		if b.NodeByHash(f) != nil {
			b.ProcessOrphans(f, BFNone)
		}
		if !added && b.NodeByHash(r) != nil {
			added = true
		}
		return added
	}) {
		high := b.index.Highest()
		b.CheckSideChain(&high.Hash)
	}
}

func (b *BlockChain) CheckSideChain(hash *chainhash.Hash) {
	node := b.NodeByHash(hash)

	if node == nil {
		return
	}

	tip := b.BestChain.Tip()
	if node.Height <= tip.Height {
		return
	}

	detachNodes, attachNodes := b.getReorganizeNodes(node)

	if detachNodes.Len() == 0 && attachNodes.Len() == 0 {
		return
	}

	// Reorganize the chain.
	b.ReorganizeChain(detachNodes, attachNodes)
	log.Infof("CheckSideChain: tx REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches. New chain height = %d", node.Hash, detachNodes.Len(), attachNodes.Len(), b.BestSnapshot().Height)

	b.index.FlushToDB(dbStoreBlockNode)
}

type orphanBlock btcutil.Block

func (b * orphanBlock) PrevBlock() * chainhash.Hash {
	return & (*btcutil.Block)(b).MsgBlock().Header.PrevBlock
}

func (b * orphanBlock) MsgBlock() wire.Message {
	return (*btcutil.Block)(b).MsgBlock()
}

func (b * orphanBlock) Hash() * chainhash.Hash {
	return (*btcutil.Block)(b).Hash()
}

func (b * orphanBlock) Removable(ob chainutil.Orphaned) bool {
	block := b.MsgBlock().(*wire.MsgBlock)
	oblock := ob.MsgBlock().(*wire.MsgBlock)
	return len(block.Transactions[0].SignatureScripts) > len(oblock.Transactions[0].SignatureScripts)
}

func (b * orphanBlock) NeedUpdate(ob chainutil.Orphaned) bool {
	block := b.MsgBlock().(*wire.MsgBlock)
	if block.Header.Nonce < 0 {
		nl := len(block.Transactions[0].SignatureScripts)
		oblock := ob.MsgBlock().(*wire.MsgBlock)
		ol := len(oblock.Transactions[0].SignatureScripts)
		if nl > ol {
			return true
		} else if nl == ol {
			if len(block.Transactions[0].SignatureScripts[1]) > len(oblock.Transactions[0].SignatureScripts[1]) {
				return true
			}
		}
	}
	return false
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
func (b *BlockChain) ProcessBlock(block *btcutil.Block, flags BehaviorFlags) (bool, bool, error, int32) {
//	log.Infof("ProcessBlock: ChainLock.RLock")
	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()

	blockHeader := &block.MsgBlock().Header
	prevHash := &blockHeader.PrevBlock
	prevHashExists, err := b.blockExists(prevHash)
	if err != nil {
		return false, false, err, -1
	}
	if !prevHashExists {
		log.Infof("block %s: prevHash block %s does not exist", block.Hash().String(), prevHash.String())
		if flags & BFNoConnect == 0 {
			if block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index > uint32(b.BestChain.Height()) + 500 {
				err := fmt.Errorf("Skipping future block %s with parent %s height appear %d", block.Hash().String(), prevHash.String(), block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index)
				return false, false, err, -1
			} else {
				log.Infof("Adding orphan block %s with parent %s height appear %d", block.Hash().String(), prevHash.String(), block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index)
				b.Orphans.AddOrphanBlock((* orphanBlock)(block))
			}
		}
		return false, true, nil, -1
	}

	prevNode := b.NodeByHash(prevHash)

	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, false, ruleError(ErrPreviousBlockUnknown, str), -1
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, false, ruleError(ErrInvalidAncestorBlock, str), -1
	}

	blockHeight := prevNode.Height + 1

	if blockHeight < int32(b.index.Cutoff) {
		return false, false, ruleError(ErrInvalidAncestorBlock, "Block height is in locked area"), -1
	}

	block.SetHeight(blockHeight)

	if blockHeight != int32(block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index) {
		return false, false, ruleError(ErrInvalidAncestorBlock, "Block height inconsistent with ostensible height"), -1
	}

//	fastAdd := flags&BFFastAdd == BFFastAdd
	blockHash := block.Hash()

	// The block must not already exist in the main chain or side chains.
	exists, err := b.blockExists(blockHash)
	if err != nil {
		return false, false, err, -1
	}

	if exists {
		if block.Height() > b.BestChain.Height() {
			// do we need to reorg?
			node := b.NodeByHash(blockHash)
			detachNodes, attachNodes := b.getReorganizeNodes(node)

			if attachNodes.Len() != 0 {
				// Reorganize the chain.
				if err = b.ReorganizeChain(detachNodes, attachNodes); err != nil {
					return false, true, err, -1
				}
				if writeErr := b.index.FlushToDB(dbStoreBlockNode); writeErr != nil {
					log.Warnf("Error flushing block index changes to disk: %v", writeErr)
				}
			}
		}
		return false, false, ruleError(ErrDuplicateBlock, errorCodeStrings[ErrDuplicateBlock]), -1
	}

	// The block must not already exist as an orphan.
	if !b.Orphans.CheckOrphan(blockHash, (*orphanBlock)(block)) {
		str := fmt.Sprintf("already have block (orphan) %v", blockHash)
		return false, true, ruleError(ErrDuplicateBlock, str), -1
	}

	// contract execution must not exceed block limit
	if block.MsgBlock().Header.ContractExec > b.ChainParams.ContractExecLimit {
		str := fmt.Sprintf("Contract execution steps exceeds block limit in %v", blockHash)
		return false, true, ruleError(ErrExcessContractExec, str), -1
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = checkBlockSanity(block, b.ChainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err, -1
	}

	if len(block.MsgBlock().Transactions) > int(b.GetBlockLimit(block.Height())) {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", block.Size(), b.GetBlockLimit(block.Height()))
		return false, false, ruleError(ErrBlockTooBig, str), -1
	}

	// Find the previous checkpoint and perform some additional checks based
	// on the checkpoint.  This provides a few nice properties such as
	// preventing old side chain blocks before the last checkpoint,
	// rejecting easy to mine, but otherwise bogus, blocks that could be
	// used to eat memory, and ensuring expected (versus claimed) proof of
	// work requirements since the previous checkpoint are met.
	checkpointNode, err := b.findPreviousCheckpoint()
	if err != nil {
		return false, false, err, -1
	}
	if checkpointNode != nil {
		// Ensure the block timestamp is after the checkpoint timestamp.
		checkpointTime := time.Unix(checkpointNode.Data.TimeStamp(), 0)
		if blockHeader.Timestamp.Before(checkpointTime) {
			str := fmt.Sprintf("block %v has timestamp %v before "+
				"last checkpoint timestamp %v", blockHash,
				blockHeader.Timestamp, checkpointTime)
			return false, false, ruleError(ErrCheckpointTimeTooOld, str), -1
		}
	}

	isMainChain := false

	// don't check POW if we are to extending a side chain and this is a comittee block
	// leave the work to reorg
	if flags & BFNoConnect == BFNoConnect {
		// this mark an pre-consus block
//		b.AddOrphanBlock(block)
		return isMainChain, false, nil, -1
	}

	err, mkorphan := b.checkProofOfWork(block, prevNode, b.ChainParams.PowLimit, flags)
	if err != nil {
		return isMainChain, true, err, -1
	}
	if mkorphan {
		log.Infof("checkProofOfWork failed. Make block %s an orphan at %d", block.Hash().String(), block.Height())
		b.Orphans.AddOrphanBlock((*orphanBlock)(block))
		return isMainChain, true, nil, -1
	}

	isMainChain, err, missing := b.maybeAcceptBlock(block, flags)
	if missing > 0 {
		return false, false, err, missing
	}
	if err != nil {
		return false, false, err, -1
	}

	if isMainChain {
		b.Miners.ProcessOrphans(&b.Miners.BestSnapshot().Hash, BFNone)
	} else if block.MsgBlock().Header.Nonce < 0 {
		// CHECK if there is a miner violation
		// block is in side chain
		mblk,_ := b.BlockByHeight(block.Height())		//	main chain block
		if mblk != nil && mblk.MsgBlock().Header.Nonce < 0 {
			// both are signed blocks. find out double singers
			best := b.BestSnapshot()
			rotate := best.LastRotation
			for p := b.BestChain.Tip(); p != nil && p.Height != block.Height(); p = b.ParentNode(p) {
				switch {
				case p.Data.GetNonce() > 0:
					rotate -= wire.POWRotate

				case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
					rotate--
				}
			}
			// examine signatures. must not have double signs
			signers := make(map[[20]byte]struct{})
			var name [20]byte
			for _, sig := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
				copy(name[:], btcutil.Hash160(sig[:btcec.PubKeyBytesLenCompressed]))
				signers[name] = struct{}{}
			}
			for _, sig := range mblk.MsgBlock().Transactions[0].SignatureScripts[1:] {
				copy(name[:], btcutil.Hash160(sig[:btcec.PubKeyBytesLenCompressed]))
				rt := rotate
				if _,ok := signers[name]; ok {
					// double signer
					mb,_ := b.Miners.BlockByHeight(int32(rt))
					for i := 0; i < wire.CommitteeSize; i++ {
						if mb.MsgBlock().Miner == name {
							b.Miners.DSReport(&wire.Violations{
								Height: block.Height(),				// Height of Tx blocks
								Signed: 2,					// times the violator signed blocks at this height
								MRBlock: *mb.Hash(),		// the MR block of violator
								Blocks: []chainhash.Hash{*block.Hash(), *mblk.Hash()},
							})
							break
						}
						rt--
						mb,_ = b.Miners.BlockByHeight(int32(rt))
					}
				}
			}
		}
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.

	// Accept any orphan blocks that depend on this block (they are
	// no longer Orphans) and repeat for those accepted blocks until
	// there are no more.
	b.ProcessOrphans(blockHash, BFNone)	// flags)

	log.Infof("ProcessBlock finished with height = %d Miner height = %d Orphans = %d", b.BestSnapshot().Height,
		b.Miners.BestSnapshot().Height, b.Orphans.Count())

	return isMainChain, false, nil, -1
}

func (b *BlockChain) consistent(block *btcutil.Block, parent * chainutil.BlockNode) bool {
//	state := b.BestSnapshot()
	if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
		mstate := b.Miners.BestSnapshot()
		if -block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ > mstate.Height {
			return false
		}
	}

	if wire.CommitteeSize == 1 || block.MsgBlock().Header.Nonce > 0 {
		return true
	}

	best := b.BestSnapshot()
	rotate := best.LastRotation
	if parent.Hash != best.Hash {
		pn := b.NodeByHash(&parent.Hash)
		fork := b.FindFork(pn)

		if fork == nil {
			return false
		}

		// parent is not the tip, go back to find correct rotation
		for p := b.BestChain.Tip(); p != nil && p != fork; p = b.ParentNode(p) {
			switch {
			case p.Data.GetNonce() > 0:
				rotate -= wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate--
			}
		}
		for p := pn; p != nil && p != fork; p = b.ParentNode(p) {
			switch {
			case p.Data.GetNonce() > 0:
				rotate += wire.POWRotate

			case p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ:
				rotate++
			}
		}
	}

	// examine signers are in committee
	miners := make(map[[20]byte]struct{})

	for i := int32(0); i < wire.CommitteeSize; i++ {
		blk, _ := b.Miners.BlockByHeight(int32(rotate) - i)
		if blk == nil {
			return false
		}

		miners[blk.MsgBlock().Miner] = struct{}{}
	}

	for _, sign := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
		k, _ := btcec.ParsePubKey(sign[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		pk, _ := btcutil.NewAddressPubKeyPubKey(*k, b.ChainParams)
		pk.SetFormat(btcutil.PKFCompressed)
		ppk := pk.AddressPubKeyHash()
		snr := *(ppk.Hash160())
		// is the signer in committee?
		if _,ok := miners[snr]; !ok {
//			b.index.RemoveNode(b.index.LookupNode(block.Hash()))
			return false
		}
	}

	return true
}