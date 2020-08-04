// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"container/list"
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/omega/token"
	"sync"
	"time"

	"github.com/omegasuite/btcd/blockchain/bccompress"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/omega/viewpoint"
)

const (
	// maxOrphanBlocks is the maximum number of orphan blocks that can be
	// queued.
	maxOrphanBlocks = 2 * wire.MaxBlocksPerMsg

	// time (blocks) to hold miner account
	MinerHoldingPeriod = 3 * wire.MINER_RORATE_FREQ
)

// BestState houses information about the current best block and other info
// related to the state of the main chain as it exists from the point of view of
// the current best block.
//
// The BestSnapshot method can be used to obtain access to this information
// in a concurrent safe manner and the data will not be changed out from under
// the caller when chain state changes occur as the function name implies.
// However, the returned snapshot must be treated as immutable since it is
// shared by all callers.
type BestState struct {
	Hash        chainhash.Hash // The hash of the block.
	Height      int32          // The height of the block.
	Bits        uint32         // The difficulty bits of the block.
	TotalTxns   uint64         // The total number of txns in the chain.
	MedianTime  time.Time      // Median time as per CalcPastMedianTime.
	LastRotation uint32		   // height of the last rotate in Miner. normally
							   // it is nonce in last rotation block.
							   // for every POW block, it increase by CommitteeSize
							   // to phase out the last committee EVEN it means to pass the
							   // end of Miner chain (for consistency among nodes
	sizeLimits map[int32]uint32	// up to 5 most recent size limits

	// values below are not store in DB
	BlockSize   uint64         // The size of the block.
	NumTxns     uint64         // The number of txns in the block.
	Updated     time.Time      // local time the best state was updated.
}

// newBestState returns a new best stats instance for the given parameters.
func newBestState(node *chainutil.BlockNode, blockSize, numTxns,
	totalTxns uint64, medianTime time.Time, bits uint32, rotation uint32) *BestState {

	return &BestState{
		Hash:         node.Hash,
		Height:       node.Height,
		Bits:         bits,
		LastRotation: rotation,
		sizeLimits:	  make(map[int32]uint32),

		BlockSize:    blockSize,
		NumTxns:      numTxns,
		TotalTxns:    totalTxns,
		MedianTime:   medianTime,
	}
}

type MinerChain interface {
	ProcessBlock (*wire.MinerBlock, BehaviorFlags) (bool, bool, error, *chainhash.Hash)
	BestSnapshot () *BestState
	BlockByHash (hash *chainhash.Hash) (*wire.MinerBlock, error)
	BlockByHeight (height int32) (*wire.MinerBlock, error)
	CheckConnectBlockTemplate (*wire.MinerBlock) error
	CalcNextRequiredDifficulty (timestamp time.Time) (uint32, error)
	ProcessOrphans (* chainhash.Hash, BehaviorFlags) error
	IsCurrent () bool
	Subscribe(callback NotificationCallback)
	Tip() *wire.MinerBlock
	DisconnectTip()
	CalcNextBlockVersion() (uint32, error)
	IsDeploymentActive(uint32) (bool, error)
	HaveBlock(hash *chainhash.Hash) (bool, error)
}

type BlackList interface {
	IsBlack([20]byte) bool
	IsGrey([20]byte) bool
	Update(uint32)
	Rollback(uint32)
	Add(uint32, [20]byte)
	Remove(uint32)
}

type sizeCalculator struct {
	knownLimits map[int32]uint32		// block size limits height to tx

	// accumulator
	target int32
	sizeSum int64
	timeSum int64
	blockCount int32
	lastNode * chainutil.BlockNode

	mtx sync.Mutex
}

// BlockChain provides functions for working with the bitcoin block chain.
// It includes functionality such as rejecting duplicate blocks, ensuring blocks
// follow all rules, orphan handling, checkpoint handling, and best chain
// selection with reorganization.
type BlockChain struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	checkpoints         []chaincfg.Checkpoint
	checkpointsByHeight map[int32]*chaincfg.Checkpoint
	db                  database.DB
	ChainParams         *chaincfg.Params
	timeSource          chainutil.MedianTimeSource
	indexManager        IndexManager

	Miners 				MinerChain		// The Miner chain to provide the next Miner

	// The following fields are calculated based upon the provided chain
	// parameters.  They are also set when the instance is created and
	// can't be changed afterwards, so there is no need to protect them with
	// a separate mutex.
	minRetargetTimespan int64 // target timespan / adjustment factor
	maxRetargetTimespan int64 // target timespan * adjustment factor
	blocksPerRetarget   int32 // target timespan / target time per block

	// ChainLock protects concurrent access to the vast majority of the
	// fields in this struct below this point.
	ChainLock sync.RWMutex

	// These fields are related to the memory block index.  They both have
	// their own locks, however they are often also protected by the chain
	// lock to help prevent logic races when blocks are being processed.
	//
	// index houses the entire block index in memory.  The block index is
	// a tree-shaped structure.
	//
	// BestChain tracks the current active chain by making use of an
	// efficient chain view into the block index.
	index     *chainutil.BlockIndex
	BestChain *chainutil.ChainView

	// These fields are related to handling of orphan blocks.  They are
	// protected by a combination of the chain lock and the orphan lock.
	Orphans * chainutil.Orphans

	// These fields are related to checkpoint handling.  They are protected
	// by the chain lock.
	nextCheckpoint *chaincfg.Checkpoint
	checkpointNode *chainutil.BlockNode

	// The state is used as a fairly efficient way to cache information
	// about the current best chain state that is returned to callers when
	// requested.  It operates on the principle of MVCC such that any time a
	// new block becomes the best block, the state pointer is replaced with
	// a new struct and the old state is left untouched.  In this way,
	// multiple callers can be pointing to different best chain states.
	// This is acceptable for most callers because the state is only being
	// queried at a specific point in time.
	//
	// In addition, some of the fields are stored in the database so the
	// chain state can be quickly reconstructed on load.
	StateLock     sync.RWMutex
	stateSnapshot *BestState

	// The notifications field stores a slice of callbacks to be executed on
	// certain blockchain events.
	notificationsLock sync.RWMutex
	notifications     []NotificationCallback

	// The virtual machine
//	Vm        * ovm.OVM
//	SigVm     * ovm.OVM
	Blacklist BlackList

	Miner btcutil.Address

	// block size calculator
	blockSizer sizeCalculator
}

// HaveBlock returns whether or not the chain instance has the block represented
// by the passed hash.  This includes checking the various places a block can
// be like part of the main chain, on a side chain, or in the orphan pool.
//
// This function is safe for concurrent access.
func (b *BlockChain) HaveBlock(hash *chainhash.Hash) (bool, error) {
	exists, err := b.blockExists(hash)
	if err != nil {
		return false, err
	}
	return exists || b.Orphans.IsKnownOrphan(hash), nil
}

// SequenceLock represents the converted relative lock-time in seconds, and
// absolute block-height for a transaction input's relative lock-times.
// According to SequenceLock, after the referenced input has been confirmed
// within a block, a transaction spending that input can be included into a
// block either after 'seconds' (according to past median time), or once the
// 'BlockHeight' has been reached.
type SequenceLock struct {
	Seconds     int64
	BlockHeight int32
}

// CalcSequenceLock computes a relative lock-time SequenceLock for the passed
// transaction using the passed UtxoViewpoint to obtain the past median time
// for blocks in which the referenced inputs of the transactions were included
// within. The generated SequenceLock lock can be used in conjunction with a
// block height, and adjusted median block time to determine if all the inputs
// referenced within a transaction have reached sufficient maturity allowing
// the candidate transaction to be included in a block.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcSequenceLock(tx *btcutil.Tx, utxoView *viewpoint.UtxoViewpoint, mempool bool) (*SequenceLock, error) {
//	log.Infof("CalcSequenceLock: ChainLock.RLock")

	b.ChainLock.Lock()
	defer b.ChainLock.Unlock()
/*
	func () {
		b.ChainLock.Unlock()
		log.Infof("CalcSequenceLock: ChainLock.Unlock")
	} ()
*/

	return b.calcSequenceLock(b.BestChain.Tip(), tx, utxoView, mempool)
}

// calcSequenceLock computes the relative lock-times for the passed
// transaction. See the exported version, CalcSequenceLock for further details.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) calcSequenceLock(node *chainutil.BlockNode, tx *btcutil.Tx, utxoView *viewpoint.UtxoViewpoint, mempool bool) (*SequenceLock, error) {
	// A value of -1 for each relative lock type represents a relative time
	// lock value that will allow a transaction to be included in a block
	// at any given height or time. This value is returned as the relative
	// lock time in the case that BIP 68 is disabled, or has not yet been
	// activated.
	sequenceLock := &SequenceLock{Seconds: -1, BlockHeight: -1}

	// If the transaction's version is less than 2, and BIP 68 has not yet
	// been activated then sequence locks are disabled. Additionally,
	// sequence locks don't apply to coinbase transactions Therefore, we
	// return sequence lock values of -1 indicating that this transaction
	// can be included within a block at any given height or time.
	mTx := tx.MsgTx()
	sequenceLockActive := mTx.Version >= 2
	if !sequenceLockActive || IsCoinBase(tx) {
		return sequenceLock, nil
	}

	// Grab the next height from the PoV of the passed blockNode to use for
	// inputs present in the mempool.
	nextHeight := node.Height + 1

	for txInIndex, txIn := range mTx.TxIn {
		if txIn.IsSeparator() {
			continue
		}
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return sequenceLock, ruleError(ErrMissingTxOut, str)
		}

		// If the input height is set to the mempool height, then we
		// assume the transaction makes it into the next block when
		// evaluating its sequence blocks.
		inputHeight := utxo.BlockHeight()
		if inputHeight == 0x7fffffff {
			inputHeight = nextHeight
		}

		// Given a sequence number, we apply the relative time lock
		// mask in order to obtain the time lock delta required before
		// this input can be spent.
		sequenceNum := txIn.Sequence
		relativeLock := int64(sequenceNum & wire.SequenceLockTimeMask)

		switch {
		// Relative time locks are disabled for this input, so we can
		// skip any further calculation.
		case sequenceNum&wire.SequenceLockTimeDisabled == wire.SequenceLockTimeDisabled:
			continue
		case sequenceNum&wire.SequenceLockTimeIsSeconds == wire.SequenceLockTimeIsSeconds:
			// This input requires a relative time lock expressed
			// in seconds before it can be spent.  Therefore, we
			// need to query for the block prior to the one in
			// which this input was included within so we can
			// compute the past median time for the block prior to
			// the one which included this referenced output.
			prevInputHeight := inputHeight - 1
			if prevInputHeight < 0 {
				prevInputHeight = 0
			}
			blockNode := node.Ancestor(prevInputHeight)
			medianTime := blockNode.CalcPastMedianTime()

			// Time based relative time-locks as defined by BIP 68
			// have a time granularity of RelativeLockSeconds, so
			// we shift left by this amount to convert to the
			// proper relative time-lock. We also subtract one from
			// the relative lock to maintain the original lockTime
			// semantics.
			timeLockSeconds := (relativeLock << wire.SequenceLockTimeGranularity) - 1
			timeLock := medianTime.Unix() + timeLockSeconds
			if timeLock > sequenceLock.Seconds {
				sequenceLock.Seconds = timeLock
			}
		default:
			// The relative lock-time for this input is expressed
			// in blocks so we calculate the relative offset from
			// the input's height as its converted absolute
			// lock-time. We subtract one from the relative lock in
			// order to maintain the original lockTime semantics.
			blockHeight := inputHeight + int32(relativeLock-1)
			if blockHeight > sequenceLock.BlockHeight {
				sequenceLock.BlockHeight = blockHeight
			}
		}
	}

	return sequenceLock, nil
}

// LockTimeToSequence converts the passed relative locktime to a sequence
// number in accordance to BIP-68.
// See: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
//  * (Compatibility)
func LockTimeToSequence(isSeconds bool, locktime uint32) uint32 {
	// If we're expressing the relative lock time in blocks, then the
	// corresponding sequence number is simply the desired input age.
	if !isSeconds {
		return locktime
	}

	// Set the 22nd bit which indicates the lock time is in seconds, then
	// shift the locktime over by 9 since the time granularity is in
	// 512-second intervals (2^9). This results in a max lock-time of
	// 33,553,920 seconds, or 1.1 years.
	return wire.SequenceLockTimeIsSeconds |
		locktime>>wire.SequenceLockTimeGranularity
}

func (b *BlockChain) TotalRotate(lst * list.List) int32 {
	s := int32(0)
	for e := lst.Front(); e != nil; e = e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		if n.Data.GetNonce() > 0 {
			s += wire.POWRotate
		} else if n.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			s++
		}
	}
	return s
}

func (b *BlockChain) GetReorganizeSideChain(hash chainhash.Hash) (*list.List, *list.List) {
	attachNodes := list.New()
	detachNodes := list.New()

	node := b.index.LookupNode(&hash)
	if b.BestChain.Contains(node) {
		return detachNodes, attachNodes
	}

	// find the best side chain
	bs := node
	for _, t := range b.index.Tips {
		if t.Height <= bs.Height {
			continue
		}
		s := t
		for ; s.Height > node.Height; s = s.Parent {}
		if s == node && t.Height > bs.Height {
			bs = t
		}
	}
	return b.getReorganizeNodes(bs)
}

// getReorganizeNodes finds the fork point between the main chain and the passed
// node and returns a list of block nodes that would need to be detached from
// the main chain and a list of block nodes that would need to be attached to
// the fork point (which will be the end of the main chain after detaching the
// returned list of block nodes) in order to reorganize the chain such that the
// passed node is the new end of the main chain.  The lists will be empty if the
// passed node is not on a side chain.
//
// This function may modify node statuses in the block index without flushing.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) getReorganizeNodes(node *chainutil.BlockNode) (*list.List, *list.List) {
	attachNodes := list.New()
	detachNodes := list.New()

	// Do not reorganize to a known invalid chain. Ancestors deeper than the
	// direct parent are checked below but this is a quick check before doing
	// more unnecessary work.
	if b.index.NodeStatus(node.Parent).KnownInvalid() {
//		b.index.SetStatusFlags(node, chainutil.StatusInvalidAncestor)
		return detachNodes, attachNodes
	}

	// Find the fork point (if any) adding each block to the list of nodes
	// to attach to the main tree.  Push them onto the list in reverse order
	// so they are attached in the appropriate order when iterating the list
	// later.
	forkNode := b.BestChain.FindFork(node)

	// fork node can not be before the last block reference by tip of miner chain
	bh := b.Miners.Tip().MsgBlock().BestBlock
	ht,_ := b.BlockHeightByHash(&bh)
	if forkNode.Height < ht {
		return detachNodes, attachNodes
	}

	for p := node; p != nil && p != forkNode; p = p.Parent {
		if p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			h := -p.Data.GetNonce() - wire.MINER_RORATE_FREQ
			mb, _ := b.Miners.BlockByHeight(h)
			if mb == nil {
				node = p.Parent
				if node == forkNode {
					return detachNodes, attachNodes
				}
			}
		}
	}

	invalidChain := false
	for n := node; n != nil && n != forkNode; n = n.Parent {
		if b.index.NodeStatus(n).KnownInvalid() {
			invalidChain = true
			break
		}
		attachNodes.PushFront(n)
	}

	// If any of the node's ancestors are invalid, unwind attachNodes, marking
	// each one as invalid for future reference.
	if invalidChain {
		var next *list.Element
		for e := attachNodes.Front(); e != nil; e = next {
			next = e.Next()
			attachNodes.Remove(e)


//			n := attachNodes.Remove(e).(*chainutil.BlockNode)
//			b.index.SetStatusFlags(n, chainutil.StatusInvalidAncestor)
		}
		return detachNodes, attachNodes
	}

	// Start from the end of the main chain and work backwards until the
	// common ancestor adding each block to the list of nodes to detach from
	// the main chain.
	for n := b.BestChain.Tip(); n != nil && n != forkNode; n = n.Parent {
		detachNodes.PushBack(n)
	}

	return detachNodes, attachNodes
}

func (s * BlockChain) GetRollbackList(h int32) * list.List {
	detachNodes := list.New()

	for n := s.BestChain.Tip(); n != nil; n = n.Parent {
		if n.Data.GetNonce() > -wire.MINER_RORATE_FREQ || n.Data.GetNonce() < -(h + wire.MINER_RORATE_FREQ) {
			detachNodes.PushBack(n)
		} else {
			detachNodes.PushBack(n)
			break
		}
	}
	return detachNodes
}
// connectBlock handles connecting the passed node/block to the end of the main
// (best) chain.
//
// This passed utxo view must have all referenced txos the block spends marked
// as spent and all of the new txos the block creates added to it.  In addition,
// the passed stxos slice must be populated with all of the information for the
// spent txos.  This approach is used because the connection validation that
// must happen prior to calling this function requires the same details, so
// it would be inefficient to repeat it.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) connectBlock(node *chainutil.BlockNode, block *btcutil.Block,
	view *viewpoint.ViewPointSet, stxos []viewpoint.SpentTxOut, vm * ovm.OVM) error {

	if block.MsgBlock().Header.Nonce < 0 && len(block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSigs {
		return fmt.Errorf("insifficient signatures")
	}
	if block.MsgBlock().Header.Nonce < 0 && len(block.MsgBlock().Transactions[0].SignatureScripts[1]) < btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("incorrect signatures")
	}

	// Make sure it's extending the end of the best chain.
	prevHash := &block.MsgBlock().Header.PrevBlock
	if !prevHash.IsEqual(&b.BestChain.Tip().Hash) {
		return AssertError("connectBlock must be called with a block " +
			"that extends the main chain")
	}

	// Sanity check the correct number of stxos are provided.
	if len(stxos) != block.CountSpentOutputs() {
		return AssertError("connectBlock called with inconsistent " +
			"spent transaction out information")
	}

	// Write any block status changes to DB before updating best state.
	err := b.index.FlushToDB(dbStoreBlockNode)
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.StateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	b.StateLock.RUnlock()
	numTxns := uint64(len(block.MsgBlock().Transactions))
	blockSize := uint64(block.MsgBlock().SerializeSize())
//	blockLimit := uint64(b.GetBlockLimit(block))

	bst := b.BestSnapshot()

	state := newBestState(node, blockSize, numTxns,
		curTotalTxns+numTxns, node.CalcPastMedianTime(), bst.Bits,
		bst.LastRotation)
	state.sizeLimits = b.blockSizer.knownLimits

	if node.Data.GetNonce() > 0 {
		state.LastRotation += wire.POWRotate
		log.Infof("Update LastRotation to %d", state.LastRotation)
	} else if node.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
		state.LastRotation = uint32(-node.Data.GetNonce() - wire.MINER_RORATE_FREQ)
		log.Infof("Update LastRotation to %d", state.LastRotation)
		s, _ := b.Miners.BlockByHeight(int32(state.LastRotation))
		state.Bits = s.MsgBlock().Bits
	}

	// Atomically insert info into the database.
	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state)
		if err != nil {
			return err
		}

		// Add the block hash and height to the block index which tracks
		// the main chain.
		err = DbPutBlockIndex(dbTx, block.Hash(), node.Height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails removing all of the utxos spent and adding the new
		// ones created by the block.
		err = viewpoint.DbPutViews(dbTx, view)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by adding a record for
		// the block that contains all txos spent by it.
		err = dbPutSpendJournalEntry(dbTx, block.Hash(), stxos)
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being connected so they can
		// update themselves accordingly.
		if b.indexManager != nil {
			err := b.indexManager.ConnectBlock(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.Commit()
	vm.Commit()

	// This node is now the end of the best chain.
	b.BestChain.SetTip(node)

	// update blocklist
	b.Blacklist.Update(uint32(node.Height))

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.StateLock.Lock()
	b.stateSnapshot = state
	b.StateLock.Unlock()

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	b.ChainLock.Unlock()
	b.SendNotification(NTBlockConnected, block)
	b.ChainLock.Lock()

	return nil
}

// disconnectBlock handles disconnecting the passed node/block from the end of
// the main (best) chain.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) disconnectBlock(node *chainutil.BlockNode, block *btcutil.Block, view *viewpoint.ViewPointSet, vm * ovm.OVM) error {
	// Make sure the node being disconnected is the end of the best chain.
	if !node.Hash.IsEqual(&b.BestChain.Tip().Hash) {
		return AssertError("disconnectBlock must be called with the " +
			"block at the end of the main chain")
	}

	// Load the previous block since some details for it are needed below.
	prevNode := node.Parent
	var prevBlock *btcutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		prevBlock, err = dbFetchBlockByNode(dbTx, prevNode)
		return err
	})
	if err != nil {
		return err
	}

	// Write any block status changes to DB before updating best state.
	err = b.index.FlushToDB(dbStoreBlockNode)
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.StateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	rotation := b.stateSnapshot.LastRotation
	bits := b.stateSnapshot.Bits
	b.StateLock.RUnlock()

	numTxns := uint64(len(prevBlock.MsgBlock().Transactions))
	blockSize := uint64(prevBlock.MsgBlock().SerializeSize())
//	blockLimit := uint64(b.GetBlockLimit(prevBlock))
	newTotalTxns := curTotalTxns - uint64(len(block.MsgBlock().Transactions))

	if node.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
		// the removed block was the first of a series rotated-in block, difficulty should be
		// in its previous block
		p := node.Parent

		for p != nil && p.Data.GetNonce() > -wire.MINER_RORATE_FREQ {
			p = p.Parent
		}

		realheight := int32(0)
		if p != nil {
			realheight = -p.Data.GetNonce() - wire.MINER_RORATE_FREQ
		}

		// the real Miner block height of the previous Miner block
		mblock, err := b.Miners.BlockByHeight(realheight)
		if err != nil {
//			continue  // err		// impossible. only when database is corrupt
		} else {
			bits = mblock.MsgBlock().Bits
		}
	}

	if node.Data.GetNonce() >= 0 {
		rotation -= wire.POWRotate
	} else if node.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
		rotation--
	}

	if rotation < 0 {		// should never happen
		rotation = 0
	}

	state := newBestState(prevNode, blockSize, numTxns,
		newTotalTxns, prevNode.CalcPastMedianTime(), bits, rotation)	// prevNode.bits, b.BestSnapshot().LastRotation)
	state.sizeLimits = b.blockSizer.knownLimits

	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state)
		if err != nil {
			return err
		}

		// Remove the block hash and height from the block index which
		// tracks the main chain.
		err = DbRemoveBlockIndex(dbTx, block.Hash(), node.Height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails restoring all of the utxos spent and removing the new
		// ones created by the block.
		err = viewpoint.DbPutViews(dbTx, view)
		if err != nil {
			return err
		}

		// Before we delete the spend journal entry for this back,
		// we'll fetch it as is so the indexers can utilize if needed.
		stxos, err := dbFetchSpendJournalEntry(dbTx, block)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by removing the record
		// that contains all txos spent by the block.
		err = dbRemoveSpendJournalEntry(dbTx, block.Hash())
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being disconnected so they
		// can update themselves accordingly.
		if b.indexManager != nil {
			err := b.indexManager.DisconnectBlock(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.Commit()
	vm.Rollback()

	if b.Blacklist != nil {
		b.Blacklist.Rollback(uint32(node.Height))
	}

	// This node's parent is now the end of the best chain.
	b.BestChain.SetTip(node.Parent)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.StateLock.Lock()
	b.stateSnapshot = state
	b.StateLock.Unlock()

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	b.ChainLock.Unlock()
	b.SendNotification(NTBlockDisconnected, block)
	b.ChainLock.Lock()

	return nil
}

func (b *BlockChain) Advance(x * list.Element) int32 {
	m := x.Value.(*chainutil.BlockNode)
	shift := int32(0)
	if m.Data.GetNonce() > 0 {
		shift = wire.POWRotate
	} else if m.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
		shift = 1
	}
	return shift
}

func (b *BlockChain) SideChainContains(x * list.Element, hash chainhash.Hash) bool {
	n := x.Value.(*chainutil.BlockNode)
	for n != nil && n.Hash != hash {
		n = n.Parent
	}
	return n != nil
}

func (b *BlockChain) SignedBy(x * list.Element, miners [][20]byte) bool {
	n := x.Value.(*chainutil.BlockNode)
	if n.Data.GetNonce() > 0 {
		return true
	}

	var block *btcutil.Block
	b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, n)
		return err
	})

	return b.signedBy(block, miners)
}

func (b *BlockChain) signedBy(block * btcutil.Block, miners [][20]byte) bool {
	for _, sign := range block.MsgBlock().Transactions[0].SignatureScripts[1:] {
		k, _ := btcec.ParsePubKey(sign[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		pk, _ := btcutil.NewAddressPubKeyPubKey(*k, b.ChainParams)
		// is the signer in committee?
		signer := *pk.AddressPubKeyHash().Hash160()
		matched := false
		for _, sig := range miners {
			if bytes.Compare(signer[:], sig[:]) != 0 {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func skipList(lst * list.List, y * list.Element) {
	for y != nil {
		z := y.Next()
		lst.Remove(y)
		y = z
	}
}

// ReorganizeChain reorganizes the block chain by disconnecting the nodes in the
// detachNodes list and connecting the nodes in the attach list.  It expects
// that the lists are already in the correct order and are in sync with the
// end of the current best chain.  Specifically, nodes that are being
// disconnected must be in reverse order (think of popping them off the end of
// the chain) and nodes the are being attached must be in forwards order
// (think pushing them onto the end of the chain).
//
// This function may modify node statuses in the block index without flushing.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) ReorganizeChain(detachNodes, attachNodes *list.List) error {
	// Nothing to do if no reorganize nodes were provided.
	if detachNodes.Len() == 0 && attachNodes.Len() == 0 {
		return nil
	}

	// Ensure the provided nodes match the current best chain.
	tip := b.BestChain.Tip()
	if detachNodes.Len() != 0 {
		firstDetachNode := detachNodes.Front().Value.(*chainutil.BlockNode)
		if firstDetachNode.Hash != tip.Hash {
			return AssertError(fmt.Sprintf("reorganize nodes to detach are "+
				"not for the current best chain -- first detach node %v, "+
				"current chain %v", &firstDetachNode.Hash, &tip.Hash))
		}
	}

	// Ensure the provided nodes are for the same fork point.
	if attachNodes.Len() != 0 && detachNodes.Len() != 0 {
		firstAttachNode := attachNodes.Front().Value.(*chainutil.BlockNode)
		lastDetachNode := detachNodes.Back().Value.(*chainutil.BlockNode)
		if firstAttachNode.Parent.Hash != lastDetachNode.Parent.Hash {
			return AssertError(fmt.Sprintf("reorganize nodes do not have the "+
				"same fork point -- first attach parent %v, last detach "+
				"parent %v", &firstAttachNode.Parent.Hash,
				&lastDetachNode.Parent.Hash))
		}
	}

	// Track the old and new best chains heads.
	oldBest := tip
	newBest := tip

	// All of the blocks to detach and related spend journal entries needed
	// to unspend transaction outputs in the blocks being disconnected must
	// be loaded from the database during the reorg check phase below and
	// then they are needed again when doing the actual database updates.
	// Rather than doing two loads, cache the loaded data into these slices.
	detachBlocks := make([]*btcutil.Block, 0, detachNodes.Len())
	detachSpentTxOuts := make([][]viewpoint.SpentTxOut, 0, detachNodes.Len())
	attachBlocks := make([]*btcutil.Block, 0, attachNodes.Len())

	state := b.BestSnapshot()
	rotate := state.LastRotation

	// Disconnect all of the blocks back to the point of the fork.  This
	// entails loading the blocks and their associated spent txos from the
	// database and using that information to unspend all of the spent txos
	// and remove the utxos created by the blocks.
	views, Vm := b.Canvas(nil)
	views.SetBestHash(&oldBest.Hash)

	for e := detachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		if n.Parent == nil {
			// never remove genesis block
			continue
		}
		var block *btcutil.Block
		err := b.db.View(func(dbTx database.Tx) error {
			var err error
			block, err = dbFetchBlockByNode(dbTx, n)
			return err
		})
		if err != nil {
			return err
		}
		if n.Hash != *block.Hash() {
			return AssertError(fmt.Sprintf("detach block node hash %v (height "+
				"%v) does not match previous parent block hash %v", &n.Hash,
				n.Height, block.Hash()))
		}

		// Load all of the utxos referenced by the block that aren't
		// already in the view.
		err = views.FetchInputUtxos(block)
		if err != nil {
			return err
		}

		// Load all of the spent txos for the block from the spend
		// journal.
		var stxos []viewpoint.SpentTxOut
		err = b.db.View(func(dbTx database.Tx) error {
			stxos, err = dbFetchSpendJournalEntry(dbTx, block)
			return err
		})
		if err != nil {
			return err
		}

		// Store the loaded block and spend journal entry for later.
		detachBlocks = append(detachBlocks, block)
		detachSpentTxOuts = append(detachSpentTxOuts, stxos)

		err = views.DisconnectTransactions(b.db, block, stxos)
		if err != nil {
			return err
		}

		if n.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			rotate--
		} else if n.Data.GetNonce() > 0 {
			rotate -= wire.POWRotate
		}

		newBest = n.Parent
	}

	// Set the fork point only if there are nodes to attach since otherwise
	// blocks are only being disconnected and thus there is no fork point.
	var forkNode *chainutil.BlockNode
	if attachNodes.Len() > 0 {
		forkNode = newBest
	}

	// Perform several checks to verify each block that needs to be attached
	// to the main chain can be connected without violating any rules and
	// without actually connecting the block.
	//
	// NOTE: These checks could be done directly when connecting a block,
	// however the downside to that approach is that if any of these checks
	// fail after disconnecting some blocks or attaching others, all of the
	// operations have to be rolled back to get the chain back into the
	// state it was before the rule violation (or other failure).  There are
	// at least a couple of ways accomplish that rollback, but both involve
	// tweaking the chain and/or database.  This approach catches these
	// issues before ever modifying the chain.

	// examine signers are in committee
	miners := make([][20]byte, wire.CommitteeSize)
	for i := int32(0); i < wire.CommitteeSize; i++ {
		if blk, _ := b.Miners.BlockByHeight(int32(rotate) - wire.CommitteeSize + i + 1); blk != nil {
			if err := b.CheckCollateral(blk, BFNone); err != nil {
				return err
			}
			miners[i] = blk.MsgBlock().Miner
		}
	}

//	prevNode := forkNode
	skipped := false
	for e := attachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*chainutil.BlockNode)

		var block *btcutil.Block
		err := b.db.View(func(dbTx database.Tx) error {
			var err error
			block, err = dbFetchBlockByNode(dbTx, n)
			return err
		})
		if err != nil {
			return err
		}

		if !b.signedBy(block, miners) {
			skipList(attachNodes, e)
			skipped = true
			continue
		}

		shift := 0
		if n.Data.GetNonce() > 0 {
			shift = wire.POWRotate
		} else if n.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			shift = 1
		}
		if shift > 0 {
			j := 0
			for k := shift; k < wire.CommitteeSize; k++ {
				copy(miners[j][:], miners[k][:])
				j++
			}

			for k := 0; k < shift; k++ {
				rotate++
				if blk, _ := b.Miners.BlockByHeight(int32(rotate)); blk != nil {
					if err := b.CheckCollateral(blk, BFNone); err != nil {
						return err
					}
					miners[j] = blk.MsgBlock().Miner
				} else if shift == 1 {
					return fmt.Errorf("Incorrect rotation")
				}
				j++
			}
		}

		b.index.UnsetStatusFlags(n, chainutil.StatusValid)

		// Store the loaded block for later.
		attachBlocks = append(attachBlocks, block)

		// Notice the spent txout details are not requested here and
		// thus will not be generated.  This is done because the state
		// is not being immediately written to the database, so it is
		// not needed.
		//
		// In the case the block is determined to be invalid due to a
		// rule violation, mark it as invalid and mark all of its
		// descendants as having an invalid ancestor.
		err = b.checkConnectBlock(n, block, views, nil, Vm)
		if err != nil {
			if _, ok := err.(RuleError); ok {
				b.index.SetStatusFlags(n, chainutil.StatusValidateFailed)
				for de := e.Next(); de != nil; de = de.Next() {
					dn := de.Value.(*chainutil.BlockNode)
					b.index.SetStatusFlags(dn, chainutil.StatusInvalidAncestor)
				}
			}
			return err
		}

		newBest = n
	}

	if skipped && attachNodes.Len() <= detachNodes.Len() {
		return fmt.Errorf("attach block failed to pass consistency check")
	}

	// Reset the view for the actual connection code below.  This is
	// required because the view was previously modified when checking if
	// the reorg would be successful and the connection code requires the
	// view to be valid from the viewpoint of each block being connected or
	// disconnected.

	views, Vm = b.Canvas(nil)
	views.SetBestHash(&b.BestChain.Tip().Hash)

	detachto := int32(0x7FFFFFFF)

	// Disconnect blocks from the main chain.
	for i, e := 0, detachNodes.Front(); e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		if n.Parent == nil {
			// never remove genesis block
			continue
		}

		block := detachBlocks[i]

		Vm.BlockNumber = func() uint64 {
			return uint64(block.Height())
		}
		Vm.Block = func() *btcutil.Block { return block }

		// Load all of the utxos referenced by the block that aren't
		// already in the view.
		err := views.FetchInputUtxos(block)
		if err != nil {
			return err
		}

		// Update the view to unspend all of the spent txos and remove
		// the utxos created by the block.
		err = views.DisconnectTransactions(b.db, block,	detachSpentTxOuts[i])
		if err != nil {
			return err
		}

		// Update the database and chain state.
		err = b.disconnectBlock(n, block, views, Vm)
		if err != nil {
			return err
		}

		Vm.BlockNumber = func() uint64 {
			return uint64(block.Height())
		}
		Vm.Block = func() *btcutil.Block { return block }
		Vm.Rollback()

		for *block.Hash() == b.Miners.Tip().MsgBlock().BestBlock {
			// also disconnect the Miner chain tip. make it an orphan!
			b.Miners.DisconnectTip()
		}
		
		detachto = n.Height
	}

	b.blockSizer.RollBackTo(detachto)

	// Connect the new best chain blocks.
	e := attachNodes.Front()
	// check if it is within holding period: a miner can not do any transaction
	// within MinerHoldingPeriod blocks since he becomes a member
	minersonhold := make(map[wire.OutPoint]int32)
	var p *chainutil.BlockNode
	if e != nil {
		p = e.Value.(*chainutil.BlockNode)
	}
	for i := int32(0); p != nil && i < MinerHoldingPeriod; i++ {
		if p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			mb,_ := b.Miners.BlockByHeight(-p.Data.GetNonce() - wire.MINER_RORATE_FREQ)
			for _,q := range mb.MsgBlock().Utxos {
				minersonhold[q] = p.Height
			}
		}
		p = p.Parent
	}

	for i := 0; e != nil; i, e = i+1, e.Next() {
		if i >= len(attachBlocks) {
			break
		}
		block := attachBlocks[i]

		coinBase := btcutil.NewTx(block.MsgBlock().Transactions[0].Stripped())
		coinBase.SetIndex(block.Transactions()[0].Index())
		coinBaseHash := *coinBase.Hash()
		Vm.SetCoinBaseOp(
			func(txo wire.TxOut) wire.OutPoint {
				if !coinBase.HasOuts {
					// this servers as a separater. only TokenType is serialized
					to := wire.TxOut{}
					to.Token = token.Token{TokenType: token.DefTypeSeparator}
					coinBase.MsgTx().AddTxOut(&to)
					coinBase.HasOuts = true
				}
				coinBase.MsgTx().AddTxOut(&txo)
				op := wire.OutPoint { coinBaseHash, uint32(len(coinBase.MsgTx().TxOut) - 1)}
				return op
		})
		Vm.BlockNumber = func() uint64 {
			return uint64(block.Height())
		}
		Vm.Block = func() *btcutil.Block { return block }
		Vm.GasLimit = block.MsgBlock().Header.ContractExec
		Vm.GetCoinBase = func() *btcutil.Tx { return coinBase }

		for i, tx := range block.Transactions() {
			if i == 0 {
				continue
			}
			newtx := btcutil.NewTx(tx.MsgTx().Stripped())
			newtx.SetIndex(tx.Index())
			err := Vm.ExecContract(newtx, block.Height())
			if err != nil {
				Vm.AbortRollback()
				return err
			}

			// compare tx & newtx
			if !tx.Match(newtx) {
				Vm.AbortRollback()
				return fmt.Errorf("Mismatch contract execution result")
			}
		}
		if !block.Transactions()[0].Match(coinBase) {
			Vm.AbortRollback()
			return fmt.Errorf("Mismatch contract execution result")
		}
		if Vm.GasLimit != 0 {
			Vm.AbortRollback()
			return fmt.Errorf("Incorrect contract execution cost.")
		}
	}

	Vm.Reset()
	e = attachNodes.Front()
	for i := 0; e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*chainutil.BlockNode)

		if i >= len(attachBlocks) {
			break
		}
		block := attachBlocks[i]

		// Load all of the utxos referenced by the block that aren't
		// already in the view.
		err := views.FetchInputUtxos(block)
		if err != nil {
			return err		// should panic. this should never happend and would potentially corrupt the database
		}

		coinBase := btcutil.NewTx(block.MsgBlock().Transactions[0].Stripped())
		coinBase.SetIndex(block.Transactions()[0].Index())
		coinBaseHash := *coinBase.Hash()
		Vm.SetCoinBaseOp(
			func(txo wire.TxOut) wire.OutPoint {
				if !coinBase.HasOuts {
					// this servers as a separater. only TokenType is serialized
					to := wire.TxOut{}
					to.Token = token.Token{TokenType: token.DefTypeSeparator}
					coinBase.MsgTx().AddTxOut(&to)
					coinBase.HasOuts = true
				}
				coinBase.MsgTx().AddTxOut(&txo)
				op := wire.OutPoint { coinBaseHash, uint32(len(coinBase.MsgTx().TxOut) - 1)}
				return op
			})
		Vm.BlockNumber = func() uint64 {
			return uint64(block.Height())
		}
		Vm.Block = func() *btcutil.Block { return block }
		Vm.GasLimit = block.MsgBlock().Header.ContractExec
		Vm.GetCoinBase = func() *btcutil.Tx { return coinBase }

		for i, tx := range block.Transactions() {
			if i == 0 {
				continue
			}
			newtx := btcutil.NewTx(tx.MsgTx().Stripped())
			newtx.SetIndex(tx.Index())
			Vm.ExecContract(newtx, block.Height())
		}
		Vm.Commit()	// commit state change & establish a rollback point

		// Update the view to mark all utxos referenced by the block
		// as spent and add all transactions being created by this block
		// to it.  Also, provide an stxo slice so the spent txout
		// details are generated.
		stxos := make([]viewpoint.SpentTxOut, 0, block.CountSpentOutputs())
		err = views.ConnectTransactions(block, &stxos, minersonhold)
		if err != nil {
			return err		// should panic. this should never happend and would potentially corrupt the database
		}

		// Update the database and chain state.
		err = b.connectBlock(n, block, views, stxos, Vm)
		if err != nil {
			return err		// should panic. this should never happend and would potentially corrupt the database
		}

		for u,v := range minersonhold {
			if v + MinerHoldingPeriod < n.Height {
				delete(minersonhold, u)
			}
		}
		if block.MsgBlock().Header.Nonce <= -wire.MINER_RORATE_FREQ {
			mb,_ := b.Miners.BlockByHeight(-block.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ)
			for _,q := range mb.MsgBlock().Utxos {
				minersonhold[q] = block.Height()
			}
		}

		b.index.SetStatusFlags(n, chainutil.StatusValid)
	}

	// Log the point where the chain forked and old and new best chain
	// heads.
	if forkNode != nil {
		log.Infof("REORGANIZE: Chain forks at %v (height %v)", forkNode.Hash,
			forkNode.Height)
	}
	log.Infof("REORGANIZE: Old best chain head was %v (height %v)",
		&oldBest.Hash, oldBest.Height)
	log.Infof("REORGANIZE: New best chain head is %v (height %v)",
		newBest.Hash, newBest.Height)

	return nil
}

// checkBlockSanity check whether the miner has provided sufficient collateral
func (b *BlockChain) CheckCollateral(block *wire.MinerBlock, flags BehaviorFlags) error {
	req := wire.Collateral(block.Height())
	if req == 0 {
		return nil
	}
	utxos := viewpoint.NewUtxoViewpoint()
	sum := int64(0)
	for _,p := range block.MsgBlock().Utxos {
		if err := utxos.FetchUtxosMain(b.db, map[wire.OutPoint]struct{}{p: struct{}{}}); err != nil {
			return err
		}
	}
	for _,e := range utxos.Entries() {
		if e == nil {
			continue
		}
		if e.TokenType != 0 {
			return fmt.Errorf("Collateral is not OTC.")
		}
		sum += e.Amount.(*token.NumToken).Val
	}
	if sum < req {
		return fmt.Errorf("Insufficient Collateral.")
	}
	return nil
}

func (b *BlockChain) Canvas(block *btcutil.Block) (*viewpoint.ViewPointSet, *ovm.OVM) {
	views := b.NewViewPointSet()

	// initialize OVM
	Vm := ovm.NewOVM(b.ChainParams)
	Vm.SetViewPoint(views)

	if block != nil {
		Vm.BlockNumber = func() uint64 {
			return uint64(block.Height())
		}
		Vm.Block = func() *btcutil.Block { return block }
		Vm.SetCoinBaseOp(
			func(txo wire.TxOut) wire.OutPoint {
				tx, _ := block.Tx(0)
				msg := tx.MsgTx()
				if !tx.HasOuts {
					// this servers as a separater. only TokenType is serialized
					to := wire.TxOut{}
					to.Token = token.Token{TokenType: token.DefTypeSeparator}
					msg.AddTxOut(&to)
					tx.HasOuts = true
				}
				msg.AddTxOut(&txo)
				op := wire.OutPoint{*tx.Hash(), uint32(len(msg.TxOut) - 1)}
//				views.Utxo.AddRawTxOut(op, &txo, false, block.Height())
				return op
			})
	}

	return views, Vm
}


// connectBestChain handles connecting the passed block to the chain while
// respecting proper chain selection according to the chain with the most
// proof of work.  In the typical case, the new block simply extends the main
// chain.  However, it may also be extending (or creating) a side chain (fork)
// which may or may not end up becoming the main chain depending on which fork
// cumulatively has the most proof of work.  It returns whether or not the block
// ended up on the main chain (either due to extending the main chain or causing
// a reorganization to become the main chain).
//
// The flags modify the behavior of this function as follows:
//  - BFFastAdd: Avoids several expensive transaction validation operations.
//    This is useful when using checkpoints.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) connectBestChain(node *chainutil.BlockNode, block *btcutil.Block, flags BehaviorFlags) (bool, error) {
	fastAdd := flags&BFFastAdd == BFFastAdd

	flushIndexState := func() {
		// Intentionally ignore errors writing updated node status to DB. If
		// it fails to write, it's not the end of the world. If the block is
		// valid, we flush in connectBlock and if the block is invalid, the
		// worst that can happen is we revalidate the block after a restart.
		if writeErr := b.index.FlushToDB(dbStoreBlockNode); writeErr != nil {
			log.Warnf("Error flushing block index changes to disk: %v",
				writeErr)
		}
	}

	// check if it is within holding period: a miner can not do any transaction
	// within MinerHoldingPeriod blocks since he becomes a member
	minersonhold := make(map[wire.OutPoint]int32)
	for i, p := int32(0), node.Parent; p != nil && i < MinerHoldingPeriod; i++ {
		if p.Data.GetNonce() <= -wire.MINER_RORATE_FREQ {
			mb,_ := b.Miners.BlockByHeight(-p.Data.GetNonce() - wire.MINER_RORATE_FREQ)
			if mb == nil {
				return false, fmt.Errorf("missing miner block")
			}
			for _,q := range mb.MsgBlock().Utxos {
				minersonhold[q] = p.Height
			}
		}
		p = p.Parent
	}

	// We are extending the main (best) chain with a new block.  This is the
	// most common case.
	parentHash := &block.MsgBlock().Header.PrevBlock
	parent := b.index.LookupNode(parentHash)
	if parentHash.IsEqual(&b.BestChain.Tip().Hash) && b.consistent(block, parent) {
		// Skip checks if node has already been fully validated.
		fastAdd = fastAdd || b.index.NodeStatus(node).KnownValid()

		// Perform several checks to verify the block can be connected
		// to the main chain without violating any rules and without
		// actually connecting the block.
		views, Vm := b.Canvas(block)
//		views.db = &b.db
//		view := NewUtxoViewpoint()
		views.Utxo.SetBestHash(parentHash)
		stxos := make([]viewpoint.SpentTxOut, 0, block.CountSpentOutputs())
		if !fastAdd {
			err := b.checkConnectBlock(node, block, views, &stxos, Vm)
			if err == nil {
				b.index.SetStatusFlags(node, chainutil.StatusValid)
			} else if _, ok := err.(RuleError); ok {
				b.index.SetStatusFlags(node, chainutil.StatusValidateFailed)
			} else {
				return false, err
			}

			flushIndexState()

			if err != nil {
				return false, err
			}
		}

		// In the fast add case the code to check the block connection
		// was skipped, so the utxo view needs to load the referenced
		// utxos, spend them, and add the new utxos being created by
		// this block.
		if fastAdd {
			err := views.FetchInputUtxos(block)
			if err != nil {
				return false, err
			}
			err = views.ConnectTransactions(block, &stxos, minersonhold)
			if err != nil {
				return false, err
			}
		}

		// Connect the block to the main chain.
		err := b.connectBlock(node, block, views, stxos, Vm)
		if err != nil {
			// If we got hit with a rule error, then we'll mark
			// that status of the block as invalid and flush the
			// index state to disk before returning with the error.
			if _, ok := err.(RuleError); ok {
				b.index.SetStatusFlags(
					node, chainutil.StatusValidateFailed,
				)
			}

			flushIndexState()

			return false, err
		}

		// If this is fast add, or this block node isn't yet marked as
		// valid, then we'll update its status and flush the state to
		// disk again.
		if fastAdd || !b.index.NodeStatus(node).KnownValid() {
			b.index.SetStatusFlags(node, chainutil.StatusValid)
			flushIndexState()
		}


//		Vm.Commit() it's done in connect block

		return true, nil
	}

	if fastAdd {
		log.Warnf("fastAdd set in the side chain case? %v\n",
			block.Hash())
	}

	// We're extending (or creating) a side chain, but the cumulative
	// work for this new side chain is not enough to make it the new chain.
	tip := b.BestChain.Tip()
	if node.Height <= tip.Height {
//	if node.workSum.Cmp(tip.workSum) < 0 ||
//		(node.workSum.Cmp(tip.workSum) == 0 && node.height <= tip.height) {
		// Log information about how the block is forking the chain.
		fork := b.BestChain.FindFork(node)
		if fork.Hash.IsEqual(parentHash) {
			log.Infof("FORK: Block %v forks the chain at height %d"+
				"/block %v, but does not cause a reorganize",
				node.Hash, fork.Height, fork.Hash)
		} else {
			log.Infof("EXTEND FORK: Block %v extends a side chain "+
				"which forks the chain at height %d/block %v",
				node.Hash, fork.Height, fork.Hash)
		}

		return false, nil
	}

	// We're extending (or creating) a side chain and the cumulative work
	// for this new side chain is more than the old best chain, so this side
	// chain needs to become the main chain.  In order to accomplish that,
	// find the common ancestor of both sides of the fork, disconnect the
	// blocks that form the (now) old fork from the main chain, and attach
	// the blocks that form the new chain to the main chain starting at the
	// common ancenstor (the point where the chain forked).
	detachNodes, attachNodes := b.getReorganizeNodes(node)

	if attachNodes.Len() == 0 {
		return false, nil
	}

	// Reorganize the chain.
	err := b.ReorganizeChain(detachNodes, attachNodes)
	log.Infof("connectBestChain: tx REORGANIZE: Block %v is causing a reorganize. %d detached %d attaches. New chain height = %d", node.Hash, detachNodes.Len(), attachNodes.Len(), b.BestSnapshot().Height)

	// Either getReorganizeNodes or ReorganizeChain could have made unsaved
	// changes to the block index, so flush regardless of whether there was an
	// error. The index would only be dirty if the block failed to connect, so
	// we can ignore any errors writing.
	if writeErr := b.index.FlushToDB(dbStoreBlockNode); writeErr != nil {
		log.Warnf("Error flushing block index changes to disk: %v", writeErr)
	}

	return err == nil, err
}

// isCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) isCurrent() bool {
	// Not current if the latest main (best) chain height is before the
	// latest known good checkpoint (when checkpoints are enabled).
	checkpoint := b.LatestCheckpoint()
	if checkpoint != nil && b.BestChain.Tip().Height < checkpoint.Height {
		log.Infof("Tx chain is below check point %d", checkpoint.Height)
		return false
	}

	if b.ChainParams.Name == "mainnet" {
		// Not current if the latest best block has a timestamp before 24 hours
		// ago.
		//
		// The chain appears to be current if none of the checks reported
		// otherwise.
		minus24Hours := b.timeSource.AdjustedTime().Add(-24 * time.Hour).Unix()

		r := b.BestChain.Tip().Data.TimeStamp() >= minus24Hours
/*
		if !r {
			log.Infof("Tx BestChain tip is %v", b.BestChain.Tip())
			blk,_ := b.BlockByHash(&b.BestChain.Tip().Hash)
			log.Infof("Tx BestChain tip block is %v", blk.MsgBlock().Header)
			log.Infof("Tx chain is more than 24 old %d < $d", b.BestChain.Tip().Data.TimeStamp(), minus24Hours)
		}
 */
		return r
	}
	return true
}

func (b *BlockChain) InBestChain(u * chainhash.Hash) bool {
	nu := b.index.LookupNode(u)
	return nu != nil && b.BestChain.Contains(nu)
}

func (b *BlockChain) SameChain(u, w chainhash.Hash) bool {
	// whether the tree blocks identified by hashes are in the same chain
	// u is the last of the 3
	nu := b.index.LookupNode(&u)
	if nu == nil {
		return false
	}
	nw := b.index.LookupNode(&w)
	if nw == nil {
		return false
	}

	for nu != nil && nu.Height >= nw.Height {
		if nu == nw {
			return true
		}
		nu = nu.Parent
	}
	return false
}

// IsCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function is safe for concurrent access.
func (b *BlockChain) IsCurrent() bool {
//	log.Infof("IsCurrent: ChainLock.RLock")
	b.ChainLock.RLock()
	defer b.ChainLock.RUnlock()
/*
	func () {
		b.ChainLock.RUnlock()
		log.Infof("IsCurrent: ChainLock.RUnlock")
	} ()
*/

	return b.isCurrent()	// && b.Miners.IsCurrent()
}

// BestSnapshot returns information about the current best chain block and
// related state as of the current point in time.  The returned instance must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (b *BlockChain) BestSnapshot() *BestState {
	b.StateLock.RLock()
	snapshot := b.stateSnapshot
	b.StateLock.RUnlock()
	return snapshot
}

// HeaderByHash returns the block header identified by the given hash or an
// error if it doesn't exist. Note that this will return headers from both the
// main and side chains.
func (b *BlockChain) HeaderByHash(hash *chainhash.Hash) (wire.BlockHeader, error) {
	node := b.index.LookupNode(hash)
	if node == nil {
		err := fmt.Errorf("block %s is not known", hash)
		return wire.BlockHeader{}, err
	}

	return NodetoHeader(node), nil
}

// MainChainHasBlock returns whether or not the block with the given hash is in
// the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) MainChainHasBlock(hash *chainhash.Hash) bool {
	node := b.index.LookupNode(hash)
	return node != nil && b.BestChain.Contains(node)
}

// BlockLocatorFromHash returns a block locator for the passed block hash.
// See BlockLocator for details on the algorithm used to create a block locator.
//
// In addition to the general algorithm referenced above, this function will
// return the block locator for the latest known tip of the main (best) chain if
// the passed hash is not currently known.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockLocatorFromHash(hash *chainhash.Hash) chainhash.BlockLocator {
//	log.Infof("BlockLocatorFromHash: ChainLock.RLock")
	b.ChainLock.RLock()
	node := b.index.LookupNode(hash)
	locator := b.BestChain.BlockLocator(node)
	b.ChainLock.RUnlock()
//	log.Infof("BlockLocatorFromHash: ChainLock.RUnlock")
	return locator
}

// LatestBlockLocator returns a block locator for the latest known tip of the
// main (best) chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) LatestBlockLocator() (chainhash.BlockLocator, error) {
//	log.Infof("LatestBlockLocator: ChainLock.RLock")
	b.ChainLock.RLock()
	locator := b.BestChain.BlockLocator(nil)
	b.ChainLock.RUnlock()
//	log.Infof("LatestBlockLocator: ChainLock.RUnlock")
	return locator, nil
}

// BlockHeightByHash returns the height of the block with the given hash in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHeightByHash(hash *chainhash.Hash) (int32, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.BestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, bccompress.ErrNotInMainChain(str)
	}

	return node.Height, nil
}

// BlockHashByHeight returns the hash of the block at the given height in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHashByHeight(blockHeight int32) (*chainhash.Hash, error) {
	node := b.BestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, bccompress.ErrNotInMainChain(str)

	}

	return &node.Hash, nil
}

// HeightRange returns a range of block hashes for the given start and end
// heights.  It is inclusive of the start height and exclusive of the end
// height.  The end height will be limited to the current main chain height.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeightRange(startHeight, endHeight int32) ([]chainhash.Hash, error) {
	// Ensure requested heights are sane.
	if startHeight < 0 {
		return nil, fmt.Errorf("start height of fetch range must not "+
			"be less than zero - got %d", startHeight)
	}
	if endHeight < startHeight {
		return nil, fmt.Errorf("end height of fetch range must not "+
			"be less than the start height - got start %d, end %d",
			startHeight, endHeight)
	}

	// There is nothing to do when the start and end heights are the same,
	// so return now to avoid the chain view lock.
	if startHeight == endHeight {
		return nil, nil
	}

	// Grab a lock on the chain view to prevent it from changing due to a
	// reorg while building the hashes.
	b.BestChain.Lock()
	defer b.BestChain.Unlock()

	// When the requested start height is after the most recent best chain
	// height, there is nothing to do.
	latestHeight := b.BestChain.TipUL().Height

	if startHeight > latestHeight {
		return nil, nil
	}

	// Limit the ending height to the latest height of the chain.
	if endHeight > latestHeight+1 {
		endHeight = latestHeight + 1
	}

	// Fetch as many as are available within the specified range.
	hashes := make([]chainhash.Hash, 0, endHeight-startHeight)
	for i := startHeight; i < endHeight; i++ {
		hashes = append(hashes, b.BestChain.NodeByHeightUL(i).Hash)
	}
	return hashes, nil
}

// HeightToHashRange returns a range of block hashes for the given start height
// and end hash, inclusive on both ends.  The hashes are for all blocks that are
// ancestors of endHash with height greater than or equal to startHeight.  The
// end hash must belong to a block that is known to be valid.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeightToHashRange(startHeight int32,
	endHash *chainhash.Hash, maxResults int) ([]chainhash.Hash, error) {

	endNode := b.index.LookupNode(endHash)
	if endNode == nil {
		return nil, fmt.Errorf("no known block header with hash %v", endHash)
	}
	if !b.index.NodeStatus(endNode).KnownValid() {
		return nil, fmt.Errorf("block %v is not yet validated", endHash)
	}
	endHeight := endNode.Height

	if startHeight < 0 {
		return nil, fmt.Errorf("start height (%d) is below 0", startHeight)
	}
	if startHeight > endHeight {
		return nil, fmt.Errorf("start height (%d) is past end height (%d)",
			startHeight, endHeight)
	}

	resultsLength := int(endHeight - startHeight + 1)
	if resultsLength > maxResults {
		return nil, fmt.Errorf("number of results (%d) would exceed max (%d)",
			resultsLength, maxResults)
	}

	// Walk backwards from endHeight to startHeight, collecting block hashes.
	node := endNode
	hashes := make([]chainhash.Hash, resultsLength)
	for i := resultsLength - 1; i >= 0; i-- {
		hashes[i] = node.Hash
		node = node.Parent
	}
	return hashes, nil
}

// IntervalBlockHashes returns hashes for all blocks that are ancestors of
// endHash where the block height is a positive multiple of interval.
//
// This function is safe for concurrent access.
func (b *BlockChain) IntervalBlockHashes(endHash *chainhash.Hash, interval int,
) ([]chainhash.Hash, error) {

	endNode := b.index.LookupNode(endHash)
	if endNode == nil {
		return nil, fmt.Errorf("no known block header with hash %v", endHash)
	}
	if !b.index.NodeStatus(endNode).KnownValid() {
		return nil, fmt.Errorf("block %v is not yet validated", endHash)
	}
	endHeight := endNode.Height

	resultsLength := int(endHeight) / interval
	hashes := make([]chainhash.Hash, resultsLength)

	b.BestChain.Lock()
	defer b.BestChain.Unlock()

	blockNode := endNode
	for index := int(endHeight) / interval; index > 0; index-- {
		// Use the BestChain chainView for faster lookups once lookup intersects
		// the best chain.
		blockHeight := int32(index * interval)
		if b.BestChain.ContainsUL(blockNode) {
			blockNode = b.BestChain.NodeByHeightUL(blockHeight)
		} else {
			blockNode = blockNode.Ancestor(blockHeight)
		}

		hashes[index-1] = blockNode.Hash
	}

	return hashes, nil
}

// locateInventory returns the node of the block after the first known block in
// the locator along with the number of subsequent nodes needed to either reach
// the provided stop hash or the provided max number of entries.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the node associated with the stop hash
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, nodes starting
//   after the genesis block will be returned
//
// This is primarily a helper function for the locateBlocks and locateHeaders
// functions.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateInventory(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxEntries uint32) (*chainutil.BlockNode, uint32) {
	// There are no block locators so a specific block is being requested
	// as identified by the stop hash.
	stopNode := b.index.LookupNode(hashStop)
	if len(locator) == 0 {
		if stopNode == nil {
			// No blocks with the stop hash were found so there is
			// nothing to do.
			return nil, 0
		}
		return stopNode, 1
	}

	// Find the most recent locator block hash in the main chain.  In the
	// case none of the hashes in the locator are in the main chain, fall
	// back to the genesis block.
	startNode := b.BestChain.Genesis()
	for _, hash := range locator {
		node := b.index.LookupNode(hash)
		if node != nil && b.BestChain.Contains(node) {
			startNode = node
			break
		}
	}

	// Start at the block after the most recently known block.  When there
	// is no next block it means the most recently known block is the tip of
	// the best chain, so there is nothing more to do.
	startNode = b.BestChain.Next(startNode)
	if startNode == nil {
		return nil, 0
	}

	// Calculate how many entries are needed.
	total := uint32((b.BestChain.Tip().Height - startNode.Height) + 1)
	if stopNode != nil && b.BestChain.Contains(stopNode) &&
		stopNode.Height >= startNode.Height {

		total = uint32((stopNode.Height - startNode.Height) + 1)
	}
	if total > maxEntries {
		total = maxEntries
	}

	return startNode, total
}

// locateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateBlocks(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHashes)
	if total == 0 {
		return nil
	}

	// Populate and return the found hashes.
	hashes := make([]chainhash.Hash, 0, total)
	for i := uint32(0); i < total; i++ {
		hashes = append(hashes, node.Hash)
		node = b.BestChain.Next(node)
	}
	return hashes
}

// LocateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that block, so it will either return the stop hash itself if it is known,
//   or nil if it is unknown
// - When locators are provided, but none of them are known, hashes starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateBlocks(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
//	log.Infof("LocateBlocks: ChainLock.RLock")
	b.ChainLock.RLock()
	hashes := b.locateBlocks(locator, hashStop, maxHashes)
	b.ChainLock.RUnlock()
//	log.Infof("LocateBlocks: ChainLock.RUnlock")
	return hashes
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateHeaders(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHeaders uint32) []wire.BlockHeader {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHeaders)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]wire.BlockHeader, 0, total)
	for i := uint32(0); i < total; i++ {
		headers = append(headers, NodetoHeader(node))
		node = b.BestChain.Next(node)
	}
	return headers
}

// LocateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to a max of
// wire.MaxBlockHeadersPerMsg headers.
//
// In addition, there are two special cases:
//
// - When no locators are provided, the stop hash is treated as a request for
//   that header, so it will either return the header for the stop hash itself
//   if it is known, or nil if it is unknown
// - When locators are provided, but none of them are known, headers starting
//   after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateHeaders(locator chainhash.BlockLocator, hashStop *chainhash.Hash) []wire.BlockHeader {
//	log.Infof("LocateHeaders: ChainLock.RLock")
	b.ChainLock.RLock()
	headers := b.locateHeaders(locator, hashStop, wire.MaxBlockHeadersPerMsg)
	b.ChainLock.RUnlock()
//	log.Infof("LocateHeaders: RUnlock.RLock")
	return headers
}

// IndexManager provides a generic interface that the is called when blocks are
// connected and disconnected to and from the tip of the main chain for the
// purpose of supporting optional indexes.
type IndexManager interface {
	// BlockInit is invoked during chain initialize in order to allow the index
	// manager to initialize itself and any indexes it is managing.  The
	// channel parameter specifies a channel the caller can close to signal
	// that the process should be interrupted.  It can be nil if that
	// behavior is not desired.
	Init(*BlockChain, <-chan struct{}) error

	// ConnectBlock is invoked when a new block has been connected to the
	// main chain. The set of output spent within a block is also passed in
	// so indexers can access the previous output scripts input spent if
	// required.
	ConnectBlock(database.Tx, *btcutil.Block, []viewpoint.SpentTxOut) error

	// DisconnectBlock is invoked when a block has been disconnected from
	// the main chain. The set of outputs scripts that were spent within
	// this block is also returned so indexers can clean up the prior index
	// state for this block.
	DisconnectBlock(database.Tx, *btcutil.Block, []viewpoint.SpentTxOut) error
}

// Config is a descriptor which specifies the blockchain instance configuration.
type Config struct {
	// DB defines the database which houses the blocks and will be used to
	// store all metadata created by this package such as the utxo set.
	//
	// This field is required.
	DB database.DB
	MinerDB  database.DB

	// Interrupt specifies a channel the caller can close to signal that
	// long running operations, such as catching up indexes or performing
	// database migrations, should be interrupted.
	//
	// This field can be nil if the caller does not desire the behavior.
	Interrupt <-chan struct{}

	// ChainParams identifies which chain parameters the chain is associated
	// with.
	//
	// This field is required.
	ChainParams *chaincfg.Params

	// Checkpoints hold caller-defined checkpoints that should be added to
	// the default checkpoints in ChainParams.  Checkpoints must be sorted
	// by height.
	//
	// This field can be nil if the caller does not wish to specify any
	// checkpoints.
	Checkpoints []chaincfg.Checkpoint

	// TimeSource defines the median time source to use for things such as
	// block processing and determining whether or not the chain is current.
	//
	// The caller is expected to keep a reference to the time source as well
	// and add time samples from other peers on the network so the local
	// time is adjusted to be in agreement with other peers.
	TimeSource chainutil.MedianTimeSource

	// SigCache defines a signature cache to use when when validating
	// signatures.  This is typically most useful when individual
	// transactions are already being validated prior to their inclusion in
	// a block such as what is usually done via a transaction memory pool.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
//	SigCache *txscript.SigCache

	// IndexManager defines an index manager to use when initializing the
	// chain and connecting and disconnecting blocks.
	//
	// This field can be nil if the caller does not wish to make use of an
	// index manager.
	IndexManager IndexManager

	Miner	btcutil.Address

	// HashCache defines a transaction hash mid-state cache to use when
	// validating transactions. This cache has the potential to greatly
	// speed up transaction validation as re-using the pre-calculated
	// mid-state eliminates the O(N^2) validation complexity due to the
	// SigHashAll flag.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
//	HashCache *txscript.HashCache
}

// New returns a BlockChain instance using the provided configuration details.
func New(config *Config) (*BlockChain, error) {
	// Enforce required config fields.
	if config.DB == nil {
		return nil, AssertError("blockchain.New database is nil")
	}
	if config.ChainParams == nil {
		return nil, AssertError("blockchain.New chain parameters nil")
	}
	if config.TimeSource == nil {
		return nil, AssertError("blockchain.New timesource is nil")
	}

	// Generate a checkpoint by height map from the provided checkpoints
	// and assert the provided checkpoints are sorted by height as required.
	var checkpointsByHeight map[int32]*chaincfg.Checkpoint
	var prevCheckpointHeight int32
	if len(config.Checkpoints) > 0 {
		checkpointsByHeight = make(map[int32]*chaincfg.Checkpoint)
		for i := range config.Checkpoints {
			checkpoint := &config.Checkpoints[i]
			if checkpoint.Height <= prevCheckpointHeight {
				return nil, AssertError("blockchain.New " +
					"checkpoints are not sorted by height")
			}

			checkpointsByHeight[checkpoint.Height] = checkpoint
			prevCheckpointHeight = checkpoint.Height
		}
	}

	params := config.ChainParams
	targetTimespan := int64(params.TargetTimespan / time.Second)
	targetTimePerBlock := int64(params.TargetTimePerBlock / time.Second)
	adjustmentFactor := params.RetargetAdjustmentFactor
	b := BlockChain{
		checkpoints:         config.Checkpoints,
		checkpointsByHeight: checkpointsByHeight,
		db:                  config.DB,
		ChainParams:         params,
		timeSource:          config.TimeSource,
		indexManager:        config.IndexManager,
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),
		index:               chainutil.NewBlockIndex(config.DB, params),
		BestChain:           chainutil.NewChainView(nil),
		Orphans:             chainutil.NewOrphanMgr(),
		Miner:               config.Miner,
	}

	// Initialize the chain state from the passed database.  When the db
	// does not yet contain any chain state, both it and the chain state
	// will be initialized to contain only the genesis block.
	if err := b.initChainState(); err != nil {
		return nil, err
	}

	// Perform any upgrades to the various chain-specific buckets as needed.
//	if err := b.maybeUpgradeDbBuckets(config.Interrupt); err != nil {
//		return nil, err
//	}

	// Initialize and catch up all of the currently active optional indexes
	// as needed.
	if config.IndexManager != nil {
		err := config.IndexManager.Init(&b, config.Interrupt)
		if err != nil {
			return nil, err
		}
	}

	bestNode := b.BestChain.Tip()
	log.Infof("Chain state (height %d, hash %v, totaltx %d)",
		bestNode.Height, bestNode.Hash, b.stateSnapshot.TotalTxns)

	return &b, nil
}

func (b *BlockChain) NodeByHash(h *chainhash.Hash) * chainutil.BlockNode {
	return b.index.LookupNode(h)
}