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
	"container/list"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/blockchain/bccompress"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
)

const (
	// maxOrphanBlocks is the maximum number of orphan blocks that can be
	// queued.
	maxOrphanBlocks = 2 * wire.MaxBlocksPerMsg
)

type orphanBlock wire.MinerBlock

func (b * orphanBlock) PrevBlock() * chainhash.Hash {
	return & (*wire.MinerBlock)(b).MsgBlock().PrevBlock
}

func (b * orphanBlock) MsgBlock() wire.Message {
	return (*wire.MinerBlock)(b).MsgBlock()
}

func (b * orphanBlock) Hash() * chainhash.Hash {
	return (*wire.MinerBlock)(b).Hash()
}

func (b * orphanBlock) NeedUpdate(ob chainutil.Orphaned) bool {
	return false
}

func (b * orphanBlock) Removable(ob chainutil.Orphaned) bool {
	return false
}

// newBestState returns a new best stats instance for the given parameters.
func newBestState(node *chainutil.BlockNode, medianTime time.Time) *blockchain.BestState {
	return &blockchain.BestState{
		Hash:        node.Hash,
		Height:      node.Height,
		Bits:        node.Data.GetBits(),
		MedianTime:  medianTime,
	}
}

// MinerChain provides functions for working with the miner chain.
// It includes functionality such as rejecting duplicate blocks, ensuring blocks
// follow all rules, orphan handling, checkpoint handling, and best chain
// selection with reorganization.
type MinerChain struct {
	// the block chain
	blockChain * blockchain.BlockChain

	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db                  database.DB
	chainParams         *chaincfg.Params
	timeSource          chainutil.MedianTimeSource

	// The following fields are calculated based upon the provided chain
	// parameters.  They are also set when the instance is created and
	// can't be changed afterwards, so there is no need to protect them with
	// a separate mutex.
	minRetargetTimespan int64 // target timespan / adjustment factor
	maxRetargetTimespan int64 // target timespan * adjustment factor
	blocksPerRetarget   int32 // target timespan / target time per block

	// chainLock protects concurrent access to the vast majority of the
	// fields in this struct below this point.
	chainLock * sync.RWMutex

	// The following caches are used to efficiently keep track of the
	// current deployment threshold state of each rule change deployment.
	//
	// This information is stored in the database so it can be quickly
	// reconstructed on load.
	//
	// warningCaches caches the current deployment threshold state for blocks
	// in each of the **possible** deployments.  This is used in order to
	// detect when new unrecognized rule changes are being voted on and/or
	// have been activated such as will be the case when older versions of
	// the software are being used
	//
	// deploymentCaches caches the current deployment threshold state for
	// blocks in each of the actively defined deployments.
	warningCaches    []ThresholdStateCache
	deploymentCaches []ThresholdStateCache

	// The following fields are used to determine if certain warnings have
	// already been shown.
	//
	// unknownRulesWarned refers to warnings due to unknown rules being
	// activated.
	//
	// unknownVersionsWarned refers to warnings due to unknown versions
	// being mined.
	unknownRulesWarned    bool
	unknownVersionsWarned bool

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
	Orphans      * chainutil.Orphans

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
	stateLock     *sync.RWMutex
	stateSnapshot *blockchain.BestState

	// The notifications field stores a slice of callbacks to be executed on
	// certain blockchain events.
	notificationsLock sync.RWMutex
	notifications     []blockchain.NotificationCallback
}

// HaveBlock returns whether or not the chain instance has the block represented
// by the passed hash.  This includes checking the various places a block can
// be like part of the main chain, on a side chain, or in the orphan pool.
//
// This function is safe for concurrent access.
func (b *MinerChain) HaveBlock(hash *chainhash.Hash) (bool, error) {
	exists, err := b.blockExists(hash)
	if err != nil {
		return false, err
	}
	return exists || b.Orphans.IsKnownOrphan(hash), nil
}

func (b *MinerChain) LatestMinerBlockLocator() (chainhash.BlockLocator, error) {
//	log.Infof("MinerChain.LatestMinerBlockLocator: ChainLock.RLock")
	b.chainLock.RLock()
	locator := b.BestChain.BlockLocator(nil)
	b.chainLock.RUnlock()
//	log.Infof("MinerChain.LatestMinerBlockLocator: ChainLock.RUnlock")

	return locator, nil
}

func skipList(lst * list.List, y * list.Element) {
	for y != nil {
		z := y.Next()
		lst.Remove(y)
		y = z
	}
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
func (b *MinerChain) getReorganizeNodes(node *chainutil.BlockNode) (*list.List, *list.List, *list.List, *list.List) {
	attachNodes := list.New()
	detachNodes := list.New()
	txattachNodes := list.New()
	txdetachNodes := list.New()

	// Do not reorganize to a known invalid chain. Ancestors deeper than the
	// direct parent are checked below but this is a quick check before doing
	// more unnecessary work.
	if b.index.NodeStatus(node.Parent).KnownInvalid() {
//		b.index.SetStatusFlags(node, chainutil.StatusInvalidAncestor)
		return detachNodes, attachNodes, txdetachNodes, txattachNodes
	}

	// Find the fork point (if any) adding each block to the list of nodes
	// to attach to the main tree.  Push them onto the list in reverse order
	// so they are attached in the appropriate order when iterating the list
	// later.
	forkNode := b.BestChain.FindFork(node)
	newtip := node
	for n := node; n != nil && n != forkNode; {
		invalidChain := false
		if b.index.NodeStatus(n).KnownInvalid() {
			invalidChain = true
		}
		p := n.Parent
		if !b.blockChain.SameChain(NodetoHeader(n).BestBlock, NodetoHeader(p).BestBlock) {
			// if any node is inconsistent, ignore all nodes after it by clearing attachNodes list
//			b.index.SetStatusFlags(n, statusInvalidAncestor)
			invalidChain = true
		}
		if invalidChain {
			var next *list.Element
			for e := attachNodes.Front(); e != nil; e = next {
				next = e.Next()
				attachNodes.Remove(e)
//				_ := attachNodes.Remove(e).(*blockNode)
//				b.index.SetStatusFlags(n, statusInvalidAncestor)
			}
			if p.Height <= b.BestChain.Height() {
				// if we would detach more than attach, don't do it
				return detachNodes, attachNodes, txdetachNodes, txattachNodes
			}
			newtip = p
		}
		attachNodes.PushFront(n)
		n = p
	}

	// Start from the end of the main chain and work backwards until the
	// common ancestor adding each block to the list of nodes to detach from
	// the main chain.
	// verify that the node is consistent
	for n := b.BestChain.Tip(); n != nil && n != forkNode; n = n.Parent {
		detachNodes.PushBack(n)
	}
	
	if detachNodes.Len() >= attachNodes.Len() {
		return list.New(), list.New(), txdetachNodes, txattachNodes
	}

	txdetachNodes, txattachNodes = b.blockChain.GetReorganizeSideChain(NodetoHeader(newtip).BestBlock)

	if txattachNodes.Len() == 0 {
		return detachNodes, attachNodes, txdetachNodes, txattachNodes
	}

	best := b.blockChain.BestSnapshot()
	rotate := int32(best.LastRotation) - b.blockChain.TotalRotate(txdetachNodes)

	// examine signers are in committee
	miners := make([][20]byte, wire.CommitteeSize)
	for i := int32(0); i < wire.CommitteeSize; i++ {
		if blk, _ := b.BlockByHeight(int32(rotate) - wire.CommitteeSize + i + 1); blk != nil {
			miners[i] = blk.MsgBlock().Miner
		}
	}

	x, y, p := attachNodes.Front(), txattachNodes.Front(), forkNode
	for x != nil && rotate >= p.Height {
		if p.Height > rotate - wire.CommitteeSize {
			miners[p.Height - (rotate - wire.CommitteeSize + 1)] = NodetoHeader(p).Miner
		}
		x = x.Next()
		if x != nil {
			p = x.Value.(*chainutil.BlockNode)
		}
	}
	contain := false
	for y != nil {
		if x == nil {
			for y != nil && b.blockChain.Advance(y) != 1 && b.blockChain.SignedBy(y, miners) {
				y = y.Next()
			}
			skipList(txattachNodes, y)
			y = nil
			continue
		}
		n := x.Value.(*chainutil.BlockNode)
		if !contain {
			contain = b.blockChain.SideChainContains(y, NodetoHeader(n).BestBlock)
		}
		if !contain {
			skipList(attachNodes, x)
			x = nil
			continue
		}
		if !b.blockChain.SignedBy(y, miners) {
			skipList(txattachNodes, y)
			y = nil
			continue
		}

		shift := b.blockChain.Advance(y)
		// try to rotate miners
		if shift > 0 {
			contain = false
			j := 0
			for k := shift; k < wire.CommitteeSize; k++ {
				copy(miners[j][:], miners[k][:])
				j++
			}
			for k := int32(0); k < shift; k++ {
				rotate++
				miners[j] = NodetoHeader(n).Miner
				x = x.Next()
				if x != nil {
					n = x.Value.(*chainutil.BlockNode)
				} else {
					break
				}
				j++
			}
		}
		y = y.Next()
	}

	return detachNodes, attachNodes, txdetachNodes, txattachNodes
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
func (b *MinerChain) connectBlock(node *chainutil.BlockNode, block *wire.MinerBlock) error {
	// Make sure it's extending the end of the best chain.
	prevHash := &block.MsgBlock().PrevBlock
	if !prevHash.IsEqual(&b.BestChain.Tip().Hash) {
		return AssertError("connectBlock must be called with a block " +
			"that extends the main chain")
	}

	// No warnings about unknown rules or versions until the chain is
	// current.
	if b.IsCurrent() {
		// Warn if any unknown new rules are either about to activate or
		// have already been activated.
		if err := b.warnUnknownRuleActivations(node); err != nil {
			return err
		}

		// Warn if a high enough percentage of the last blocks have
		// unexpected versions.
		if err := b.warnUnknownVersions(node); err != nil {
			return err
		}
	}

	// Write any block status changes to DB before updating best state.
	err := b.index.FlushToDB(dbStoreBlockNode)
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	state := newBestState(node, node.CalcPastMedianTime())

	// Atomically insert info into the database.
	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.Data.(*blockchainNodeData).workSum)
		if err != nil {
			return err
		}

		// Add the block hash and height to the block index which tracks
		// the main chain.
		h := block.Hash()
		err = blockchain.DbPutBlockIndex(dbTx, h, node.Height)
		if err != nil {
			return err
		}

		if len(NodetoHeader(node).BlackList) > 0 {
			meta := dbTx.Metadata()

			bkt := meta.Bucket(BlacklistKeyName)
			var height [4]byte
			common.LittleEndian.PutUint32(height[:], uint32(node.Height))
			ser := make([]byte, len(NodetoHeader(node).BlackList) * 20)
			for i, p := range NodetoHeader(node).BlackList {
				copy(ser[20 * i:], p.Address[:])
				b.blockChain.Blacklist.Add(uint32(node.Height), p.Address)
			}
			if err := bkt.Put(height[:], ser); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// This node is now the end of the best chain.
	b.BestChain.SetTip(node)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	b.chainLock.Unlock()
	b.sendNotification(blockchain.NTBlockConnected, block)
	b.chainLock.Lock()

	return nil
}

// disconnectBlock handles disconnecting the passed node/block from the end of
// the main (best) chain.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) disconnectBlock(node *chainutil.BlockNode, block *wire.MinerBlock) error {
	// Make sure the node being disconnected is the end of the best chain.
	if !node.Hash.IsEqual(&b.BestChain.Tip().Hash) {
		return AssertError("disconnectBlock must be called with the " +
			"block at the end of the main chain")
	}

	// Load the previous block since some details for it are needed below.
	prevNode := node.Parent
	var prevBlock *wire.MinerBlock
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
	state := newBestState(prevNode, prevNode.CalcPastMedianTime())

	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.Data.(*blockchainNodeData).workSum)
		if err != nil {
			return err
		}

		// Remove the block hash and height from the block index which
		// tracks the main chain.
		err = blockchain.DbRemoveBlockIndex(dbTx, block.Hash(), node.Height)
		if err != nil {
			return err
		}

		meta := dbTx.Metadata()
		bkt := meta.Bucket(BlacklistKeyName)
		var height [4]byte
		common.LittleEndian.PutUint32(height[:], uint32(node.Height))
		bkt.Delete(height[:])
		if b.blockChain.Blacklist != nil {
			b.blockChain.Blacklist.Remove(uint32(node.Height))
		}

		return nil
	})
	if err != nil {
		return err
	}

	// This node's parent is now the end of the best chain.
	b.BestChain.SetTip(node.Parent)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	b.chainLock.Unlock()
	b.sendNotification(blockchain.NTBlockDisconnected, block)
	b.chainLock.Lock()

	return nil
}

// reorganizeChain reorganizes the block chain by disconnecting the nodes in the
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
func (b *MinerChain) reorganizeChain(detachNodes, attachNodes *list.List) error {
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
	detachBlocks := make([]*wire.MinerBlock, 0, detachNodes.Len())
	attachBlocks := make([]*wire.MinerBlock, 0, attachNodes.Len())

	for e := detachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		if n.Parent == nil {
			// never remove genesis block
			continue
		}
		var block *wire.MinerBlock
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

		// Store the loaded block and spend journal entry for later.
		detachBlocks = append(detachBlocks, block)

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
	for e := attachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*chainutil.BlockNode)

		var block *wire.MinerBlock
		err := b.db.View(func(dbTx database.Tx) error {
			var err error
			block, err = dbFetchBlockByNode(dbTx, n)
			return err
		})
		if err != nil {
			return err
		}

		// Store the loaded block for later.
		attachBlocks = append(attachBlocks, block)

		// Skip checks if node has already been fully validated. Although
		// checkConnectBlock gets skipped, we still need to update the UTXO
		// view.
		if b.index.NodeStatus(n).KnownValid() {
			newBest = n
			continue
		}

		// Notice the spent txout details are not requested here and
		// thus will not be generated.  This is done because the state
		// is not being immediately written to the database, so it is
		// not needed.
		//
		// In the case the block is determined to be invalid due to a
		// rule violation, mark it as invalid and mark all of its
		// descendants as having an invalid ancestor.
		b.index.SetStatusFlags(n, chainutil.StatusValid)

		newBest = n
	}

	if detachNodes.Len() >= len(attachBlocks) {
		return fmt.Errorf("Detach more than attach.")
	}

	// Disconnect blocks from the main chain.
	for i, e := 0, detachNodes.Front(); e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		if n.Parent == nil {
			// never remove genesis block
			continue
		}

		block := detachBlocks[i]

		// Update the database and chain state.
		err := b.disconnectBlock(n, block)
		if err != nil {
			return err
		}
	}
/*
	// roll back tx chain if necessary
	rot := int32(b.blockChain.BestSnapshot().LastRotation)
	txtip := b.blockChain.BestChain.Tip()
	if rot >= detachedHeight {
		txdetachNodes := list.New()
		restore := 0
		for rot >= detachedHeight {
			txdetachNodes.PushBack(txtip)
			if txtip.Nonce() > 0 {
				rot -= wire.CommitteeSize / 2 + 1
				restore++
			} else if txtip.Nonce() <= -wire.MINER_RORATE_FREQ {
				rot--
				restore = 0
			}
			txtip = txtip.Parent()
		}
		for e := txdetachNodes.Back(); restore > 0; {
			f := e.Prev()
			txdetachNodes.Remove(e)
			e = f
			restore--
		}
		b.blockChain.ReorganizeChain(txdetachNodes, list.New())
	}
 */

	// Connect the new best chain blocks.
	for i, e := 0, attachNodes.Front(); e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*chainutil.BlockNode)
		block := attachBlocks[i]

		// Update the database and chain state.
		err := b.connectBlock(n, block)
		if err != nil {
			return err
		}
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
func (b *MinerChain) connectBestChain(node *chainutil.BlockNode, block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, error) {
	fastAdd := flags&blockchain.BFFastAdd == blockchain.BFFastAdd

	flushIndexState := func() {
		// Intentionally ignore errors writing updated node status to DB. If
		// it fails to write, it's not the end of the world. If the block is
		// valid, we flush in connectBlock and if the block is invalid, the
		// worst that can happen is we revalidate the block after a restart.
		b.index.FlushToDB(dbStoreBlockNode)
	}

	// We are extending the main (best) chain with a new block.  This is the
	// most common case.
	parentHash := &block.MsgBlock().PrevBlock
	parent := b.index.LookupNode(parentHash)
	if flags & blockchain.BFSideChain == 0 && parentHash.IsEqual(&b.BestChain.Tip().Hash) &&
		b.blockChain.SameChain(block.MsgBlock().BestBlock, NodetoHeader(parent).BestBlock) &&
		b.blockChain.InBestChain(&block.MsgBlock().BestBlock) {
		// Skip checks if node has already been fully validated.
		fastAdd = fastAdd || b.index.NodeStatus(node).KnownValid()

		// Perform several checks to verify the block can be connected
		// to the main chain without violating any rules and without
		// actually connecting the block.
		if !fastAdd {
			b.index.SetStatusFlags(node, chainutil.StatusValid)
			flushIndexState()
		}

		// Connect the block to the main chain.
		err := b.connectBlock(node, block)
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

		return true, nil
	}

	if flags & blockchain.BFNoReorg != 0 {
		return false, nil
	}

//	if fastAdd {
//		log.Warnf("fastAdd set in the side chain case? %v\n",
//			block.Hash())
//	}

	// We're extending (or creating) a side chain, but the WorkSum is not sufficient
	//// to cause a reorganization. connectBlock must be called with a blocke cumulative
	// work for this new side chain is not enough to make it the new chain.
	if b.WorkSum(node).Cmp(b.WorkSum(b.BestChain.Tip())) <= 0 {
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
	detachNodes, attachNodes, txdetachNodes, txattachNodes := b.getReorganizeNodes(node)

	if attachNodes.Len() == 0 {
		return false, nil
	}

	// Reorganize the chain.
	log.Infof("REORGANIZE: Block %v is causing a reorganize.", node.Hash)

	// a reorganization in miner chain may cause a reorg in tx chain
	// but a reorg in tx chain will not cause reorg in mainer chain

	if err := b.reorganizeChain(detachNodes, attachNodes); err != nil {
		return false, err
	}
	if err := b.blockChain.ReorganizeChain(txdetachNodes, txattachNodes); err != nil {
		b.reorganizeChain(attachNodes, detachNodes)
		return false, err
	}
/*
	if forkheight <= int32(b.blockChain.BestSnapshot().LastRotation) {
		// a reorg is required
		detach := list.New()

		p := b.blockChain.BestChain.Tip()
		rotated := b.blockChain.BestSnapshot().LastRotation
		for p !=nil {
			// do we want to add it to orphan list in case this chain might be switched back?
			// No. It is unlikely to happen. Even if it does, the problem can be addressed by peer sync.
			detach.PushBack(p)
			if p.Header().Nonce > 0 {
				blk, _ := b.blockChain.BlockByHash(p.Hash())
				b.blockChain.AddOrphanBlock(blk)
				rotated -= wire.CommitteeSize/2 + 1
			} else if p.Header().Nonce <= -wire.MINER_RORATE_FREQ {
				rotated--
			}

			if rotated < uint32(forkheight) {
				break
			}
			p = p.Parent()
		}
		b.blockChain.ReorganizeChain(detach, list.New())
	}
 */

	// Either getReorganizeNodes or reorganizeChain could have made unsaved
	// changes to the block index, so flush regardless of whether there was an
	// error. The index would only be dirty if the block failed to connect, so
	// we can ignore any errors writing.
	if writeErr := b.index.FlushToDB(dbStoreBlockNode); writeErr != nil {
		log.Warnf("Error flushing block index changes to disk: %v", writeErr)
	}

	return true, nil
}

func (b *MinerChain) WorkSum(node *chainutil.BlockNode) * big.Int {
	s := node.Data.WorkSum()
	bb := b.blockChain.NodeByHash(&node.Data.(*blockchainNodeData).block.BestBlock)
	for bb != nil && bb.Data.GetNonce() > -wire.MINER_RORATE_FREQ {
		bb = bb.Parent
	}
	if bb == nil {
		return s
	}
	mb := b.BestChain.NodeByHeight(-bb.Data.GetNonce() - wire.MINER_RORATE_FREQ)
	if mb == nil {
		return s
	}
	return s.Add(s, mb.Data.WorkSum())
}

// isCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the chain state lock held (for reads).
func (b *MinerChain) IsCurrent() bool {
	// Not current if the latest main (best) chain height is before the
	// latest known good checkpoint (when checkpoints are enabled).
	if b.chainParams.Name == "mainnet" {
		// Not current if the latest best block has a timestamp before 24 hours
		// ago.
		//
		// The chain appears to be current if none of the checks reported
		// otherwise.
		minus24Hours := b.timeSource.AdjustedTime().Add(-1 * b.chainParams.ChainCurrentStd).Unix()

		return b.BestChain.Tip().Data.TimeStamp() >= minus24Hours
	}
	return true
}

// IsCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//  - Latest block height is after the latest checkpoint (if enabled)
//  - Latest block has a timestamp newer than 24 hours ago
//
// This function is safe for concurrent access.
/*
func (b *MinerChain) IsCurrent() bool {
	b.chainLock.RLock()
	defer
	c := b.isCurrent()
	b.chainLock.RUnlock()

	if !c {
		return false
	}

	return b.blockChain.IsCurrent()
}

*/

// BestSnapshot returns information about the current best chain block and
// related state as of the current point in time.  The returned instance must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (b *MinerChain) BestSnapshot() *blockchain.BestState {
	b.stateLock.RLock()
	snapshot := b.stateSnapshot
	b.stateLock.RUnlock()
	return snapshot
}

// HeaderByHash returns the block header identified by the given hash or an
// error if it doesn't exist. Note that this will return headers from both the
// main and side chains.
func (b *MinerChain) HeaderByHash(hash *chainhash.Hash) (wire.MingingRightBlock, error) {
	node := b.index.LookupNode(hash)
	if node == nil {
		err := fmt.Errorf("block %s is not known", hash)
		return wire.MingingRightBlock{}, err
	}

	return NodetoHeader(node), nil
}

// MainChainHasBlock returns whether or not the block with the given hash is in
// the main chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) MainChainHasBlock(hash *chainhash.Hash) bool {
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
func (b *MinerChain) BlockLocatorFromHash(hash *chainhash.Hash) chainhash.BlockLocator {
//	log.Infof("MinerChain.BlockLocatorFromHash: ChainLock.RLock")
	b.chainLock.RLock()
	node := b.index.LookupNode(hash)
	locator := b.BestChain.BlockLocator(node)
	b.chainLock.RUnlock()
//	log.Infof("MinerChain.BlockLocatorFromHash: ChainLock.RUnlock")

	return locator
}

// LatestBlockLocator returns a block locator for the latest known tip of the
// main (best) chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) LatestBlockLocator() (chainhash.BlockLocator, error) {
//	log.Infof("MinerChain.LatestBlockLocator: ChainLock.RLock")
	b.chainLock.RLock()
	locator := b.BestChain.BlockLocator(nil)
	b.chainLock.RUnlock()
//	log.Infof("MinerChain.LatestBlockLocator: ChainLock.RUnlock")
	return locator, nil
}

// BlockHeightByHash returns the height of the block with the given hash in the
// main chain.
//
// This function is safe for concurrent access.
func (b *MinerChain) BlockHeightByHash(hash *chainhash.Hash) (int32, error) {
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
func (b *MinerChain) BlockHashByHeight(blockHeight int32) (*chainhash.Hash, error) {
	node := b.BestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no miner miner block at height %d exists", blockHeight)
		return nil, bccompress.ErrNotInMainChain(str)

	}

	return &node.Hash, nil
}

// HeightRange returns a range of block hashes for the given start and end
// heights.  It is inclusive of the start height and exclusive of the end
// height.  The end height will be limited to the current main chain height.
//
// This function is safe for concurrent access.
func (b *MinerChain) HeightRange(startHeight, endHeight int32) ([]chainhash.Hash, error) {
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
	latestHeight := b.BestChain.Tip().Height
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
func (b *MinerChain) HeightToHashRange(startHeight int32,
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
func (b *MinerChain) IntervalBlockHashes(endHash *chainhash.Hash, interval int) ([]chainhash.Hash, error) {
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
func (b *MinerChain) locateInventory(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxEntries uint32) (*chainutil.BlockNode, uint32) {
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
func (b *MinerChain) locateBlocks(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
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
func (b *MinerChain) LocateBlocks(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) []chainhash.Hash {
//	log.Infof("MinerChain.LocateBlocks: ChainLock.RLock")
	b.chainLock.RLock()
	hashes := b.locateBlocks(locator, hashStop, maxHashes)
	b.chainLock.RUnlock()
//	log.Infof("MinerChain.LocateBlocks: ChainLock.RUnlock")

	return hashes
}

func (b *MinerChain) Tip() * wire.MinerBlock {
	h := NodetoHeader(b.BestChain.Tip())
	return wire.NewMinerBlock(&h)
}

// This function MUST be called with the chain state lock held (for write).
func (b *MinerChain) DisconnectTip() {
	tip := b.BestChain.Tip()
	h := NodetoHeader(tip)
	blk := wire.NewMinerBlock(&h)
	b.disconnectBlock(tip, blk)
	b.Orphans.AddOrphanBlock((*orphanBlock)(blk))
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *MinerChain) locateHeaders(locator chainhash.BlockLocator, hashStop *chainhash.Hash, maxHeaders uint32) []wire.MingingRightBlock {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHeaders)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]wire.MingingRightBlock, 0, total)
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
func (b *MinerChain) LocateHeaders(locator chainhash.BlockLocator, hashStop *chainhash.Hash) []wire.MingingRightBlock {
//	log.Infof("MinerChain.LocateHeaders: ChainLock.RLock")
	b.chainLock.RLock()
	headers := b.locateHeaders(locator, hashStop, wire.MaxBlockHeadersPerMsg)
	b.chainLock.RUnlock()
//	log.Infof("MinerChain.LocateHeaders: ChainLock.RUnlock")

	return headers
}

// New returns a BlockChain instance using the provided configuration details.
func New(config *blockchain.Config) (*blockchain.BlockChain, error) {
	// Enforce required config fields.
	if config.DB == nil || config.MinerDB == nil {
		return nil, AssertError("blockchain.New database is nil")
	}

	if config.ChainParams == nil {
		return nil, AssertError("blockchain.New chain parameters nil")
	}
	if config.TimeSource == nil {
		return nil, AssertError("blockchain.New timesource is nil")
	}

	s, err := blockchain.New(config)
	if err != nil {
		return nil, err
	}

	params := config.ChainParams
	targetTimespan := int64(params.TargetTimespan / time.Second)
	targetTimePerBlock := int64(params.TargetTimePerBlock / time.Second)
	adjustmentFactor := params.RetargetAdjustmentFactor

	b := & MinerChain{
		db:                  config.MinerDB,
		chainParams:         params,
		timeSource:          config.TimeSource,
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),
		index:               chainutil.NewBlockIndex(config.MinerDB, params),
		BestChain:           chainutil.NewChainView(nil),
		Orphans:             chainutil.NewOrphanMgr(),
		stateLock:           &s.StateLock,
		chainLock:			 &s.ChainLock,
		warningCaches:       NewThresholdCaches(vbNumBits),
		deploymentCaches:    NewThresholdCaches(chaincfg.DefinedDeployments),
	}

	// Initialize the chain state from the passed database.  When the db
	// does not yet contain any chain state, both it and the chain state
	// will be initialized to contain only the genesis block.
	if err := b.initChainState(); err != nil {
		return nil, err
	}

	b.blockChain = s
	s.Miners = b

	// verify chain state is not corrupted
//	best := s.BestSnapshot()
	mbest := b.BestSnapshot()

	mtop := b.BestChain.Tip()
	ok := true

	// Start from the end of the main chain and work backwards until
	// the node whose bestblock is the tx chain's last block.
	n := mtop
	h := NodetoHeader(n).BestBlock
	detachNodes := list.New()
	for n.Parent != nil && !s.MainChainHasBlock(&h) {
		//			&& n.Header().BestBlock != best.Hash
		detachNodes.PushBack(n)
		n = n.Parent
		h = NodetoHeader(n).BestBlock
		ok = false
	}

	if !ok {
		log.Warnf("miner chain is corrupted. roll back %d blocks", detachNodes.Len())
		b.chainLock.Lock()
		// Disconnect blocks from the main chain.
		for i, e := 0, detachNodes.Front(); e != nil; i, e = i+1, e.Next() {
			n := e.Value.(*chainutil.BlockNode)
			if n.Parent == nil {
				// never remove genesis block
				continue
			}

			var block *wire.MinerBlock
			err := b.db.View(func(dbTx database.Tx) error {
				var err error
				block, err = dbFetchBlockByNode(dbTx, n)
				return err
			})
			if err != nil {
				break
			}

			// Update the database and chain state.
			err = b.disconnectBlock(n, block)
			if err != nil {
				break
			}
		}

//		b.reorganizeChain(detachNodes, list.New())
		b.chainLock.Unlock()

		detachNodes := list.New()
		for m := s.BestChain.Tip(); m.Hash != NodetoHeader(n).BestBlock; m = m.Parent {
			detachNodes.PushBack(n)
		}
		s.ChainLock.Lock()
		s.ReorganizeChain(detachNodes, list.New())
		s.ChainLock.Unlock()
	}

	txtop := s.BestChain.Tip()
	for txtop != nil && txtop.Data.GetNonce() > -wire.MINER_RORATE_FREQ {
		txtop = txtop.Parent
	}
	if txtop != nil && mbest.Height < -txtop.Data.GetNonce() - wire.MINER_RORATE_FREQ {
		ok = false
		// roll back tx chain to the point where a rotation references to a valid
		// miner block and non rotation blocks that follows

		rp, sp := txtop, txtop
		for sp != nil {
			if sp.Data.GetNonce() > -wire.MINER_RORATE_FREQ {
				sp = sp.Parent
			} else if mbest.Height < -sp.Data.GetNonce() - wire.MINER_RORATE_FREQ {
				rp = sp
				sp = sp.Parent
			} else {
				sp = nil
			}
		}

		detachNodes := list.New()
		for n := s.BestChain.Tip(); n.Parent != nil && n != rp; n = n.Parent {
			detachNodes.PushBack(n)
		}
		detachNodes.PushBack(rp)

		log.Warnf("tx chain is corrupted. roll back %d blocks", detachNodes.Len())
		s.ChainLock.Lock()
		s.ReorganizeChain(detachNodes, list.New())
		s.ChainLock.Unlock()
	}

	// Initialize rule change threshold state caches.
	if err := b.InitThresholdCaches(); err != nil {
		return nil, err
	}

	if !ok {
		log.Infof("commit to data base and exit")

		config.DB.Close()
		config.MinerDB.Close()
		return nil, fmt.Errorf("databased was corrupted. please restart")
	}
	log.Infof("Miner Chain state (height %d, hash %s)",
		mtop.Height, mtop.Hash.String())

	return s, nil
}

// checkProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
//
// The flags modify the behavior of this function as follows:
//  - BFNoPoWCheck: The check to ensure the block hash is less than the target
//    difficulty is not performed.
func checkProofOfWork(header *wire.MingingRightBlock, powLimit *big.Int, flags blockchain.BehaviorFlags) error {
	// The target difficulty must be larger than zero.
	target := CompactToBig(header.Bits)
	if target.Sign() <= 0 {
		str := fmt.Sprintf("block target difficulty of %064x is too low",
			target)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The target difficulty must be less than the maximum allowed.
	if target.Cmp(powLimit) > 0 {
		str := fmt.Sprintf("block target difficulty of %064x is "+
			"higher than max of %064x", target, powLimit)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The block hash must be less than the claimed target unless the flag
	// to avoid proof of work checks is set.
	if flags&blockchain.BFNoPoWCheck != blockchain.BFNoPoWCheck {
		// The block hash must be less than the claimed target.
		hash := header.BlockHash()
		hashNum := HashToBig(&hash)
		if hashNum.Cmp(target) > 0 {
			str := fmt.Sprintf("block hash of %064x is higher than "+
				"expected max of %064x", hashNum, target)
			return ruleError(ErrHighHash, str)
		}
	}

	return nil
}
