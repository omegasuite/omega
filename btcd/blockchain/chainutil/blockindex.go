// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chainutil

import (
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
)

// BlockStatus is a bit field representing the validation state of the block.
type BlockStatus byte

const (
	// StatusDataStored indicates that the block's payload is stored on disk.
	StatusDataStored BlockStatus = 1 << iota

	// StatusValid indicates that the block has been fully validated.
	StatusValid

	// StatusValidateFailed indicates that the block has failed validation.
	StatusValidateFailed

	// StatusInvalidAncestor indicates that one of the block's ancestors has
	// has failed validation, thus the block is also invalid.
	StatusInvalidAncestor

	// StatusNone indicates that the block has no validation state flags set.
	//
	// NOTE: This must be defined last in order to avoid influencing iota.
	StatusNone BlockStatus = 0

	// MedianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	MedianTimeBlocks = 11
)

// blockIndexBucketName is the name of the db bucket used to house to the
// block headers and contextual information.
var	blockIndexBucketName = []byte("blockheaderidx")

// HaveData returns whether the full block data is stored in the database. This
// will return false for a block node where only the header is downloaded or
// kept.
func (status BlockStatus) HaveData() bool {
	return status&StatusDataStored != 0
}

// KnownValid returns whether the block is known to be valid. This will return
// false for a valid block that has not been fully validated yet.
func (status BlockStatus) KnownValid() bool {
	return status&StatusValid != 0
}

// KnownInvalid returns whether the block is known to be invalid. This may be
// because the block itself failed validation or any of its ancestors is
// invalid. This will return false for invalid blocks that have not been proven
// invalid yet.
func (status BlockStatus) KnownInvalid() bool {
	return status&(StatusValidateFailed|StatusInvalidAncestor) != 0
}

type NodeData interface {
	TimeStamp() int64
	GetNonce() int32
	GetBits() uint32
	SetBits(uint32)
	GetVersion() uint32
	GetContractExec() int64
	WorkSum() *big.Int
}

// BlockNode represents a block within the block chain and is primarily used to
// aid in selecting the best chain to be the main chain.  The main chain is
// stored into the block database.
type BlockNode struct {
	// parent is the parent block for this node.
	Parent *BlockNode

	// hash is the double sha 256 of the block.
	Hash chainhash.Hash

	// Height is the position in the block chain.
	Height    int32
	// Status is a bitfield representing the validation state of the block. The
	// Status field, unlike the other fields, may be written to and so should
	// only be accessed using the concurrent-safe NodeStatus method on
	// BlockIndex once the node has been added to the global index.
	Status BlockStatus

	// Data is chain type specific data.
	Data NodeData
}

// Ancestor returns the ancestor block node at the provided Height by following
// the chain backwards from this node.  The returned block will be nil when a
// Height is requested that is after the Height of the passed node or is less
// than zero.
//
// This function is safe for concurrent access.
func (node *BlockNode) Ancestor(height int32) *BlockNode {
	if height < 0 || height > node.Height {
		return nil
	}

	n := node
	for ; n != nil && n.Height != height; n = n.Parent {
		// Intentionally left blank
	}

	return n
}

// RelativeAncestor returns the ancestor block node a relative 'distance' blocks
// before this node.  This is equivalent to calling Ancestor with the node's
// Height minus provided distance.
//
// This function is safe for concurrent access.
func (node *BlockNode) RelativeAncestor(distance int32) *BlockNode {
	// this func is only used by miner chain. so we don't worry about nil return
	return node.Ancestor(node.Height - distance)
}

// CalcPastMedianTime calculates the median time of the previous few blocks
// prior to, and including, the block node.
//
// This function is safe for concurrent access.
func (node *BlockNode) CalcPastMedianTime() time.Time {
	// Create a slice of the previous few block timestamps used to calculate
	// the median per the number defined by the constant MedianTimeBlocks.
	timestamps := make([]int64, MedianTimeBlocks)
	numNodes := 0
	iterNode := node
	for i := 0; i < MedianTimeBlocks && iterNode != nil; i++ {
		timestamps[i] = iterNode.Data.TimeStamp()
		numNodes++

		iterNode = iterNode.Parent
	}

	// Prune the slice to the actual number of available timestamps which
	// will be fewer than desired near the beginning of the block chain
	// and sort them.
	timestamps = timestamps[:numNodes]
	sort.Sort(TimeSorter(timestamps))

	// NOTE: The consensus rules incorrectly calculate the median for even
	// numbers of blocks.  A true median averages the middle two elements
	// for a set with an even number of elements in it.   Since the constant
	// for the previous number of blocks to be used is odd, this is only an
	// issue for a few blocks near the beginning of the chain.  I suspect
	// this is an optimization even though the result is slightly wrong for
	// a few of the first blocks since after the first few blocks, there
	// will always be an odd number of blocks in the set per the constant.
	//
	// This code follows suit to ensure the same rules are used, however, be
	// aware that should the MedianTimeBlocks constant ever be changed to an
	// even number, this code will be wrong.
	medianTimestamp := timestamps[numNodes/2]
	return time.Unix(medianTimestamp, 0)
}

// BlockIndex provides facilities for keeping track of an in-memory index of the
// block chain.  Although the name block chain suggests a single chain of
// blocks, it is actually a tree-shaped structure where any node can have
// multiple children.  However, there can only be one active branch which does
// indeed form a chain from the tip all the way back to the genesis block.

// To reduce memory footprint, at initialization, we only load latest 300K nodes.
// That should be sufficient for normal ops. Older nodes will be loaded dynamically.
// The only real performance problem is when a new client request full chain data.
// But it does not happen often and performance degradation should be acceptable.
type BlockIndex struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	db          database.DB
	chainParams *chaincfg.Params

	sync.RWMutex
	index map[chainhash.Hash]*BlockNode
	dirty map[*BlockNode]bool

//	Unloaded []chainhash.Hash		// unloaded blocks. sorted by hash

	Cutoff uint32
//	Unloaded map[chainhash.Hash]int32
//	Ulocator []chainhash.Hash

	// Tips of side chains
	Tips map[chainhash.Hash]*BlockNode
}

// newBlockIndex returns a new empty instance of a block index.  The index will
// be dynamically populated as block nodes are loaded from the database and
// manually added.
func NewBlockIndex(db database.DB, chainParams *chaincfg.Params) *BlockIndex {
	return &BlockIndex{
		db:          db,
		chainParams: chainParams,
		index:       make(map[chainhash.Hash]*BlockNode),
		dirty:       make(map[*BlockNode]bool),
		Tips:        make(map[chainhash.Hash]*BlockNode),
//		Unloaded:	 make(map[chainhash.Hash]int32),
	}
}

func (bi *BlockIndex) Highest() *BlockNode {
	h, high := int32(0), (*BlockNode)(nil)
	for _, node := range bi.index {
		if node.Height > h {
			h = node.Height
			high = node
		}
	}
	return high
}

/*
func (bi *BlockIndex) search(hash *chainhash.Hash, m, start, end uint32) bool {
	if r := bytes.Compare((*hash)[:], bi.Unloaded[m][:]); r == 0 {
		return true
	} else if start >= end {
		return false
	} else if r > 0 {
		return bi.search(hash, (m + 1 + end) / 2, m + 1, end)
	} else {
		return bi.search(hash, (m - 1 + start) / 2, start, m - 1)
	}
}

 */
// HaveBlock returns whether or not the block index Contains the provided hash.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) HaveBlock(hash *chainhash.Hash) bool {
	bi.RLock()
	_, hasBlock := bi.index[*hash]
	bi.RUnlock()

/*
	if !hasBlock && bi.Cutoff > 0 {
		hasBlock = bi.search(hash, bi.Cutoff / 2, 1, bi.Cutoff)
	}
 */

	return hasBlock
}

// LookupNode returns the block node identified by the provided hash.  It will
// return nil if there is no entry for the hash.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) LookupNode(hash *chainhash.Hash) *BlockNode {
	bi.RLock()
	node := bi.index[*hash]
	bi.RUnlock()
	return node
}

func (bi *BlockIndex) LookupNodeUL(hash *chainhash.Hash) *BlockNode {
	return bi.index[*hash]
}

// AddNode adds the provided node to the block index and marks it as dirty.
// Duplicate entries are not checked so it is up to caller to avoid adding them.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) AddNode(node *BlockNode) {
	bi.Lock()
	bi.AddNodeUL(node)
	bi.dirty[node] = true
	bi.Unlock()
}

func (bi *BlockIndex) AddNodeDirect(node *BlockNode) {
	if node.Parent != nil {
		delete(bi.Tips, node.Parent.Hash)
	}
	bi.index[node.Hash] = node
}

/*
func (bi *BlockIndex) RemoveNode(node *BlockNode) {
	bi.Lock()
	bi.dirty[node] = false
	bi.Unlock()
}
 */

// AddNodeUL adds the provided node to the block index, but does not mark it as
// dirty. This can be used while initializing the block index.
//
// This function is NOT safe for concurrent access.
func (bi *BlockIndex) AddNodeUL(node *BlockNode) {
	if node.Parent != nil {
		delete(bi.Tips, node.Parent.Hash)
	}
	bi.index[node.Hash] = node
	bi.Tips[node.Hash] = node
}
/*
func (bi *BlockIndex) AddNodeHash(h chainhash.Hash) {
	bi.index[h] = nil
}
 */

func (bi *BlockIndex) Untip(hash chainhash.Hash) {
	delete(bi.Tips, hash)
}

// NodeStatus provides concurrent-safe access to the Status field of a node.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) NodeStatus(node *BlockNode) BlockStatus {
	bi.RLock()
	status := node.Status
	bi.RUnlock()
	return status
}

// SetStatusFlags flips the provided Status flags on the block node to on,
// regardless of whether they were on or off previously. This does not unset any
// flags currently on.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) SetStatusFlags(node *BlockNode, flags BlockStatus) {
	bi.Lock()
	node.Status |= flags
	bi.dirty[node] = true
	bi.Unlock()
}

// UnsetStatusFlags flips the provided Status flags on the block node to off,
// regardless of whether they were on or off previously.
//
// This function is safe for concurrent access.
func (bi *BlockIndex) UnsetStatusFlags(node *BlockNode, flags BlockStatus) {
	bi.Lock()
	node.Status &^= flags
	bi.dirty[node] = true
	bi.Unlock()
}

// FlushToDB writes all dirty block nodes to the database. If all writes
// succeed, this clears the dirty set.
func (bi *BlockIndex) FlushToDB(dbStoreBlockNode func(dbTx database.Tx, node *BlockNode) error) error {
	bi.Lock()
	if len(bi.dirty) == 0 {
		bi.Unlock()
		return nil
	}

	err := bi.db.Update(func(dbTx database.Tx) error {
		for node, b := range bi.dirty {
			if b {
				err := dbStoreBlockNode(dbTx, node)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})

	// If write was successful, clear the dirty set.
	if err == nil {
		bi.dirty = make(map[*BlockNode]bool)
	}

	bi.Unlock()
	return err
}
