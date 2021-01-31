// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chainutil

import (
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"sync"
)

// approxNodesPerWeek is an approximation of the number of new blocks there are
// in a week on average.
const approxNodesPerWeek = 6 * 24 * 7 * 200

// log2FloorMasks defines the masks to use when quickly calculating
// floor(log2(x)) in a constant log2(32) = 5 steps, where x is a uint32, using
// shifts.  They are derived from (2^(2^x) - 1) * (2^(2^x)), for x in 4..0.
var log2FloorMasks = []uint32{0xffff0000, 0xff00, 0xf0, 0xc, 0x2}

// fastLog2Floor calculates and returns floor(log2(x)) in a constant 5 steps.
func fastLog2Floor(n uint32) uint8 {
	rv := uint8(0)
	exponent := uint8(16)
	for i := 0; i < 5; i++ {
		if n&log2FloorMasks[i] != 0 {
			rv += exponent
			n >>= exponent
		}
		exponent >>= 1
	}

	return rv
}

// ChainView provides a flat view of a specific branch of the block chain from
// its tip back to the genesis block and provides various convenience functions
// for comparing chains.
//
// For example, assume a block chain with a side chain as depicted below:
//   genesis -> 1 -> 2 -> 3 -> 4  -> 5 ->  6  -> 7  -> 8
//                         \-> 4a -> 5a -> 6a
//
// The chain view for the branch ending in 6a consists of:
//   genesis -> 1 -> 2 -> 3 -> 4a -> 5a -> 6a
type ChainView struct {
	mtx   sync.Mutex
	nodes []*BlockNode
}

// NewChainView returns a new chain view for the given tip block node.  Passing
// nil as the tip will result in a chain view that is not initialized.  The tip
// can be updated at any time via the setTip function.
func NewChainView(tip *BlockNode) *ChainView {
	// The mutex is intentionally not held since this is a constructor.
	var c ChainView
	c.setTip(tip)
	return &c
}

func (c *ChainView) SetNode(h int32, node *BlockNode) {
	c.nodes[h] = node
}

// genesis returns the genesis block for the chain view.  This only differs from
// the exported Version in that it is up to the caller to ensure the lock is
// held.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) genesis() *BlockNode {
	if len(c.nodes) == 0 {
		return nil
	}

	return c.nodes[0]
}

// Genesis returns the genesis block for the chain view.
//
// This function is safe for concurrent access.
func (c *ChainView) Genesis() *BlockNode {
	c.mtx.Lock()
	genesis := c.genesis()
	c.mtx.Unlock()
	return genesis
}

// tip returns the current tip block node for the chain view.  It will return
// nil if there is no tip.  This only differs from the exported Version in that
// it is up to the caller to ensure the lock is held.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) tip() *BlockNode {
	if len(c.nodes) == 0 {
		return nil
	}

	return c.nodes[len(c.nodes)-1]
}

// Tip returns the current tip block node for the chain view.  It will return
// nil if there is no tip.
//
// This function is safe for concurrent access.
func (c *ChainView) Tip() *BlockNode {
	c.mtx.Lock()
	tip := c.tip()
	c.mtx.Unlock()
	return tip
}

func (c *ChainView) TipUL() *BlockNode {
	return c.tip()
}

// setTip sets the chain view to use the provided block node as the current tip
// and ensures the view is consistent by populating it with the nodes obtained
// by walking backwards all the way to genesis block as necessary.  Further
// calls will only perform the minimum work needed, so switching between chain
// Tips is efficient.  This only differs from the exported Version in that it is
// up to the caller to ensure the lock is held.
//
// This function MUST be called with the view mutex locked (for writes).
func (c *ChainView) setTip(node *BlockNode) {
	if node == nil {
		// Keep the backing array around for potential future use.
		c.nodes = c.nodes[:0]
		return
	}

	// Create or resize the slice that will hold the block nodes to the
	// provided tip Height.  When creating the slice, it is created with
	// some additional capacity for the underlying array as append would do
	// in order to reduce overhead when extending the chain later.  As long
	// as the underlying array already has enough capacity, simply expand or
	// contract the slice accordingly.  The additional capacity is chosen
	// such that the array should only have to be extended about once a
	// week.
	needed := node.Height + 1
	if int32(cap(c.nodes)) < needed {
		nodes := make([]*BlockNode, needed, needed+approxNodesPerWeek)
		copy(nodes, c.nodes)
		c.nodes = nodes
	} else {
		prevLen := int32(len(c.nodes))
		c.nodes = c.nodes[0:needed]
		for i := prevLen; i < needed; i++ {
			c.nodes[i] = nil
		}
	}

	h := node.Height
	for node != nil && c.nodes[h] != node {
		c.nodes[h] = node
		node = node.Parent
		h--
	}
	if h > 0 && node == nil && c.nodes[h] != nil {
		for ; h > 0 && c.nodes[h] != nil; h-- {
			c.nodes[h] = nil
		}
	}
}

// SetTip sets the chain view to use the provided block node as the current tip
// and ensures the view is consistent by populating it with the nodes obtained
// by walking backwards all the way to genesis block as necessary.  Further
// calls will only perform the minimum work needed, so switching between chain
// Tips is efficient.
//
// This function is safe for concurrent access.
func (c *ChainView) SetTip(node *BlockNode) {
	c.mtx.Lock()
	c.setTip(node)
	c.mtx.Unlock()
}

// Height returns the Height of the tip of the chain view.  It will return -1 if
// there is no tip (which only happens if the chain view has not been
// initialized).  This only differs from the exported Version in that it is up
// to the caller to ensure the lock is held.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) height() int32 {
	return int32(len(c.nodes) - 1)
}

// Height returns the Height of the tip of the chain view.  It will return -1 if
// there is no tip (which only happens if the chain view has not been
// initialized).
//
// This function is safe for concurrent access.
func (c *ChainView) Height() int32 {
	c.mtx.Lock()
	height := c.height()
	c.mtx.Unlock()
	return height
}

func (c *ChainView) HeightUL() int32 {
	return c.height()
}

// NodeByHeightUL returns the block node at the specified Height.  Nil will be
// returned if the Height does not exist.  This only differs from the exported
// Version in that it is up to the caller to ensure the lock is held.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) NodeByHeightUL(height int32) *BlockNode {
	if height < 0 || height >= int32(len(c.nodes)) {
		return nil
	}

	return c.nodes[height]
}

// NodeByHeight returns the block node at the specified Height.  Nil will be
// returned if the Height does not exist.
//
// This function is safe for concurrent access.
func (c *ChainView) NodeByHeight(height int32) *BlockNode {
	c.mtx.Lock()
	node := c.NodeByHeightUL(height)
	c.mtx.Unlock()
	return node
}

// Equals returns whether or not two chain views are the same.  Uninitialized
// views (tip set to nil) are considered equal.
//
// This function is safe for concurrent access.
func (c *ChainView) Equals(other *ChainView) bool {
	if c == other {
		return true
	}
	c.mtx.Lock()
	other.mtx.Lock()
	equals := len(c.nodes) == len(other.nodes) && c.tip() == other.tip()
	other.mtx.Unlock()
	c.mtx.Unlock()
	return equals
}

// ContainsUL returns whether or not the chain view ContainsUL the passed block
// node.  This only differs from the exported Version in that it is up to the
// caller to ensure the lock is held.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) ContainsUL(node *BlockNode) bool {
	return node != nil && c.NodeByHeightUL(node.Height) == node
}

// Contains returns whether or not the chain view ContainsUL the passed block
// node.
//
// This function is safe for concurrent access.
func (c *ChainView) Contains(node *BlockNode) bool {
	c.mtx.Lock()
	contains := c.ContainsUL(node)
	c.mtx.Unlock()
	return contains
}

// next returns the successor to the provided node for the chain view.  It will
// return nil if there is no successor or the provided node is not part of the
// view.  This only differs from the exported Version in that it is up to the
// caller to ensure the lock is held.
//
// See the comment on the exported function for more details.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) next(node *BlockNode) *BlockNode {
	if node == nil || !c.ContainsUL(node) {
		return nil
	}

	return c.NodeByHeightUL(node.Height + 1)
}

// Next returns the successor to the provided node for the chain view.  It will
// return nil if there is no successfor or the provided node is not part of the
// view.
//
// For example, assume a block chain with a side chain as depicted below:
//   genesis -> 1 -> 2 -> 3 -> 4  -> 5 ->  6  -> 7  -> 8
//                         \-> 4a -> 5a -> 6a
//
// Further, assume the view is for the longer chain depicted above.  That is to
// say it consists of:
//   genesis -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8
//
// Invoking this function with block node 5 would return block node 6 while
// invoking it with block node 5a would return nil since that node is not part
// of the view.
//
// This function is safe for concurrent access.
func (c *ChainView) Next(node *BlockNode) *BlockNode {
	c.mtx.Lock()
	next := c.next(node)
	c.mtx.Unlock()
	return next
}

// findFork returns the final common block between the provided node and the
// the chain view.  It will return nil if there is no common block.  This only
// differs from the exported Version in that it is up to the caller to ensure
// the lock is held.
//
// See the exported FindFork comments for more details.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) findFork(node *BlockNode) *BlockNode {
	// No fork point for node that doesn't exist.
	if node == nil {
		return nil
	}

	// When the Height of the passed node is higher than the Height of the
	// tip of the current chain view, walk backwards through the nodes of
	// the other chain until the heights match (or there or no more nodes in
	// which case there is no common node between the two).
	//
	// NOTE: This isn't strictly necessary as the following section will
	// find the node as well, however, it is more efficient to avoid the
	// ContainsUL check since it is already known that the common node can't
	// possibly be past the end of the current chain view.  It also allows
	// this code to take advantage of any potential future optimizations to
	// the Ancestor function such as using an O(log n) skip list.
	chainHeight := c.height()
	if node.Height > chainHeight {
		node = node.Ancestor(chainHeight)
	}

	// Walk the other chain backwards as long as the current one does not
	// contain the node or there are no more nodes in which case there is no
	// common node between the two.
	for node != nil && !c.ContainsUL(node) {
		node = node.Parent
	}

	return node
}

// FindFork returns the final common block between the provided node and the
// the chain view.  It will return nil if there is no common block.
//
// For example, assume a block chain with a side chain as depicted below:
//   genesis -> 1 -> 2 -> ... -> 5 -> 6  -> 7  -> 8
//                                \-> 6a -> 7a
//
// Further, assume the view is for the longer chain depicted above.  That is to
// say it consists of:
//   genesis -> 1 -> 2 -> ... -> 5 -> 6 -> 7 -> 8.
//
// Invoking this function with block node 7a would return block node 5 while
// invoking it with block node 7 would return itself since it is already part of
// the branch formed by the view.
//
// This function is safe for concurrent access.
func (c *ChainView) FindFork(node *BlockNode) *BlockNode {
	c.mtx.Lock()
	fork := c.findFork(node)
	c.mtx.Unlock()
	return fork
}

func (c *ChainView) Unlock() {
	c.mtx.Unlock()
}

func (c *ChainView) Lock() {
	c.mtx.Lock()
}

// blockLocator returns a block locator for the passed block node.  The passed
// node can be nil in which case the block locator for the current tip
// associated with the view will be returned.  This only differs from the
// exported Version in that it is up to the caller to ensure the lock is held.
//
// See the exported BlockLocator function comments for more details.
//
// This function MUST be called with the view mutex locked (for reads).
func (c *ChainView) blockLocator(node *BlockNode, index *BlockIndex) chainhash.BlockLocator {
	// Use the current tip if requested.
	if node == nil {
		node = c.tip()
	}
	if node == nil {
		return nil
	}

	// Calculate the max number of entries that will ultimately be in the
	// block locator.  See the description of the algorithm for how these
	// numbers are derived.
	var maxEntries uint8
	maxEntries = 2 + fastLog2Floor(uint32(node.Height))
/*
	if node.Height <= 12 {
		maxEntries = uint8(node.Height) + 1
	} else {
		// Requested hash itself + previous 10 entries + genesis block.
		// Then floor(log2(Height-10)) entries for the skip portion.
		adjustedHeight := uint32(node.Height) - 10
		maxEntries = 12 + fastLog2Floor(adjustedHeight)
	}
 */
	locator := make(chainhash.BlockLocator, 0, maxEntries)

	var nodehash * chainhash.Hash

	step := int32(1)
	height := node.Height
	nodehash = &node.Hash

	for height > 0 {
		locator = append(locator, nodehash)
		nodehash = nil

		height -= step
		if height <= 0 {
			break
		}

		// When the node is in the current chain view, all of its
		// ancestors must be too, so use a much faster O(1) lookup in
		// that case.  Otherwise, fall back to walking backwards through
		// the nodes of the other chain to the correct ancestor.
		if c.ContainsUL(node) {
			node = c.nodes[height]
			if node != nil {
				nodehash = &node.Hash
			}
		} else if height <= int32(index.Cutoff) {
//			for _, h := range index.Ulocator {
//				var hash chainhash.Hash
//				hash = h
//				locator = append(locator, &hash)
//			}
			break
		} else {
			for ; node != nil && node.Height > height; node = node.Parent {}
			if node != nil {
				nodehash = &node.Hash
			}
		}

		if nodehash == nil {
			break
		}
		step <<= 1

		// Once 11 entries have been included, start doubling the
		// distance between included hashes.
	}

	locator = append(locator, &c.nodes[0].Hash)

	return locator
}

func (c *ChainView) LastNil(begin, end int32) int32 {
	// find the first non-nil (ex. genesis) node following nil nodes
	for begin < end {
		h := (begin + end) >> 1
		if c.nodes[h] == nil {
			begin = h + 1
		} else {
			end = h
		}
	}
	return end
}

// BlockLocator returns a block locator for the passed block node.  The passed
// node can be nil in which case the block locator for the current tip
// associated with the view will be returned.
//
// See the BlockLocator type for details on the algorithm used to create a block
// locator.
//
// This function is safe for concurrent access.
func (c *ChainView) BlockLocator(node *BlockNode, index * BlockIndex) chainhash.BlockLocator {
	c.mtx.Lock()
	locator := c.blockLocator(node, index)
	c.mtx.Unlock()
	return locator
}
