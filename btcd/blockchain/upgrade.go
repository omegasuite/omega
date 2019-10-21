// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)

const (
	// blockHdrOffset defines the offsets into a v1 block index row for the
	// block header.
	//
	// The serialized block index row format is:
	//   <blocklocation><blockheader>
	blockHdrOffset = 12
)

// errInterruptRequested indicates that an operation was cancelled due
// to a user-requested interrupt.
var errInterruptRequested = errors.New("interrupt requested")

// interruptRequested returns true when the provided channel has been closed.
// This simplifies early shutdown slightly since the caller can just use an if
// statement instead of a select.
func interruptRequested(interrupted <-chan struct{}) bool {
	select {
	case <-interrupted:
		return true
	default:
	}

	return false
}

// blockChainContext represents a particular block's placement in the block
// chain. This is used by the block index migration to track block metadata that
// will be written to disk.
type blockChainContext struct {
	parent    *chainhash.Hash
	children  []*chainhash.Hash
	height    int32
	mainChain bool
}

// readBlockTree reads the old block index bucket and constructs a mapping of
// each block to its parent block and all child blocks. This mapping represents
// the full tree of blocks. This function does not populate the height or
// mainChain fields of the returned blockChainContext values.
func readBlockTree(v1BlockIdxBucket database.Bucket) (map[chainhash.Hash]*blockChainContext, error) {
	blocksMap := make(map[chainhash.Hash]*blockChainContext)
	err := v1BlockIdxBucket.ForEach(func(_, blockRow []byte) error {
		var header wire.BlockHeader
		endOffset := blockHdrOffset + blockHdrSize
		headerBytes := blockRow[blockHdrOffset:endOffset:endOffset]
		err := header.Deserialize(bytes.NewReader(headerBytes))
		if err != nil {
			return err
		}

		blockHash := header.BlockHash()
		prevHash := header.PrevBlock

		if blocksMap[blockHash] == nil {
			blocksMap[blockHash] = &blockChainContext{height: -1}
		}
		if blocksMap[prevHash] == nil {
			blocksMap[prevHash] = &blockChainContext{height: -1}
		}

		blocksMap[blockHash].parent = &prevHash
		blocksMap[prevHash].children =
			append(blocksMap[prevHash].children, &blockHash)
		return nil
	})
	return blocksMap, err
}

// determineBlockHeights takes a map of block hashes to a slice of child hashes
// and uses it to compute the height for each block. The function assigns a
// height of 0 to the genesis hash and explores the tree of blocks
// breadth-first, assigning a height to every block with a path back to the
// genesis block. This function modifies the height field on the blocksMap
// entries.
func determineBlockHeights(blocksMap map[chainhash.Hash]*blockChainContext) error {
	queue := list.New()

	// The genesis block is included in blocksMap as a child of the zero hash
	// because that is the value of the PrevBlock field in the genesis header.
	preGenesisContext, exists := blocksMap[zeroHash]
	if !exists || len(preGenesisContext.children) == 0 {
		return fmt.Errorf("Unable to find genesis block")
	}

	for _, genesisHash := range preGenesisContext.children {
		blocksMap[*genesisHash].height = 0
		queue.PushBack(genesisHash)
	}

	for e := queue.Front(); e != nil; e = queue.Front() {
		queue.Remove(e)
		hash := e.Value.(*chainhash.Hash)
		height := blocksMap[*hash].height

		// For each block with this one as a parent, assign it a height and
		// push to queue for future processing.
		for _, childHash := range blocksMap[*hash].children {
			blocksMap[*childHash].height = height + 1
			queue.PushBack(childHash)
		}
	}

	return nil
}

// determineMainChainBlocks traverses the block graph down from the tip to
// determine which block hashes that are part of the main chain. This function
// modifies the mainChain field on the blocksMap entries.
func determineMainChainBlocks(blocksMap map[chainhash.Hash]*blockChainContext, tip *chainhash.Hash) {
	for nextHash := tip; *nextHash != zeroHash; nextHash = blocksMap[*nextHash].parent {
		blocksMap[*nextHash].mainChain = true
	}
}
