/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package minerchain

import (
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/btcd/wire"
)

type blockchainNodeData struct {
	// workSum is the total amount of work in the chain up to and including
	// this node.
	block *wire.MingingRightBlock
}

func (d *blockchainNodeData) GetContractExec() int64 {
	return d.block.ContractLimit
}

func (d *blockchainNodeData) TimeStamp() int64 {
	return d.block.Timestamp.Unix()
}

func (d *blockchainNodeData) GetNonce() int32 {
	return d.block.Nonce
}

func (d *blockchainNodeData) SetBits(s uint32) {
	d.block.Bits = s
}

func (d *blockchainNodeData) GetBits() uint32 {
	return d.block.Bits
}

func (d *blockchainNodeData) GetVersion() uint32 {
	return d.block.Version
}

// Header constructs a block header from the node and returns it.
//
// This function is safe for concurrent access.
func NodetoHeader(node *chainutil.BlockNode) wire.MingingRightBlock {
	return *node.Data.(*blockchainNodeData).block
}

func (b *MinerChain) NodetoHeader(node *chainutil.BlockNode) wire.MingingRightBlock {
	return *node.Data.(*blockchainNodeData).block
}

// InitBlockNode initializes a block node from the given header and parent node,
// calculating the Height and workSum from the respective fields on the parent.
// This function is NOT safe for concurrent access.  It must only be called when
// initially creating a node.
func InitBlockNode(node *chainutil.BlockNode, blockHeader *wire.MingingRightBlock, parent *chainutil.BlockNode) {
	d := blockchainNodeData{
		block: blockHeader,
	}
	*node = chainutil.BlockNode{
		Hash: blockHeader.BlockHash(),
	}

	if parent != nil {
		if d.block.Bits == 0 {
			d.block.Bits = parent.Data.GetBits()
		}
		node.Parent = parent
		node.Height = parent.Height + 1
	}
	node.Data = &d
}

// newBlockNode returns a new block node for the given block header and parent
// node, calculating the Height and workSum from the respective fields on the
// parent. This function is NOT safe for concurrent access.
func NewBlockNode(blockHeader *wire.MingingRightBlock, parent *chainutil.BlockNode) *chainutil.BlockNode {
	var node chainutil.BlockNode
	InitBlockNode(&node, blockHeader, parent)
	return &node
}
