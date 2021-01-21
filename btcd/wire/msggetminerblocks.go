// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
)

// MsgGetMinerBlocks implements the Message interface and represents a bitcoin
// getblocks message.  It is used to request a list of blocks starting after the
// last known hash in the slice of block locator hashes.  The list is returned
// via an inv message (MsgInv) and is limited by a specific hash to stop at or
// the maximum number of blocks per message, which is currently 500.
//
// Set the HashStop field to the hash at which to stop and use
// AddBlockLocatorHash to build up the list of block locator hashes.
//
// The algorithm for building the block locator hashes should be to add the
// hashes in reverse order until you reach the genesis block.  In order to keep
// the list of locator hashes to a reasonable number of entries, first add the
// most recent 10 block hashes, then double the step each loop iteration to
// exponentially decrease the number of hashes the further away from head and
// closer to the genesis block you get.
type MsgGetMinerBlocks struct {
	ProtocolVersion    uint32
	BlockLocatorHashes []*chainhash.Hash
	HashStop           chainhash.Hash
}

// AddBlockLocatorHash adds a new block locator hash to the message.
func (msg * MsgGetMinerBlocks) AddBlockLocatorHash(hash *chainhash.Hash) error {
	if len(msg.BlockLocatorHashes)+1 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message [max %v]",
			MaxBlockLocatorsPerMsg)
		return messageError("MsgGetMinerBlocks.AddBlockLocatorHash", str)
	}

	msg.BlockLocatorHashes = append(msg.BlockLocatorHashes, hash)
	return nil
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgGetMinerBlocks) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := common.ReadElement(r, &msg.ProtocolVersion)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.OmcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	locatorHashes := make([]chainhash.Hash, count)
	msg.BlockLocatorHashes = make([]*chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		hash := &locatorHashes[i]
		err := common.ReadElement(r, hash)
		if err != nil {
			return err
		}
		msg.AddBlockLocatorHash(hash)
	}

	return common.ReadElement(r, &msg.HashStop)
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgGetMinerBlocks) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	count := len(msg.BlockLocatorHashes)
	if count > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetMinerBlocks.OmcEncode", str)
	}

	err := common.WriteElement(w, msg.ProtocolVersion)
	if err != nil {
		return err
	}

	err = common.WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, hash := range msg.BlockLocatorHashes {
		err = common.WriteElement(w, hash)
		if err != nil {
			return err
		}
	}

	return common.WriteElement(w, &msg.HashStop)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg * MsgGetMinerBlocks) Command() string {
	return CmdGetMinerBlocks
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg * MsgGetMinerBlocks) MaxPayloadLength(pver uint32) uint32 {
//	 return 8192
	return 4 + common.MaxVarIntPayload + (MaxBlockLocatorsPerMsg * chainhash.HashSize) + chainhash.HashSize
}

// NewMsgGetBlocks returns a new bitcoin getblocks message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewMsgGetMinerBlocks(hashStop *chainhash.Hash) *MsgGetMinerBlocks {
	return &MsgGetMinerBlocks{
		ProtocolVersion:    ProtocolVersion,
		BlockLocatorHashes: make([]*chainhash.Hash, 0, MaxBlockLocatorsPerMsg),
		HashStop:           *hashStop,
	}
}
