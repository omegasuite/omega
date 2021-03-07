// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
)

// MaxBlockLocatorsPerMsg is the maximum number of block locator hashes allowed
// per message.
const MaxBlockLocatorsPerMsg = 500

// MsgGetBlocks implements the Message interface and represents a bitcoin
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
type MsgGetBlocks struct {
	ProtocolVersion      uint32
	TxBlockLocatorHashes []*chainhash.Hash
	TxHashStop           chainhash.Hash
	MinerBlockLocatorHashes []*chainhash.Hash
	MinerHashStop           chainhash.Hash
}

// AddBlockLocatorHash adds a new block locator hash to the message.
func (msg *MsgGetBlocks) AddBlockLocatorHash(hash *chainhash.Hash) error {
	if len(msg.TxBlockLocatorHashes)+len(msg.MinerBlockLocatorHashes)+2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message [max %v]",
			MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.AddBlockLocatorHash", str)
	}

	msg.TxBlockLocatorHashes = append(msg.TxBlockLocatorHashes, hash)
	return nil
}

func (msg *MsgGetBlocks) AddMinerBlockLocatorHash(hash *chainhash.Hash) error {
	if len(msg.TxBlockLocatorHashes)+len(msg.MinerBlockLocatorHashes)+2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message [max %v]",
			MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.AddMinerBlockLocatorHash", str)
	}

	msg.MinerBlockLocatorHashes = append(msg.MinerBlockLocatorHashes, hash)
	return nil
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetBlocks) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := common.ReadElement(r, &msg.ProtocolVersion)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count + 2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.OmcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	locatorHashes := make([]chainhash.Hash, count)
	msg.TxBlockLocatorHashes = make([]*chainhash.Hash, 0, count)
	for i := uint64(0); i < count; i++ {
		hash := &locatorHashes[i]
		err := common.ReadElement(r, hash)
		if err != nil {
			return err
		}
		msg.AddBlockLocatorHash(hash)
	}

	if err = common.ReadElement(r, &msg.TxHashStop); err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count2, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count + count2 + 2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.OmcDecode", str)
	}

	// Create a contiguous slice of hashes to deserialize into in order to
	// reduce the number of allocations.
	locatorHashes = make([]chainhash.Hash, count2)
	msg.MinerBlockLocatorHashes = make([]*chainhash.Hash, 0, count2)
	for i := uint64(0); i < count2; i++ {
		hash := &locatorHashes[i]
		err := common.ReadElement(r, hash)
		if err != nil {
			return err
		}
		msg.AddMinerBlockLocatorHash(hash)
	}

	err = common.ReadElement(r, &msg.MinerHashStop)
	if err != nil {
		return err
	}
	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetBlocks) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	count := len(msg.TxBlockLocatorHashes)
	if count + 2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.OmcEncode", str)
	}

	err := common.WriteElement(w, msg.ProtocolVersion)
	if err != nil {
		return err
	}

	err = common.WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, hash := range msg.TxBlockLocatorHashes {
		err = common.WriteElement(w, hash)
		if err != nil {
			return err
		}
	}

	if err = common.WriteElement(w, &msg.TxHashStop); err != nil {
		return err
	}

	count2 := len(msg.MinerBlockLocatorHashes)
	if count + count2 + 2 > MaxBlockLocatorsPerMsg {
		str := fmt.Sprintf("too many block locator hashes for message "+
			"[count %v, max %v]", count2, MaxBlockLocatorsPerMsg)
		return messageError("MsgGetBlocks.OmcEncode", str)
	}

	err = common.WriteVarInt(w, pver, uint64(count2))
	if err != nil {
		return err
	}

	for _, hash := range msg.MinerBlockLocatorHashes {
		err = common.WriteElement(w, hash)
		if err != nil {
			return err
		}
	}

	return common.WriteElement(w, &msg.MinerHashStop)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetBlocks) Command() string {
	return CmdGetBlocks
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetBlocks) MaxPayloadLength(pver uint32) uint32 {
	// Protocol version 4 bytes + num hashes (varInt) + max block locator
	// hashes + hash stop.
	return 4 + 2 * common.MaxVarIntPayload + (MaxBlockLocatorsPerMsg * chainhash.HashSize) + 2 * chainhash.HashSize
}

// NewMsgGetBlocks returns a new bitcoin getblocks message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewMsgGetBlocks(hashStop, minerstop *chainhash.Hash) *MsgGetBlocks {
	return &MsgGetBlocks{
		ProtocolVersion:      ProtocolVersion,
		TxBlockLocatorHashes: make([]*chainhash.Hash, 0, MaxBlockLocatorsPerMsg),
		TxHashStop:           *hashStop,
		MinerBlockLocatorHashes: make([]*chainhash.Hash, 0, MaxBlockLocatorsPerMsg),
		MinerHashStop:        *minerstop,
	}
}
