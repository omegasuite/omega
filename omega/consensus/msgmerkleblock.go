// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"fmt"
	"io"

	"github.com/btcsuite/btcd/wire"
)

// maxFlagsPerMerkleBlock is the maximum number of flag bytes that could
// possibly fit into a merkle block.  Since each transaction is represented by
// a single bit, this is the max number of transactions per block divided by
// 8 bits per byte.  Then an extra one to cover partials.
const maxFlagsPerMerkleBlock = 50000 / 8

type MsgMerkleBlock struct {
	Header wire.BlockHeader
	From [20]byte
	Height int32
	Fees uint64
}

func (msg *MsgMerkleBlock) Block() int32 {
	return msg.Height
}

func (msg *MsgMerkleBlock) BtcDecode(r io.Reader, pver uint32, enc wire.MessageEncoding) error {
	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.From)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Fees)
	if err != nil {
		return err
	}

	// Read num block locator hashes and limit to max.
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if count > maxTxPerBlock {
		str := fmt.Sprintf("too many transaction hashes for message "+
			"[count %v, max %v]", count, maxTxPerBlock)
		return messageError("MsgMerkleBlock.BtcDecode", str)
	}

	return err
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMerkleBlock) BtcEncode(w io.Writer, pver uint32, enc wire.MessageEncoding) error {
	// Read num transaction hashes and limit to max.
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Fees)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMerkleBlock) Command() string {
	return CmdMerkleBlock
}

const MaxBlockPayload  = 80000000

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgMerkleBlock) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgMerkleBlock returns a new bitcoin merkleblock message that conforms to
// the Message interface.  See MsgMerkleBlock for details.
func NewMsgMerkleBlock(bh *wire.BlockHeader) *MsgMerkleBlock {
	return &MsgMerkleBlock{
		Header: *bh,
		Height: 0,
		Fees: 0,
	}
}
