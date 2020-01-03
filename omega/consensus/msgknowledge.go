// Copyright (c) 2018 The Hao Xu
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"io"
)

type MsgKnowledge struct {
	Height    int32
	K         []int64
	M         chainhash.Hash
	Finder    [20]byte
	From      [20]byte
//	Signatures      map[int][]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgKnowledge) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := common.ReadElement(r, &msg.Height)
	if err != nil {
		return err
	}

	k, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.K = make([]int64, k)
	for i := 0; i < int(k); i++ {
		p, err := common.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		msg.K[i] = int64(p)
	}

	err = readElement(r, &msg.M)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, &msg.Finder)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, &msg.From)
	if err != nil {
		return err
	}

	// Read stop hash
//	err = readElement(r, &msg.Signatures)
//	if err != nil {
//		return err
//	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgKnowledge) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = common.WriteVarInt(w, 0, uint64(len(msg.K))); err != nil {
		return err
	}
	for _, p := range msg.K {
		if err = common.WriteVarInt(w, 0, uint64(p)); err != nil {
			return err
		}
	}

	// Write stop hash
	err = writeElement(w, msg.K)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.M)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.Finder)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}

	// Write stop hash
//	err = writeElement(w, msg.Signatures)
//	if err != nil {
//		return err
//	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg * MsgKnowledge) Command() string {
	return CmdKnowledge
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgKnowledge) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgKnowledge) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 64 + 4 * len(msg.K))
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}
	for _,k := range msg.K {
		for i := uint(0); i < 4; i++ {
			h[i] = byte((k >> (i * 8) & 0xFF))
		}
	}
	copy(h[(len(msg.K) + 1) * 4:], msg.Finder[:])
	copy(h[(len(msg.K) + 1) * 4 + 20:], msg.From[:])
	copy(h[(len(msg.K) + 1) * 4 + 40:], msg.M[:])
	return chainhash.DoubleHashB(h)
}

func (msg * MsgKnowledge) Block() int32 {
	return msg.Height
}

//func (msg MsgKnowledge) GetSignature() []byte {
//	return msg.Signatures[msg.K[len(msg.K) - 1]]
//}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgKnowledge() *MsgKnowledge {
	return &MsgKnowledge{
		K:      make([]int64, 0),
//		Signatures: make(map[int][]byte),
	}
}
