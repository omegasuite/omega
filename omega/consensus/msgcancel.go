// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type FilterType uint8

type MsgCancel struct {
	Height    int32
	K         []int
	Finder    [20]byte
	From      [20]byte
	Signature  [65]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg MsgCancel) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	var n int
	err = readElement(r, &n)
	if err != nil {
		return err
	}
	msg.K = make([]int, n)
	err = readElement(r, msg.K)
	if err != nil {
		return err
	}

	err = readElement(r, msg.Finder)
	if err != nil {
		return err
	}

	err = readElement(r, msg.From)
	if err != nil {
		return err
	}
	err = readElement(r, msg.Signature)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg MsgCancel) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	err = writeElement(w, len(msg.K))
	if err != nil {
		return err
	}

	err = writeElement(w, msg.K)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.Finder)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Signature)
	if err != nil {
		return err
	}


	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg MsgCancel) Command() string {
	return CmdCancel
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg MsgCancel) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg MsgCancel) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 44 + len(msg.K) * 4)
	i := uint(0)
	for ; i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}
	for _,k := range msg.K {
		for j := uint(0); j < 4; j++ {
			h[i] = byte((k >> (j * 8) & 0xFF))
			i++
		}
	}
	copy(h[i:], msg.Finder[:])
	copy(h[i + 20:], msg.From[:])
	return chainhash.DoubleHashB(h)
}
func (msg MsgCancel) GetSignature() []byte {
	return msg.Signature[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgCancel(filterType FilterType, stopHash *chainhash.Hash,
	headersCount int) *MsgCancel {
	return &MsgCancel{}
}
