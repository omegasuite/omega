// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type MsgRelease struct {
	Height    int32
	F	      [20]byte
	Nonce 	  int
	K         int
	Signature      [65]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg MsgRelease) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, msg.F)
	if err != nil {
		return err
	}
	err = readElement(r, &msg.Nonce)
	if err != nil {
		return err
	}
	err = readElement(r, &msg.K)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, msg.Signature)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg MsgRelease) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.F)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.Nonce)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.K)
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
func (msg MsgRelease) Command() string {
	return CmdRelease
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg MsgRelease) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg MsgRelease) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 97)
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}
	copy(h[4:], msg.F[:])
	for i := uint(0); i < 4; i++ {
		h[24 + i] = byte((msg.Nonce >> (i * 8) & 0xFF))
	}
	for i := uint(0); i < 4; i++ {
		h[28 + i] = byte((msg.K >> (i * 8) & 0xFF))
	}
	return chainhash.DoubleHashB(h)
}
func (msg MsgRelease) GetSignature() []byte {
	return msg.Signature[:]
}
// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgRelease(filterType FilterType, stopHash *chainhash.Hash,
	headersCount int) *MsgRelease {
	return &MsgRelease{}
}
