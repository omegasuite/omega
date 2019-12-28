// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"io"
)

type MsgConsensus struct {
	Height    int32
	Nonce	  int
	F	      [20]byte
	M	      chainhash.Hash
	Signature      [65]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg MsgConsensus) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, &msg.Nonce)
	if err != nil {
		return err
	}

	err = readElement(r, msg.F)
	if err != nil {
		return err
	}

	err = readElement(r, msg.M)
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
func (msg MsgConsensus) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.Nonce)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.F)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.M)
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
func (msg MsgConsensus) Command() string {
	return CmdConsensus
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg MsgConsensus) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg MsgConsensus) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 48)
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}
	for i := uint(0); i < 4; i++ {
		h[4 + i] = byte((msg.Nonce >> (i * 8) & 0xFF))
	}
	copy(h[8:], msg.F[:])
	copy(h[28:], msg.M[:])
	return chainhash.DoubleHashB(h)
}

func (msg MsgConsensus) GetSignature() []byte {
	return msg.Signature[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgConsensus() *MsgConsensus {
	return &MsgConsensus{}
}


type MsgConsensusResp struct {
	Height    int32
	Nonce 	  int
	F	      [20]byte
	Sign	  [65]byte
	Signature      [65]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg MsgConsensusResp) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Nonce)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, msg.F)
	if err != nil {
		return err
	}

	err = readElement(r, msg.Sign)
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
func (msg MsgConsensusResp) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Nonce)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.F)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Sign)
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
func (msg MsgConsensusResp) Command() string {
	return CmdConsensusReply
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg MsgConsensusResp) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg MsgConsensusResp) DoubleHashB() []byte {
	h := make([]byte, 28 + len(msg.Signature))
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}
	for i := uint(0); i < 4; i++ {
		h[4 + i] = byte((msg.Nonce >> (i * 8) & 0xFF))
	}
	copy(h[8:], msg.F[:])
	copy(h[28:], msg.Sign[:])
	return chainhash.DoubleHashB(h)
}

func (msg MsgConsensusResp) GetSignature() []byte {
	return msg.Signature[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgConsensusResp() *MsgConsensusResp {
	return &MsgConsensusResp{}
}
