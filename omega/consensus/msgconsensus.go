// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"io"
)

type MsgConsensus struct {
	Height    int32
	From      [20]byte
	Signature      [98]byte
}

func (msg * MsgConsensus) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgConsensus) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
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
func (msg * MsgConsensus) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
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
func (msg * MsgConsensus) Command() string {
	return CmdConsensus
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgConsensus) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg * MsgConsensus) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, wire.BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgConsensus) GetSignature() []byte {
	return msg.Signature[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgConsensus() *MsgConsensus {
	return &MsgConsensus{}
}


type MsgSignature MsgConsensus

func (msg * MsgSignature) Block() int32 {
	return (*MsgConsensus)(msg).Block()
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgSignature) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	return (*MsgConsensus)(msg).BtcDecode(r, pver, wire.BaseEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgSignature) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	return (*MsgConsensus)(msg).BtcEncode(w, pver, wire.BaseEncoding)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg * MsgSignature) Command() string {
	return CmdSignature
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg MsgSignature) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg * MsgSignature) DoubleHashB() []byte {
	return (*MsgConsensus)(msg).DoubleHashB()
}

func (msg * MsgSignature) GetSignature() []byte {
	return msg.Signature[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgSignature() *MsgSignature {
	return &MsgSignature{}
}
