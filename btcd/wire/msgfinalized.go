// Copyright (c) 2013-2015 The omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
	"io"
)

// MsgFinalized  implements the Message interface and defines a Finalized message.

type MsgFinalized struct {
	ChainId uint32 // id of the chain
	Block   chainhash.Hash
}

type MsgReFinal struct {
	ChainId uint32 // id of the chain
	Block   chainhash.Hash
	ETA     int32 // expected final time
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgFinalized) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.ReadElement(r, &msg.ChainId)
	if err != nil {
		return err
	}

	return common.ReadElement(r, &msg.Block)
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgFinalized) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.WriteElement(w, msg.ChainId)
	if err != nil {
		return err
	}

	return common.WriteElement(w, msg.Block)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgFinalized) Command() string {
	return CmdFinalized
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgFinalized) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgFinalized(chain uint32, tx chainhash.Hash) *MsgFinalized {
	return &MsgFinalized{
		ChainId: chain,
		Block:   tx,
	}
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgReFinal) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.ReadElement(r, &msg.ChainId)
	if err != nil {
		return err
	}

	err = common.ReadElement(r, &msg.Block)
	if err != nil {
		return err
	}

	return common.ReadElement(r, &msg.ETA)
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgReFinal) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.WriteElement(w, msg.ChainId)
	if err != nil {
		return err
	}

	err = common.WriteElement(w, msg.Block)
	if err != nil {
		return err
	}

	return common.WriteElement(w, msg.ETA)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgReFinal) Command() string {
	return CmdFinal
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgReFinal) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgFinal(chain uint32, tx chainhash.Hash, eta int32) *MsgReFinal {
	return &MsgReFinal{
		ChainId: chain,
		Block:   tx,
		ETA:     eta,
	}
}
