// Copyright (c) 2013-2015 The omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"github.com/omegasuite/famofchains/omega/chainmap"
	"io"
)

type MsgGetChainMap struct {
	Sequence uint32 // id of the chain
}

type MsgChainMap struct {
	Count  uint32 // id of the chain
	Chains []chainmap.ChainDescriptor
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetChainMap) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return common.ReadElement(r, &msg.Sequence)
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetChainMap) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return common.WriteElement(w, msg.Sequence)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetChainMap) Command() string {
	return CmdGetChainMap
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetChainMap) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgGetChainMap(seq uint32) *MsgGetChainMap {
	return &MsgGetChainMap{
		Sequence: seq,
	}
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgChainMap) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.ReadElement(r, &msg.Count)
	if err != nil {
		return err
	}

	msg.Chains = make([]chainmap.ChainDescriptor, msg.Count)

	for i := uint32(0); i < msg.Count; i++ {
		c := chainmap.ChainDescriptor{}
		err := c.OmcDecode(r)
		if err != nil {
			return err
		}
		msg.Chains[i] = c
	}

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgChainMap) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.WriteElement(w, msg.Count)
	if err != nil {
		return err
	}

	for i := uint32(0); i < msg.Count; i++ {
		err := msg.Chains[i].OmcEncode(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgChainMap) Command() string {
	return CmdChainMap
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgChainMap) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgChainMap() *MsgChainMap {
	return &MsgChainMap{
		Count:  0,
		Chains: make([]chainmap.ChainDescriptor, 0),
	}
}
