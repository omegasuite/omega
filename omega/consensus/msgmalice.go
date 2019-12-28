// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type MsgMalice struct {
	Height    int32
	K         []int
	Finder    string
	From      string
	Signatures      [][]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMalice) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMalice) BtcEncode(w io.Writer, pver uint32, _ wire.MessageEncoding) error {
	// Write filter type
	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgMalice) Command() string {
	return "CmdMalice"
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgMalice) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgMalice(filterType FilterType, stopHash *chainhash.Hash,
	headersCount int) *MsgMalice {
	return &MsgMalice{}
}
