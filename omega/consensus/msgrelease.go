// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"bytes"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type MsgRelease struct {
	Height    int32
	From      [20]byte
	Better 	  int32
	K         []int64
//	Signature      [65]byte
}

func (msg * MsgRelease) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgRelease) BtcDecode(r io.Reader, pver uint32, _ wire.MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, msg.From)
	if err != nil {
		return err
	}
	err = readElement(r, &msg.Better)
	if err != nil {
		return err
	}
	err = readElement(r, &msg.K)
	if err != nil {
		return err
	}

	// Read stop hash
//	err = readElement(r, msg.Signature)
//	if err != nil {
//		return err
//	}

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

	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.Better)
	if err != nil {
		return err
	}
	err = writeElement(w, msg.K)
	if err != nil {
		return err
	}
//	err = writeElement(w, msg.Signature)
//	if err != nil {
//		return err
//	}

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
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, wire.BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}
//func (msg MsgRelease) GetSignature() []byte {
//	return msg.Signature[:]
//}
// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgRelease() *MsgRelease {
	return &MsgRelease{}
}
