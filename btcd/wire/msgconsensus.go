// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"io"
)

type MsgConsensus struct {
	Height    int32
	From      [20]byte
	M      	  chainhash.Hash
	Signature      []byte
}

func (msg * MsgConsensus) Sign(key *btcec.PrivateKey) {
	// never use. just to make interface happy
}

func (msg * MsgConsensus) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgConsensus) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	if err = readElement(r, &msg.From); err != nil {
		return err
	}

	if err = readElement(r, &msg.M); err != nil {
		return err
	}

	if enc == SignatureEncoding {
		var ln uint32
		if err = readElement(r, &ln); err != nil {
			return err
		}
		msg.Signature = make([]byte, ln)
		if err = readElement(r, msg.Signature); err != nil {
			return err
		}
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgConsensus) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = writeElement(w, msg.From); err != nil {
		return err
	}

	if err = writeElement(w, msg.M); err != nil {
		return err
	}

	if enc == SignatureEncoding {
		ln := uint32(len(msg.Signature))
		if err = writeElement(w, ln); err != nil {
			return err
		}
		if err = writeElement(w, msg.Signature); err != nil {
			return err
		}
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
	msg.BtcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgConsensus) GetSignature() []byte {
	return msg.Signature[:]
}

func (msg * MsgConsensus) Sender() []byte {
	return msg.From[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgConsensus() *MsgConsensus {
	return &MsgConsensus{}
}

type MsgSignature struct {
	MsgConsensus
	For [20]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgSignature) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := msg.MsgConsensus.BtcDecode(r, pver, enc)
	if err != nil {
		return err
	}
	return readElement(r, &msg.For)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgSignature) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := msg.MsgConsensus.BtcEncode(w, pver, enc)
	if err != nil {
		return err
	}
	return writeElement(w, &msg.For)
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
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgSignature) GetSignature() []byte {
	return msg.Signature[:]
}

func (msg * MsgSignature) Sender() []byte {
	return msg.From[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgSignature() *MsgSignature {
	return &MsgSignature{}
}
