// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"

	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

type MsgPull struct {
	Height int32
	M      chainhash.Hash
	Seq    int32
}

func (msg *MsgPull) SetSeq(t int32) {
	if msg.Seq != 0 {
		msg.Seq = t
	}
}

func (msg *MsgPull) Sequence() int32 {
	return msg.Seq
}

func (msg *MsgPull) Sign(key *btcec.PrivateKey) {
}

func (msg *MsgPull) Block() int32 {
	return msg.Height
}

func (msg *MsgPull) BlockHash() chainhash.Hash {
	return msg.M
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgPull) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	if err = readElement(r, &msg.M); err != nil {
		return err
	}

	msg.Seq = 0

	readElement(r, &msg.Seq)

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgPull) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = writeElement(w, msg.M); err != nil {
		return err
	}

	if enc == SignatureEncoding || enc == FullEncoding {
		if err = writeElement(w, msg.Seq); err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgPull) Command() string {
	return CmdPull
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgPull) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg *MsgPull) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.OmcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg MsgPull) GetSignature() []byte {
	return nil
}

func (msg *MsgPull) Sender() [20]byte {
	var s [20]byte
	return s
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgPull() *MsgPull {
	return &MsgPull{}
}
