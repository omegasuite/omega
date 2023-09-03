// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"io"
)

type MsgConsensus struct {
	Height    int32
	From      [20]byte
	M         chainhash.Hash
	Signature []byte
	Seq       int32
}

func (msg *MsgConsensus) SetSeq(t int32) {
	if msg.Seq != 0 {
		msg.Seq = t
	}
}

func (msg *MsgConsensus) Sequence() int32 {
	return msg.Seq
}

func (msg *MsgConsensus) Sign(key *btcec.PrivateKey) {
	// never use. just to make interface happy
}

func (msg *MsgConsensus) Block() int32 {
	return msg.Height
}

func (msg *MsgConsensus) BlockHash() chainhash.Hash {
	return msg.M
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgConsensus) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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

	msg.Seq = 0

	var ln uint32
	if err = readElement(r, &ln); err != nil || ln == 0 {
		msg.Signature = make([]byte, 0)
		return nil
	}

	msg.Signature = make([]byte, ln)
	if err = readElement(r, msg.Signature); err != nil {
		return err
	}

	readElement(r, &msg.Seq)

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgConsensus) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
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

	if enc == SignatureEncoding || enc == FullEncoding {
		ln := uint32(len(msg.Signature))
		if err = writeElement(w, ln); err != nil {
			return err
		}
		if err = writeElement(w, msg.Signature); err != nil {
			return err
		}
		if err = writeElement(w, msg.Seq); err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgConsensus) Command() string {
	return CmdConsensus
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgConsensus) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg *MsgConsensus) DoubleHashB() []byte {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	var w bytes.Buffer
	msg.OmcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg *MsgConsensus) GetSignature() []byte {
	return msg.Signature[:]
}

func (msg *MsgConsensus) Sender() []byte {
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

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSignature) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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

	if err = readElement(r, &msg.For); err != nil {
		return err
	}

	msg.Seq = 0

	var ln uint32
	if err = readElement(r, &ln); err != nil || ln == 0 {
		msg.Signature = make([]byte, 0)
		return nil
	}

	msg.Signature = make([]byte, ln)
	if err = readElement(r, msg.Signature); err != nil {
		return err
	}

	readElement(r, &msg.Seq)

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSignature) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
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
	if err = writeElement(w, msg.For); err != nil {
		return err
	}

	if enc == SignatureEncoding || enc == FullEncoding {
		ln := uint32(len(msg.Signature))
		if err = writeElement(w, ln); err != nil {
			return err
		}
		if err = writeElement(w, msg.Signature); err != nil {
			return err
		}
		if err = writeElement(w, msg.Seq); err != nil {
			return err
		}
	}
	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSignature) Command() string {
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
	msg.OmcEncode(&w, 0, BaseEncoding)
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
