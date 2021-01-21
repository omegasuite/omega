// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"

	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

type MsgRelease struct {
	Height    int32
	From      [20]byte
	Better 	  int32
	M  	      chainhash.Hash
	Signature      []byte
}

func (msg * MsgRelease) Sign(key *btcec.PrivateKey) {
	sig, _ := key.Sign(msg.DoubleHashB())

	ss := sig.Serialize()
	ssig := make([]byte, btcec.PubKeyBytesLenCompressed + len(ss))

	copy(ssig, key.PubKey().SerializeCompressed())
	copy(ssig[btcec.PubKeyBytesLenCompressed:], ss)

	msg.Signature = ssig
}

func (msg * MsgRelease) Block() int32 {
	return msg.Height
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgRelease) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	// Read stop hash
	if err = readElement(r, &msg.From); err != nil {
		return err
	}
	if err = readElement(r, &msg.Better); err != nil {
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

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgRelease) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = writeElement(w, msg.From); err != nil {
		return err
	}
	if err = writeElement(w, msg.Better); err != nil {
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
func (msg *MsgRelease) Command() string {
	return CmdRelease
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgRelease) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg *MsgRelease) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.OmcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg MsgRelease) GetSignature() []byte {
	return msg.Signature[:]
}

func (msg * MsgRelease) Sender() []byte {
	return msg.From[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgRelease() *MsgRelease {
	return &MsgRelease{}
}
