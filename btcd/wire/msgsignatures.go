// Copyright (c) 2018 The Hao Xu
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"io"
)

type MsgSignatures struct {
	Hash       chainhash.Hash
	Signatures [][]byte
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSignatures) OmcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	// Read filter type
	err := readElement(r, &msg.Hash)
	if err != nil {
		return err
	}

	var ns int32
	if err = readElement(r, &ns); err != nil {
		return err
	}

	msg.Signatures = make([][]byte, ns)
	for i := int32(0); i < ns; i++ {
		var sn int32
		if err = readElement(r, &sn); err != nil {
			return err
		}
		msg.Signatures[i] = make([]byte, sn)
		if err = readElement(r, msg.Signatures[i]); err != nil {
			return err
		}
	}

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSignatures) OmcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	// Write filter type
	if err := writeElement(w, msg.Hash); err != nil {
		return err
	}

	ns := int32(len(msg.Signatures))
	if err := writeElement(w, ns); err != nil {
		return err
	}
	for _, s := range msg.Signatures {
		ns = int32(len(s))
		if err := writeElement(w, ns); err != nil {
			return err
		}
		if err := writeElement(w, s); err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSignatures) Command() string {
	return CmdSignatures
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgSignatures) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg *MsgSignatures) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.OmcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgSignatures() *MsgSignatures {
	return &MsgSignatures{
		Hash:       chainhash.Hash{},
		Signatures: make([][]byte, 0),
	}
}
