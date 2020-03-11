// Copyright (c) 2018 The Hao Xu
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
	"io"
)

type MsgKnowledge struct {
	Height    int32
	K         []int32
	M         chainhash.Hash
	Finder    [20]byte
	From      [20]byte
	Signatures [][]byte
}

func (msg * MsgKnowledge) AddK(k int32, key *btcec.PrivateKey) {
	sig, _ := key.Sign(msg.DoubleHashB())

	ss := sig.Serialize()
	ssig := make([]byte, btcec.PubKeyBytesLenCompressed + len(ss))

	copy(ssig, key.PubKey().SerializeCompressed())
	copy(ssig[btcec.PubKeyBytesLenCompressed:], ss)

	msg.Signatures = append(msg.Signatures, ssig)
	msg.K = append(msg.K, k)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgKnowledge) BtcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	// Read filter type
	err := common.ReadElement(r, &msg.Height)
	if err != nil {
		return err
	}

	k, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	msg.K = make([]int32, k)
	for i := 0; i < int(k); i++ {
		p, err := common.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		msg.K[i] = int32(p)
	}

	err = readElement(r, &msg.M)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Finder)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.From)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Signatures)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgKnowledge) BtcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = common.WriteVarInt(w, 0, uint64(len(msg.K))); err != nil {
		return err
	}
	for _, p := range msg.K {
		if err = common.WriteVarInt(w, 0, uint64(p)); err != nil {
			return err
		}
	}

	err = writeElement(w, msg.M)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Finder)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Signatures)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg * MsgKnowledge) Command() string {
	return CmdKnowledge
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgKnowledge) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg * MsgKnowledge) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgKnowledge) Block() int32 {
	return msg.Height
}

func (msg *MsgKnowledge) GetSignature() []byte {
	return msg.Signatures[msg.K[len(msg.K) - 1]]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgKnowledge() *MsgKnowledge {
	return &MsgKnowledge{
		K:      make([]int32, 0),
		Signatures: make([][]byte, 0),
	}
}
