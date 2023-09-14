// Copyright (c) 2018 The Hao Xu
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
	"io"
)

type MsgKnowledge struct {
	Height     int32
	K          []int32
	M          chainhash.Hash
	Finder     [20]byte
	From       [20]byte
	Signatures [][]byte
	Seq        int32
}

func (msg *MsgKnowledge) SetSeq(t int32) {
	if msg.Seq != 0 {
		msg.Seq = t
	}
}

func (msg *MsgKnowledge) Sequence() int32 {
	return msg.Seq
}

func (msg *MsgKnowledge) Sign(key *btcec.PrivateKey) {
	// to make interface happy. never used.
}

func (msg *MsgKnowledge) AddK(k int32, key *btcec.PrivateKey) {
	msg.K = append(msg.K, k)
	sig, _ := key.Sign(msg.DoubleHashB())

	ss := sig.Serialize()
	ssig := make([]byte, btcec.PubKeyBytesLenCompressed+len(ss))

	copy(ssig, key.PubKey().SerializeCompressed())
	copy(ssig[btcec.PubKeyBytesLenCompressed:], ss)

	msg.Signatures = append(msg.Signatures, ssig)
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgKnowledge) OmcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
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

	var ns int32
	if err = readElement(r, &ns); err != nil {
		return err
	}

	msg.Seq = 0
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
	readElement(r, &msg.Seq)

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgKnowledge) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
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

	if err = writeElement(w, msg.M); err != nil {
		return err
	}

	if err = writeElement(w, msg.Finder); err != nil {
		return err
	}

	if err = writeElement(w, msg.From); err != nil {
		return err
	}

	ns := int32(len(msg.Signatures))
	if err = writeElement(w, ns); err != nil {
		return err
	}
	for _, s := range msg.Signatures {
		ns = int32(len(s))
		if err = writeElement(w, ns); err != nil {
			return err
		}
		if err = writeElement(w, s); err != nil {
			return err
		}
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
func (msg *MsgKnowledge) Command() string {
	return CmdKnowledge
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgKnowledge) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

func (msg *MsgKnowledge) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.OmcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg *MsgKnowledge) Block() int32 {
	return msg.Height
}

func (msg *MsgKnowledge) BlockHash() chainhash.Hash {
	return msg.M
}

func (msg *MsgKnowledge) GetSignature() []byte {
	return msg.Signatures[len(msg.K)-1]
}

func (msg *MsgKnowledge) Sender() [20]byte {
	return msg.From
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgKnowledge() *MsgKnowledge {
	return &MsgKnowledge{
		K:          make([]int32, 0),
		Signatures: make([][]byte, 0),
	}
}
