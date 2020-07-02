// Copyright (c) 2018 The btcsuite developers
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

type MsgCandidate struct {
	Height    int32
	F		  [20]byte
	M	      chainhash.Hash
	Signature      []byte
}

func (msg * MsgCandidate) Sign(key *btcec.PrivateKey) {
	sig, _ := key.Sign(msg.DoubleHashB())

	ss := sig.Serialize()
	ssig := make([]byte, btcec.PubKeyBytesLenCompressed + len(ss))

	copy(ssig, key.PubKey().SerializeCompressed())
	copy(ssig[btcec.PubKeyBytesLenCompressed:], ss)

	msg.Signature = ssig
}

func (msg * MsgCandidate) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgCandidate) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	if err = readElement(r, &msg.F); err != nil {
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
func (msg * MsgCandidate) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	if err = writeElement(w, msg.F); err != nil {
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
func (msg * MsgCandidate) Command() string {
	return CmdCandidate
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgCandidate) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgCandidate) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgCandidate) GetSignature() []byte {
	return msg.Signature
}

func (msg * MsgCandidate) Sender() []byte {
	return msg.F[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgCandidate(blk int32, f [20]byte, m chainhash.Hash) *MsgCandidate {
	return &MsgCandidate{
		Height: blk,
		F:      f,
		M:      m,
	}
}

type MsgCandidateResp struct {
	Height    int32
	Reply     string	// a 4 byte string
	K         []int64	// knowledge, when rejected
	Better    int32
	From      [20]byte
	M         chainhash.Hash
	Signature []byte
}

func (msg * MsgCandidateResp) Sign(key *btcec.PrivateKey) {
	sig, _ := key.Sign(msg.DoubleHashB())

	ss := sig.Serialize()
	ssig := make([]byte, btcec.PubKeyBytesLenCompressed + len(ss))

	copy(ssig, key.PubKey().SerializeCompressed())
	copy(ssig[btcec.PubKeyBytesLenCompressed:], ss)

	msg.Signature = ssig
}

func (msg * MsgCandidateResp) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgCandidateResp) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	var rp [4]byte
	if err = readElement(r, &rp); err != nil {
		return err
	}
	msg.Reply = string(rp[:])

	if err = readElement(r, &msg.From); err != nil {
		return err
	}

	if err = readElement(r, &msg.M); err != nil {
		return err
	}

	if err = readElement(r, &msg.Better); err != nil {
		return err
	}

	l, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.K = make([]int64, l)
	for i := 0; i < int(l); i++ {
		n, err := common.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		msg.K[i] = int64(n)
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
func (msg * MsgCandidateResp) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	// Write stop hash
	var r [4]byte
	copy(r[:], []byte(msg.Reply))
	if err = writeElement(w, r); err != nil {
		return err
	}

	if err = writeElement(w, msg.From);	err != nil {
		return err
	}

	if err = writeElement(w, msg.M); err != nil {
		return err
	}

	if err = writeElement(w, msg.Better); err != nil {
		return err
	}

	if err = common.WriteVarInt(w, 0, uint64(len(msg.K))); err != nil {
		return err
	}
	for i := 0; i < len(msg.K); i++ {
		if err = common.WriteVarInt(w, 0, uint64(msg.K[i])); err != nil {
			return err
		}
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
func (msg * MsgCandidateResp) Command() string {
	return CmdCandidateReply
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgCandidateResp) MaxPayloadLength(pver uint32) uint32 {
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	return MaxMessagePayload
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg * MsgCandidateResp) DoubleHashB() []byte {
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, BaseEncoding)
	return chainhash.DoubleHashB(w.Bytes())
}

func (msg * MsgCandidateResp) GetSignature() []byte {
	return msg.Signature
}

func (msg * MsgCandidateResp) Sender() []byte {
	return msg.From[:]
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgCandidateResp() *MsgCandidateResp {
	return &MsgCandidateResp{}
}
