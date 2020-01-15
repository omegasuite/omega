// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
	"io"
)

type MsgCandidate struct {
	Height    int32
	F		  [20]byte
	M	      chainhash.Hash
	Signature      []byte
}

func (msg * MsgCandidate) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgCandidate) BtcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.F)
	if err != nil {
		return err
	}

	// Read stop hash
	err = readElement(r, &msg.M)
	if err != nil {
		return err
	}
	// Read stop hash
	err = readElement(r, &msg.Signature)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgCandidate) BtcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.F)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.M)
	if err != nil {
		return err
	}

	// Write stop hash
	err = writeElement(w, msg.Signature)
	if err != nil {
		return err
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
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 48)
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}

	copy(h[8:], msg.F[:])
	copy(h[28:], msg.M[:])
	return chainhash.DoubleHashB(h)
}

func (msg * MsgCandidate) GetSignature() []byte {
	return msg.Signature
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

func (msg * MsgCandidateResp) Block() int32 {
	return msg.Height
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg * MsgCandidateResp) BtcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	err := readElement(r, &msg.Height)
	if err != nil {
		return err
	}

	var rp [4]byte
	err = readElement(r, &rp)
	if err != nil {
		return err
	}
	msg.Reply = string(rp[:])

	err = readElement(r, &msg.From)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.M)
	if err != nil {
		return err
	}

	err = readElement(r, &msg.Better)
	if err != nil {
		return err
	}

	l, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.K = make([]int64, l)
	for i := 0; i < int(l); i++ {
		n, err := common.ReadVarInt(r, 0)
		msg.K[i] = int64(n)
		if err != nil {
			return err
		}
	}

	err = readElement(r, &msg.Signature)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg * MsgCandidateResp) BtcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	// Write filter type
	err := writeElement(w, msg.Height)
	if err != nil {
		return err
	}

	// Write stop hash
	var r [4]byte
	copy(r[:], []byte(msg.Reply))
	err = writeElement(w, r)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.From)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.M)
	if err != nil {
		return err
	}

	err = writeElement(w, msg.Better)
	if err != nil {
		return err
	}

	err = common.WriteVarInt(w, 0, uint64(len(msg.K)))
	if err != nil {
		return err
	}
	for i := 0; i < len(msg.K); i++ {
		err = common.WriteVarInt(w, 0, uint64(msg.K[i]))
		if err != nil {
			return err
		}
	}

	err = writeElement(w, msg.Signature)
	if err != nil {
		return err
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
	// Message size depends on the blockchain height, so return general limit
	// for all messages.
	h := make([]byte, 12)
	for i := uint(0); i < 4; i++ {
		h[i] = byte((msg.Height >> (i * 8) & 0xFF))
	}

	copy(h[8:], msg.Reply[:])
	return chainhash.DoubleHashB(h)
}

func (msg * MsgCandidateResp) GetSignature() []byte {
	return msg.Signature
}

// NewMsgCFCheckpt returns a new bitcoin cfheaders message that conforms to
// the Message interface. See MsgCFCheckpt for details.
func NewMsgCandidateResp() *MsgCandidateResp {
	return &MsgCandidateResp{}
}
