// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
	"io"
)

type Invitation struct {
	Height int32	// my miner chain height
	Pubkey [33]byte	// my pub key goes with the signature
	IP []byte		// my IP address for connection
}

func (m * Invitation) Serialize(w io.Writer) error {
	err := common.WriteVarInt(w, 0, uint64(m.Height))
	if err != nil {
		return err
	}

	err = common.WriteElement(w, m.Pubkey)
	if err != nil {
		return err
	}

	return common.WriteVarBytes(w, 0, m.IP[:])
}

func (m * Invitation) Deserialize(r io.Reader) error {
	h, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	m.Height = int32(h)

	err = common.ReadElement(r, &m.Pubkey)
	if err != nil {
		return err
	}

	t, err := common.ReadVarBytes(r, 0, 1024, "IP")
	if err != nil {
		return err
	}
	m.IP = make([]byte, len(t))
	copy(m.IP[:], t)

	return nil
}

type MsgInvitation struct {
	Expire uint32 // expiration height. anything more than Height + committee size
	To [20]byte	// receipient identified by PKH address
	Encrypt bool	// whether Msg is encrypted Invitation
	Sig []byte	// my signature (w/o pubkey) on invitation to prove I am the one
	Msg []byte	// RSA encrypted invitation message using the receipient's RSA pubkey
}

func (msg *MsgInvitation) Hash() chainhash.Hash {
	var w bytes.Buffer
	msg.BtcEncode(&w, 0, 0)

	return chainhash.DoubleHashH(w.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgInvitation) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	x, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.Expire = uint32(x)

	err = common.ReadElement(r, msg.To)
	if err != nil {
		return err
	}

	var b byte
	err = common.ReadElement(r, &b)
	if err != nil {
		return err
	}
	if b == 0 {
		msg.Encrypt = false
	} else {
		msg.Encrypt = true
	}

	t, err := common.ReadVarBytes(r, 0, 1024, "Sig")
	if err != nil {
		return err
	}
	msg.Sig = make([]byte, len(t))
	copy(msg.Sig[:], t)

	t, err = common.ReadVarBytes(r, 0, 1024, "Msg")
	if err != nil {
		return err
	}
	msg.Msg = make([]byte, len(t))
	copy(msg.Msg[:], t)

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgInvitation) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := common.WriteVarInt(w, pver, uint64(msg.Expire))
	if err != nil {
		return err
	}

	err = common.WriteElement(w, msg.To[:])
	if err != nil {
		return err
	}

	if msg.Encrypt {
		err = common.WriteElement(w, byte(1))
	} else {
		err = common.WriteElement(w, byte(0))
	}
	if err != nil {
		return err
	}

	err = common.WriteVarBytes(w, 0, msg.Sig[:])
	if err != nil {
		return err
	}

	return common.WriteVarBytes(w, 0, msg.Msg[:])
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgInvitation) Command() string {
	return CmdInvitation
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgInvitation) MaxPayloadLength(pver uint32) uint32 {
	// Num addresses (varInt) + max allowed addresses.
	return 2048
}

// NewMsgAddr returns a new bitcoin addr message that conforms to the
// Message interface.  See MsgAddr for details.
func NewMsgInvitation() *MsgInvitation {
	return &MsgInvitation{}
}

type MsgAckInvitation struct {
	// acknowledgement to invitation, send back after connected on invitation
	Invitation	// this does not have to be RSA encrypted since we know we are connected
				// to confirmed committee member, but we do have to sign to to prove ourself
	Sig []byte	// my signature (w/o pubkey) on invitation to prove I am the one
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgAckInvitation) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	msg.Invitation.Deserialize(r)

	t, err := common.ReadVarBytes(r, 0, 1024, "Sig")
	if err != nil {
		return err
	}
	msg.Sig = make([]byte, len(t))
	copy(msg.Sig[:], t)

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgAckInvitation) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	msg.Invitation.Serialize(w)

	return common.WriteVarBytes(w, 0, msg.Sig[:])
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgAckInvitation) Command() string {
	return CmdAckInvitation
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgAckInvitation) MaxPayloadLength(pver uint32) uint32 {
	// Num addresses (varInt) + max allowed addresses.
	return 2048
}

// NewMsgAddr returns a new bitcoin addr message that conforms to the
// Message interface.  See MsgAddr for details.
func NewMsgAckInvitation() *MsgAckInvitation {
	return &MsgAckInvitation{}
}
