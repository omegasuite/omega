// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
)

// MsgReject implements the Message interface and represents a bitcoin reject
// message.
//
// This message was not added until protocol version RejectVersion.
type MsgReject struct {
	// Cmd is the command for the message which was rejected such as
	// as CmdBlock or CmdTx.  This can be obtained from the Command function
	// of a Message.
	Cmd string

	// RejectCode is a code indicating why the command was rejected.  It
	// is encoded as a uint8 on the wire.
	Code common.RejectCode

	// Reason is a human-readable string with specific details (over and
	// above the reject code) about why the command was rejected.
	Reason string

	// Hash identifies a specific block or transaction that was rejected
	// and therefore only applies the MsgBlock and MsgTx messages.
	Hash chainhash.Hash
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgReject) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < RejectVersion {
		str := fmt.Sprintf("reject message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgReject.OmcDecode", str)
	}

	// Command that was rejected.
	cmd, err := common.ReadVarString(r, pver)
	if err != nil {
		return err
	}
	msg.Cmd = cmd

	// Code indicating why the command was rejected.
	err = common.ReadElement(r, &msg.Code)
	if err != nil {
		return err
	}

	// Human readable string with specific details (over and above the
	// reject code above) about why the command was rejected.
	reason, err := common.ReadVarString(r, pver)
	if err != nil {
		return err
	}
	msg.Reason = reason

	// CmdBlock and CmdTx messages have an additional hash field that
	// identifies the specific block or transaction.
	if msg.Cmd == CmdBlock || msg.Cmd == CmdTx {
		err := common.ReadElement(r, &msg.Hash)
		if err != nil {
			return err
		}
	}

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgReject) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < RejectVersion {
		str := fmt.Sprintf("reject message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgReject.OmcEncode", str)
	}

	// Command that was rejected.
	err := common.WriteVarString(w, pver, msg.Cmd)
	if err != nil {
		return err
	}

	// Code indicating why the command was rejected.
	err = common.WriteElement(w, msg.Code)
	if err != nil {
		return err
	}

	// Human readable string with specific details (over and above the
	// reject code above) about why the command was rejected.
	err = common.WriteVarString(w, pver, msg.Reason)
	if err != nil {
		return err
	}

	// CmdBlock and CmdTx messages have an additional hash field that
	// identifies the specific block or transaction.
	if msg.Cmd == CmdBlock || msg.Cmd == CmdTx {
		err := common.WriteElement(w, &msg.Hash)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgReject) Command() string {
	return CmdReject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgReject) MaxPayloadLength(pver uint32) uint32 {
	plen := uint32(0)
	// The reject message did not exist before protocol version
	// RejectVersion.
	if pver >= RejectVersion {
		// Unfortunately the bitcoin protocol does not enforce a sane
		// limit on the length of the reason, so the max payload is the
		// overall maximum message payload.
		plen = MaxMessagePayload
	}

	return plen
}

// NewMsgReject returns a new bitcoin reject message that conforms to the
// Message interface.  See MsgReject for details.
func NewMsgReject(command string, code common.RejectCode, reason string) *MsgReject {
	return &MsgReject{
		Cmd:    command,
		Code:   code,
		Reason: reason,
	}
}
