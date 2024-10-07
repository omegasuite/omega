// Copyright (c) 2013-2015 The omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"github.com/omegasuite/famofchains/btcd/wire/common"
	"io"
)

type MsgGetChainMap struct {
	Sequence uint32 // id of the chain
}

type ChainDescriptor struct {
	Magic          uint32
	MRChain        bool
	Genesis        string
	MrGenesis      string
	Parent         uint32
	ChainID        uint32
	Dns            string
	DefaultPort    string
	DefaultRPCPort string
	Height         uint32
	GlobalParams   string
}

func (t *ChainDescriptor) Match(s *ChainDescriptor) bool {
	return t.Magic == s.Magic && t.MRChain == s.MRChain &&
		t.Genesis == s.Genesis && t.MrGenesis == s.MrGenesis &&
		t.Dns == s.Dns && t.DefaultRPCPort == s.DefaultRPCPort &&
		t.DefaultPort == s.DefaultPort && t.Parent == s.Parent &&
		t.ChainID == s.ChainID && t.GlobalParams == s.GlobalParams
}

func (t *ChainDescriptor) Serialize() []byte {
	var w bytes.Buffer
	err := t.OmcEncode(&w)
	if err != nil {
		return nil
	}
	return w.Bytes()
}

func (t *ChainDescriptor) OmcEncode(w io.Writer) error {
	var b byte
	if t.MRChain {
		b = 1
	} else {
		b = 0
	}
	err := common.WriteElements(w, t.Magic, b)
	if err != nil {
		return err
	}

	err = common.WriteVarBytes(w, 0, []byte(t.Genesis))
	if err != nil {
		return err
	}
	err = common.WriteVarBytes(w, 0, []byte(t.MrGenesis))
	if err != nil {
		return err
	}
	err = common.WriteElements(w, t.Parent, t.ChainID)
	if err != nil {
		return err
	}

	err = common.WriteElements(w, uint32(len(t.Dns)), uint32(len(t.DefaultPort)), uint32(len(t.DefaultRPCPort)))
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(t.Dns))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(t.DefaultPort))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(t.DefaultRPCPort))
	if err != nil {
		return err
	}

	err = common.WriteVarBytes(w, 0, []byte(t.GlobalParams))
	if err != nil {
		return err
	}

	return nil
}

func (t *ChainDescriptor) OmcDecode(r io.Reader) error {
	var b byte
	err := common.ReadElements(r, &t.Magic, &b)
	if err != nil {
		return err
	}

	if b == 1 {
		t.MRChain = true
	} else {
		t.MRChain = false
	}

	t.Genesis, err = common.ReadVarString(r, 0)
	if err != nil {
		return err
	}
	t.MrGenesis, err = common.ReadVarString(r, 0)
	if err != nil {
		return err
	}

	err = common.ReadElements(r, &t.Parent, &t.ChainID)
	if err != nil {
		return err
	}

	var n, m, k uint32

	err = common.ReadElements(r, &n, &m, &k)
	if err != nil {
		return err
	}

	buf := make([]byte, n)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	t.Dns = string(buf)

	buf = make([]byte, m)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	t.DefaultPort = string(buf)

	buf = make([]byte, k)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	t.DefaultRPCPort = string(buf)

	t.GlobalParams, err = common.ReadVarString(r, 0)
	if err != nil {
		return err
	}

	return nil
}

func (t *ChainDescriptor) Deserialize(res []byte) bool {
	ln := len(res)
	if ln < 81+12 {
		return false
	}

	var r bytes.Reader
	r.Reset(res)
	return t.OmcDecode(&r) == nil
	/*
		ln := len(res)
		if ln < 81+12 {
			return false
		}
		t.Magic = common.LittleEndian.Uint32(res[:])
		if res[4] == 1 {
			t.MRChain = true
		} else {
			t.MRChain = false
		}

		copy(t.Genesis[:], res[5:])
		copy(t.MrGenesis[:], res[37:])
		t.Parent = common.LittleEndian.Uint32(res[69:])
		t.ChainID = common.LittleEndian.Uint32(res[73:])
		t.Mature = common.LittleEndian.Uint32(res[77:])
		n := common.LittleEndian.Uint32(res[81:])
		m := common.LittleEndian.Uint32(res[85:])
		k := common.LittleEndian.Uint32(res[89:])
		if uint32(ln) != 93+n+m+k {
			return false
		}

		t.Dns = string(res[93 : 93+n])
		t.DefaultPort = string(res[93+n : 93+n+m])
		t.DefaultRPCPort = string(res[93+n+m : 93+n+m+k])

		return true
	*/
}

type MsgChainMap struct {
	Count  uint32 // id of the chain
	Chains []ChainDescriptor
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetChainMap) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return common.ReadElement(r, &msg.Sequence)
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetChainMap) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return common.WriteElement(w, msg.Sequence)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetChainMap) Command() string {
	return CmdGetChainMap
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetChainMap) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgGetChainMap(seq uint32) *MsgGetChainMap {
	return &MsgGetChainMap{
		Sequence: seq,
	}
}

// OmcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgChainMap) OmcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.ReadElement(r, &msg.Count)
	if err != nil {
		return err
	}

	msg.Chains = make([]ChainDescriptor, msg.Count)

	for i := uint32(0); i < msg.Count; i++ {
		c := &ChainDescriptor{}
		err := c.OmcDecode(r)
		if err != nil {
			return err
		}
		msg.Chains[i] = *c
	}

	return nil
}

// OmcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgChainMap) OmcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	err = common.WriteElement(w, msg.Count)
	if err != nil {
		return err
	}

	for i := uint32(0); i < msg.Count; i++ {
		err := msg.Chains[i].OmcEncode(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgChainMap) Command() string {
	return CmdChainMap
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgChainMap) MaxPayloadLength(pver uint32) uint32 {
	// Since this can vary depending on the message, make it the max
	// size allowed.
	return MaxMessagePayload
}

// NewMsgAlert returns a new bitcoin alert message that conforms to the Message
// interface.  See MsgAlert for details.
func NewMsgChainMap() *MsgChainMap {
	return &MsgChainMap{
		Count:  0,
		Chains: make([]ChainDescriptor, 0),
	}
}
