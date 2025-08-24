// Copyright (c) 2013-2015 The omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"btcd/wire/common"
	"bytes"
	"io"
)

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

	// patch: removing trailing ,
	bts := []byte(t.Genesis)
	for bts[len(bts)-1] == ',' {
		bts = bts[:len(bts)-1]
	}
	t.Genesis = string(bts)

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
}
