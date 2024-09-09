// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/famofchains/btcd/wire/common"
)

type MsgXrossL2 struct {
	Utxo OutPoint
	Txo  TxOut
}

func (t *MsgXrossL2) Serialize() []byte {
	res := make([]byte, 56, 100)
	copy(res, t.Utxo.Hash[:])
	common.LittleEndian.PutUint32(res[32:], t.Utxo.Index)
	common.LittleEndian.PutUint64(res[36:], t.Txo.TokenType)

	res = append(res, t.Txo.Serialize()...)
	return res
}

func (t *MsgXrossL2) DeSerialize(d []byte) (int, error) {
	copy(t.Utxo.Hash[:], d)
	t.Utxo.Index = common.LittleEndian.Uint32(d[32:])
	return t.Txo.DeSerialize(d[36:]), nil
}

type XchainData struct {
	ChainID uint32
	Hash    chainhash.Hash			// block
	Height  int32					// height
	Txs     []*MsgXrossL2
	Finalized	byte				// whether the block is finalized
}

func (t *XchainData) Serialize() []byte {
	var w bytes.Buffer
	w.Write(t.Hash[:])

	var h [4]byte
	common.LittleEndian.PutUint32(h[:], uint32(t.Height))
	w.Write(h[:])

	if t.Txs == nil || len(t.Txs) == 0 {
		common.LittleEndian.PutUint32(h[:], 0)
		w.Write(h[:])
		return w.Bytes()
	}

	common.LittleEndian.PutUint32(h[:], uint32(len(t.Txs)))
	w.Write(h[:])

	for _, txo := range t.Txs {
		w.Write(txo.Serialize())
	}

	w.Write([]byte{t.Finalized})
	return w.Bytes()
}

func (t *XchainData) DeSerialize(buf []byte) error {
	m := len(buf)

	if m < 40 {
		return fmt.Errorf("Insufficient data")
	}

	copy(t.Hash[:], buf)

	t.Height = int32(common.LittleEndian.Uint32(buf[32:36]))

	h := common.LittleEndian.Uint32(buf[36:40])
	if h == 0 {
		t.Txs = nil
		return nil
	}

	n := 40
	t.Txs = make([]*MsgXrossL2, h)

	for i := 0; i < int(h); i++ {
		t.Txs[i] = &MsgXrossL2{}
	}

	for _, txo := range t.Txs {
		if n >= len(buf) {
			return fmt.Errorf("Insufficient data")
		}
		m, err := txo.DeSerialize(buf[n:])
		if err != nil {
			return err
		}
		n += m
	}
	if n >= len(buf) {
		return fmt.Errorf("Insufficient data")
	}

	t.Finalized = buf[n]

	return nil
}
