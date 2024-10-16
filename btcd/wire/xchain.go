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
	res := make([]byte, 36, 100)
	copy(res, t.Utxo.Hash[:])
	common.LittleEndian.PutUint32(res[32:], t.Utxo.Index)

	res = append(res, t.Txo.Serialize()...)
	return res
}

func (t *MsgXrossL2) DeSerialize(d []byte) (int, error) {
	copy(t.Utxo.Hash[:], d)
	t.Utxo.Index = common.LittleEndian.Uint32(d[32:])
	return t.Txo.DeSerialize(d[36:]) + 36, nil
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

	if t.Txs == nil || len(t.Txs) == 0 {
		return nil
	}

	common.WriteElement(&w, t.ChainID)
	w.Write(t.Hash[:])

	common.WriteElement(&w, uint32(t.Height))

	common.WriteElement(&w, uint32(len(t.Txs)))

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

	t.ChainID = common.LittleEndian.Uint32(buf[:])

	copy(t.Hash[:], buf[4:])

	t.Height = int32(common.LittleEndian.Uint32(buf[36:]))

	h := common.LittleEndian.Uint32(buf[40:])
	if h == 0 {
		t.Txs = nil
		return nil
	}

	n := 44

	t.Txs = make([]*MsgXrossL2, h)

	for i := 0; i < int(h); i++ {
		if n >= len(buf) {
			return fmt.Errorf("Insufficient data")
		}

		txo := &MsgXrossL2{}
		m, err := txo.DeSerialize(buf[n:])
		if err != nil {
			return err
		}
		t.Txs[i] = txo
		n += m
	}
	if n >= len(buf) {
		return fmt.Errorf("Insufficient data")
	}

	t.Finalized = buf[n]

	return nil
}
