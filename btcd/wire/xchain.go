// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire/common"
)

type MsgXrossL2 struct {
	Utxo     OutPoint
	Value    int64
	PkScript []byte
	Redeem   []byte
}

func (t *MsgXrossL2) Serialize() []byte {
	res := make([]byte, 52, 100)
	copy(res, t.Utxo.Hash[:])
	common.LittleEndian.PutUint32(res[32:], t.Utxo.Index)
	common.LittleEndian.PutUint64(res[36:], uint64(t.Value))
	common.LittleEndian.PutUint32(res[44:], uint32(len(t.PkScript)))
	common.LittleEndian.PutUint32(res[48:], uint32(len(t.Redeem)))

	res = append(res, t.PkScript...)
	res = append(res, t.Redeem...)
	return res
}

func (t *MsgXrossL2) UnSerialize(d []byte) (int, error) {
	copy(t.Utxo.Hash[:], d)
	t.Utxo.Index = common.LittleEndian.Uint32(d[32:])
	t.Value = int64(common.LittleEndian.Uint64(d[36:]))
	m := common.LittleEndian.Uint32(d[44:])
	n := common.LittleEndian.Uint32(d[48:])

	t.PkScript = d[52 : 52+m]
	t.Redeem = d[52+m : 52+m+n]

	return int(52 + m + n), nil
}

func XrossL2(utxo *OutPoint, Value int64, PkScript []byte) *MsgXrossL2 {
	return &MsgXrossL2{
		Utxo:     *utxo,
		Value:    Value,
		PkScript: PkScript,
	}
}

type BTCL2Data struct {
	ChainID uint32
	Hash    chainhash.Hash
	Height  int32
	Txs     []*MsgXrossL2
}

func (t *BTCL2Data) Serialize() []byte {
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
		var v [8]byte

		_ = common.WriteElements(&w, &txo.Utxo.Hash, txo.Utxo.Index)

		common.LittleEndian.PutUint64(v[:], uint64(txo.Value))
		w.Write(v[:])

		common.LittleEndian.PutUint32(h[:], uint32(len(txo.PkScript)))
		w.Write(h[:])
		w.Write(txo.PkScript)

		common.LittleEndian.PutUint32(h[:], uint32(len(txo.Redeem)))
		w.Write(h[:])
		w.Write(txo.Redeem)
	}
	return w.Bytes()
}

func (t *BTCL2Data) Unserialize(buf []byte) error {
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
		if m < n+48 {
			return fmt.Errorf("Insufficient data")
		}

		copy(txo.Utxo.Hash[:], buf[n:n+32])
		n += 32
		txo.Utxo.Index = common.LittleEndian.Uint32(buf[n : n+4])
		n += 4

		txo.Value = int64(common.LittleEndian.Uint64(buf[n : n+8]))
		n += 8

		h := common.LittleEndian.Uint32(buf[n : n+4])
		n += 4

		if m < n+int(h) {
			return fmt.Errorf("Insufficient data")
		}

		txo.PkScript = make([]byte, h)
		copy(txo.PkScript, buf[n:n+int(h)])
		n += int(h)

		h = common.LittleEndian.Uint32(buf[n : n+4])
		n += 4

		txo.Redeem = make([]byte, h)
		copy(txo.Redeem, buf[n:n+int(h)])
		n += int(h)
	}
	return nil
}
