// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"strconv"
	"strings"

	"github.com/omegasuite/btcd/blockchain"
	//	"github.com/omegasuite/btcutil"
	//	"github.com/omegasuite/omega"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/viewpoint"
	"os"
	"path/filepath"
	"runtime"
)

func Fatalf(s string, err error) {
	if err != nil {
		fmt.Printf(s, err.Error())
	} else {
		fmt.Printf(s)
	}
	os.Exit(1)
}

type fakedb struct { }

func (d * fakedb) View(f func(dbTx database.Tx) error) error {
	return nil
}

func (d * fakedb) Update(func(dbTx database.Tx) error) error {
	return nil
}

func (d * fakedb) Type() string {
	return ""
}
func (d * fakedb) Begin(writable bool) (database.Tx, error) {
	return nil, nil
}

func (d * fakedb) Close() error {
	return nil
}

func revhash(h chainhash.Hash) chainhash.Hash {
	h[0] |= 1
	return h
}

func jsonreader(file * os.File, m byte) ([]byte, bool) {
	var res []byte
	s,_ := file.Stat()
	res = make([]byte, s.Size())
	p := 0
	_, err := file.Read(res[p:p + 1])

	eof := false
	var t []byte

	for !eof {
		p++
		switch res[p - 1] {
		case '[':
			t, eof = jsonreader(file, ']')
			copy(res[p:], t)
			p += len(t)

		case '{':
			t, eof = jsonreader(file, '}')
			copy(res[p:], t)
			p += len(t)

		case m:
			return res[:p], eof

		case '"':
			t, eof = jsonreader(file, '"')
			copy(res[p:], t)
			p += len(t)
		}
		_, err = file.Read(res[p:p + 1])
		eof = (err != nil)
	}
	return res[:p], true
}

type rdef struct {
	Type int
	Parent string
	Desc string
	Attrib int
	Members [] string
}

type TxOut struct {
	TokenType	uint64
	Value     uint64
	Rights string
}

type OutPoint struct {
	Hash string
	Index uint32
}

type TxIn struct {
	PreviousOutPoint OutPoint
	Sequence         uint32
}

type alpha struct {
	Utxos map[string] TxOut
	Rights [] rdef
	Inputs [] TxIn
	Outputs [] TxOut
}

var views * viewpoint.ViewPointSet

func addUtxotoDB(s string, w TxOut) {
	var op wire.OutPoint
	t := strings.Split(s, ":")
	h, _ := chainhash.NewHashFromStr(t[0])
	op.Hash = *h
	q,_ := strconv.Atoi(t[1])
	op.Index = uint32(q)

	r, _ := chainhash.NewHashFromStr(w.Rights)

	ww := wire.NewTxOut(w.TokenType, &token.NumToken{Val: int64(w.Value)}, r, nil)

	views.Utxo.AddRawTxOut(op, ww, false, 1)
}

func addRighttoDB(r rdef) {
	if r.Type == 4 {
		h, _ := chainhash.NewHashFromStr(r.Parent)
		x, _ := hex.DecodeString(r.Desc)
		p := token.RightDef {
			Father: *h,
			Desc: x,
			Attrib: uint8(r.Attrib),
		}
		views.AddRight(&p)
	} else if r.Type == 5 {
		p := token.RightSetDef {
			Rights: []chainhash.Hash{},
		}
		for _,s := range r.Members {
			h, _ := chainhash.NewHashFromStr(s)
			p.Rights = append(p.Rights, *h)
		}
		views.Rights.AddRightSet(&p)
	}
}

func main() {
	// test 1: genesis polygon
	var db fakedb
	views = viewpoint.NewViewPointSet(&db)

	_, path, _, ok := runtime.Caller(0)
	if !ok {
		Fatalf("Failed finding file path", nil)
	}

	fname := "sample.tx"
	if len(os.Args) > 1 {
		fname = os.Args[1]
	}

	file,err := os.Open(filepath.Join(filepath.Dir(path), fname))
	if err != nil {
		Fatalf("Failed reading tx file", err)
	}

	s, eof := jsonreader(file, '\n')
	for len(s) > 0 || !eof {
		var v alpha
		if err = json.Unmarshal(s, &v); err != nil {
			Fatalf("Failed Unmarshal tx file", err)
		}
		for _,r := range v.Rights {
			addRighttoDB(r)
		}
		for op,r := range v.Utxos {
			addUtxotoDB(op, r)
		}

		var msgTx2 *wire.MsgTx

		msgTx2 = &wire.MsgTx{
			Version: 1,
			TxDef:   []token.Definition{},
			TxIn:    []*wire.TxIn{},
			TxOut:   []*wire.TxOut{},
		}
		for _,r := range v.Inputs {
			h, _ := chainhash.NewHashFromStr(r.PreviousOutPoint.Hash)
			in := wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash:*h, Index:r.PreviousOutPoint.Index},
				Sequence:         r.Sequence,
				SignatureIndex:   0,
			}
			msgTx2.TxIn = append(msgTx2.TxIn, &in)
		}
		for _,r := range v.Outputs {
			h, _ := chainhash.NewHashFromStr(r.Rights)
			out := wire.NewTxOut(r.TokenType, &token.NumToken{Val: int64(r.Value)}, h, nil)
			msgTx2.TxOut = append(msgTx2.TxOut, out)
		}

		tx := btcutil.NewTx(msgTx2)

		if err := blockchain.CheckTransactionIntegrity(tx, views, wire.Version5); err != nil {
			Fatalf("Failed test: %v", err)
		}

		if eof {
			s = nil
		} else {
			s, eof = jsonreader(file, '\n')
		}
	}

	os.Exit(0)
}
