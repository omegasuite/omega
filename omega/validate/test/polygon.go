// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/validate"
	"github.com/btcsuite/omega/viewpoint"
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

func (d * fakedb) View(func(dbTx database.Tx) error) error {
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

type alpha struct {
	Inst string
	Desc string
	Loop [][][2]float64
	Expect byte
}

func loop2border(ps [][2]float64) ([]token.Definition, token.LoopDef, token.LoopDef) {
	bs := make([]*token.BorderDef, len(ps))
	vs := make([]*token.VertexDef, len(ps))
	loop := token.LoopDef{}
	rloop := token.LoopDef{}
	defs := []token.Definition{}

	for i, p := range ps {
		vs[i] = token.NewVertexDef(int32(p[0]*token.CoordPrecision), int32(p[1]*token.CoordPrecision), 0)
	}

	for i, p := range vs {
		bs[i] = token.NewBorderDef(*p, *vs[(i+1)%len(vs)], chainhash.Hash{})
		loop = append(loop, bs[i].Hash())
		rloop = append(token.LoopDef{revhash(bs[i].Hash())}, rloop...)
		defs = append(defs, bs[i])
	}
	return defs, loop, rloop
}

func main() {
	// test 1: genesis polygon
	msgTx := omega.GenesisBlock.Transactions[1]
	tx := btcutil.NewTx(msgTx)
	var db fakedb
	views := viewpoint.NewViewPointSet(&db)

	// check genesis polygon is ok
	if err := validate.CheckDefinitions(tx.MsgTx()); err != nil {
		Fatalf("Failed genesis CheckDefinitions test: %v", err)
	}

	if err := validate.CheckTransactionInputs(tx, views); err != nil {
		Fatalf("Failed genesis CheckTransactionInputs test: %v", err)
	}

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
		fmt.Printf("\n%s\n", v.Desc)
		var msgTx2 *wire.MsgTx
		var result byte
		switch v.Inst {
		case "alpha":
			defs, loop, rloop := loop2border(v.Loop[0])
			p1 := token.NewPolygonDef([]token.LoopDef{ loop })
			p0 := token.NewPolygonDef([]token.LoopDef{
				token.LoopDef{ msgTx.TxOut[0].Value.(*token.HashToken).Hash },
				rloop,
			})
			defs = append(defs, p1)
			defs = append(defs, p0)

			msgTx2 = &wire.MsgTx{
				Version: 1,
				TxDef: defs,
				TxIn:     []*wire.TxIn{},
				TxOut:    []*wire.TxOut{
					wire.NewTxOut(3, &token.HashToken{p1.Hash()}, nil, nil),
					wire.NewTxOut(3, &token.HashToken{p0.Hash()}, nil, nil),
				},
			}

		case "beta":
			defs, loop, rloop := loop2border(v.Loop[0])
			defs2, loop2, rloop2 := loop2border(v.Loop[1])
			p1 := token.NewPolygonDef([]token.LoopDef{ rloop, rloop2 })
			p2 := token.NewPolygonDef([]token.LoopDef{ loop })
			p3 := token.NewPolygonDef([]token.LoopDef{
				token.LoopDef{ msgTx.TxOut[0].Value.(*token.HashToken).Hash },
				token.LoopDef{p1.Hash()},
			})
			p4 := token.NewPolygonDef([]token.LoopDef{ loop2 })

			defs = append(defs, defs2...)
			defs = append(defs, p1)
			defs = append(defs, p2)
			defs = append(defs, p3)
			defs = append(defs, p4)

			msgTx2 = &wire.MsgTx{
				Version: 1,
				TxDef: defs,
				TxIn:     []*wire.TxIn{},
				TxOut:    []*wire.TxOut{
					wire.NewTxOut(3, &token.HashToken{p2.Hash()}, nil, nil),
					wire.NewTxOut(3, &token.HashToken{p3.Hash()}, nil, nil),
					wire.NewTxOut(3, &token.HashToken{p4.Hash()}, nil, nil),
				},
			}
		}
		tx = btcutil.NewTx(msgTx2)
		if err := validate.CheckDefinitions(tx.MsgTx()); err != nil {
			result = 1
			fmt.Printf("%s: %s\n", v.Desc, err.Error())
		} else if err := validate.CheckTransactionInputs(tx, views); err != nil {
			result = 2
			fmt.Printf("%s : %s\n", v.Desc, err.Error())
		}
		if v.Expect == result {
			fmt.Printf("%s passed\n", v.Desc)
		} else {
			fmt.Printf("%s Expect result %d, Actual result %d.\n", v.Desc, v.Expect, result)
		}
		if eof {
			s = nil
		} else {
			s, eof = jsonreader(file, '\n')
		}
	}

	/*
		_, path, _, ok := runtime.Caller(0)
		if !ok {
			Fatalf("Failed finding config file path", nil)
		}

		fnames := []string{"sample.tx"}
		if len(os.Args) > 1 {
			fnames = os.Args[1:]
		}

		for _,fname := range fnames {
			testVector := filepath.Join(filepath.Dir(path), fname)
			rawdata, err := ioutil.ReadFile(testVector)
			if err != nil {
				Fatalf("Failed reading sample config file: %v", err)
			}

			hexStr := string(rawdata)
			if len(hexStr)%2 != 0 {
				hexStr = "0" + hexStr
			}
			serializedTx, err := hex.DecodeString(hexStr)
			if err != nil {
				Fatalf("Failed to decode test vextor file. %s", err)
			}
			var msgTx wire.MsgTx
			err = msgTx.Deserialize(bytes.NewReader(serializedTx))
			if err != nil {
				Fatalf("Failed reading sample config file: %v", err)
			}

			tx := btcutil.NewTx(&msgTx)
			var db fakedb
			views := viewpoint.NewViewPointSet(&db)

			if err = validate.CheckTransactionInputs(tx, views); err != nil {
				Fatalf("Failed reading sample config file: %v", err)
			}
		}
	 */
	os.Exit(0)
}
