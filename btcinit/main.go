// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/btcsuite/btcutil"
	_ "net/http/pprof"
	"time"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/blockchain"
	"fmt"
	"os"
	"github.com/vsergeev/btckeygenie/btckey"
	"github.com/btcsuite/btcd/txscript"
	"log"
)

type geoCoords struct {
	Lat float64
	Lng float64
}

func solveGenesisBlock(msgBlock *wire.MsgBlock) {
	// Create some convenience variables.
	header := &msgBlock.Header
	targetDifficulty := blockchain.CompactToBig(header.Bits)

	log.Printf("targetDifficulty = %s\n", targetDifficulty.String())

	for i := uint32(0); true; i++ {
			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = i
			hash := header.BlockHash()

			log.Printf("%d: solve = %s\n", i, blockchain.HashToBig(&hash).String())

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
				return
			}
	}
}

func main() {
	log.Printf("Begin\n")

	var priv btckey.PrivateKey

	// for main net
	priv.FromWIF("cQdPVU5KSzLkD1rhvLJztvpWBu9TrVAE2iPxfgEQrzWuS5xLNRX6")

	// generate initial polygon representing the globe
	var vertices = []geoCoords {	// international date line
		{ Lat: 90.0000, Lng: 180.0000, },
		{ Lat: 75.0000, Lng: 180.0000, },
		{ Lat: 67.7356, Lng: -169.2500, },
		{ Lat: 65.0189, Lng: -169.2500, },
		{ Lat: 52.6863, Lng: 170.0500, },
		{ Lat: 47.8353, Lng: 180.0000, },
		{ Lat: -0.9000, Lng: 180.0000, },
		{ Lat: -0.9000, Lng: -159.6500, },
		{ Lat: 2.9000, Lng: -159.6500, },
		{ Lat: 2.9000, Lng: -161.8500, },
		{ Lat: 5.0000, Lng: -161.8500, },
		{ Lat: 5.0000, Lng: -155.9500, },
		{ Lat: -7.8000, Lng: -150.6500, },
		{ Lat: -10.0000, Lng: -150.6500, },
		{ Lat: -10.0000, Lng: -156.0500, },
		{ Lat: -7.8000, Lng: -156.0500, },
		{ Lat: -7.80000, Lng: -178.0500, },
		{ Lat: -15.0000, Lng: -172.7500, },
		{ Lat: -45.0000, Lng: -172.7500, },
		{ Lat: -51.1815, Lng: 180.0000, },
		{ Lat: -90.0000, Lng: 180.0000, },
	}

	m := len(vertices)

	defs := make([]wire.Definition, 0, 42 + 40 + 4 + 1 + 1)	// 42 vertices, 40 + 4 borders, 1 polygon, 1 right

	for _, v := range vertices {
		vl := v.Lng
		if v.Lng > 0 {
			vl -= 360.0
		}
		v := wire.NewVertexDef(int32(v.Lat * wire.CoordPrecision), int32(vl * wire.CoordPrecision), []byte{})
		defs = append(defs, v)
	}

	for i := len(vertices) - 1; i >= 0; i-- {
		vl := vertices[i].Lng
		if vertices[i].Lng < 0 {
			vl += 360.0
		}
		v := wire.NewVertexDef(int32(vertices[i].Lat * wire.CoordPrecision), int32(vl * wire.CoordPrecision), []byte{})
		defs = append(defs, v)
	}

	b0 := wire.NewBorderDef(defs[0].Hash(), defs[m-1].Hash(), chainhash.Hash{})
	defs = append(defs, b0)
	b1 := wire.NewBorderDef(defs[m-1].Hash(), defs[m].Hash(), chainhash.Hash{})
	defs = append(defs, b1)
	b2 := wire.NewBorderDef(defs[m].Hash(), defs[2 * m - 1].Hash(), chainhash.Hash{})
	defs = append(defs, b2)
	b3 := wire.NewBorderDef(defs[2 * m - 1].Hash(), defs[0].Hash(), chainhash.Hash{})
	defs = append(defs, b3)

	for i := 0; i < m - 1; i++ {
		j := i + 1
		b := wire.NewBorderDef(defs[i].Hash(), defs[j].Hash(), b0.Hash())
		defs = append(defs, b)

		b = wire.NewBorderDef(defs[i + m].Hash(), defs[j + m].Hash(), b2.Hash())
		defs = append(defs, b)
	}
	polygon := wire.NewPolygonDef([]wire.LoopDef{{b0.Hash(), b1.Hash(), b2.Hash(), b3.Hash()}})
	defs = append(defs, polygon)
	uright := wire.NewRightDef(chainhash.Hash{}, []byte("All Rights"), 3)
	defs = append(defs, uright)

	// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
	// the main network, regression test network, and test network (version 3).
	// mainnet version = 0, testnet = 0x6F

	addr, err := btcutil.DecodeAddress(priv.PublicKey.ToAddress(0x6F), &chaincfg.TestNet3Params)
	if err != nil {
		fmt.Printf("Failed to generate pay-to-address script")
		os.Exit(1)
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		fmt.Printf("Failed to generate pay-to-address script")
		os.Exit(1)
	}

	var genesisCoinbaseTx = wire.MsgTx{
		Version: 1,
		TxDef: []wire.Definition{},
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte("Omega chain, the final block chain!"),
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				TokenType: 0,
				Value: &wire.NumToken{Val: 0x12a05f200},
				Rights: []chainhash.Hash{},
				PkScript: []byte(pkScript),
			},
		},
		LockTime: 0,
	}

	var genesisInitPolygonTx = wire.MsgTx{
		Version: 1,
		TxDef: defs,
		TxIn: []*wire.TxIn{},
		TxOut: []*wire.TxOut{
			{
				TokenType: 3,
				Value: &wire.HashToken{Hash: polygon.Hash()},
				Rights: []chainhash.Hash{uright.Hash()},
				PkScript: []byte(pkScript),
			},
		},
		LockTime: 0,
	}

	t1 := btcutil.NewTx(&genesisCoinbaseTx)
	t2 := btcutil.NewTx(&genesisInitPolygonTx)
	t1.SetIndex(0)
	t2.SetIndex(1)

	merkles := blockchain.BuildMerkleTreeStore([]*btcutil.Tx{t1, t2}, false)

	// genesisMerkleRoot is the hash of the first transaction in the genesis block
	// for the main network.
	var genesisMerkleRoot = merkles[len(merkles) - 1]

	fmt.Printf("genesisMerkleRoot: ")
	printhash(*genesisMerkleRoot)

	// genesisBlock defines the genesis block of the block chain which serves as the
	// public transaction ledger for the main network.
	var genesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
			MerkleRoot: *genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
			Timestamp:  time.Now(),
			Bits:       0x1f00ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&genesisBlock)

	// genesisHash is the hash of the first block in the block chain for the main
	// network (genesis block)

//	var genesisHash = genesisBlock.BlockHash()
	var genesisHash = genesisBlock.Header.BlockHash()
	fmt.Printf("genesisHash: ")
	printhash(genesisHash)

	// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
	// block for the regression test network.  It is the same as the merkle root for
	// the main network.
	var regTestGenesisMerkleRoot = genesisMerkleRoot

	// regTestGenesisBlock defines the genesis block of the block chain which serves
	// as the public transaction ledger for the regression test network.
	var regTestGenesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
			MerkleRoot: *regTestGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
			Timestamp:  time.Now(),
			Bits:       0x1f7fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&regTestGenesisBlock)

	// regTestGenesisHash is the hash of the first block in the block chain for the
	// regression test network (genesis block).
//	var regTestGenesisHash = regTestGenesisBlock.BlockHash()
	var regTestGenesisHash = regTestGenesisBlock.Header.BlockHash()
	fmt.Printf("regTestGenesisHash: ")
	printhash(regTestGenesisHash)

	// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
	// block for the test network (version 3).  It is the same as the merkle root
	// for the main network.
	var testNet3GenesisMerkleRoot = genesisMerkleRoot

	// testNet3GenesisBlock defines the genesis block of the block chain which
	// serves as the public transaction ledger for the test network (version 3).
	var testNet3GenesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
			MerkleRoot: *testNet3GenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
			Timestamp:  time.Now(),
			Bits:       0x1f00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
			Nonce:      0,                // 414098458
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&testNet3GenesisBlock)

	// testNet3GenesisHash is the hash of the first block in the block chain for the
	// test network (version 3).
//	var testNet3GenesisHash = testNet3GenesisBlock.BlockHash()
	var testNet3GenesisHash = testNet3GenesisBlock.Header.BlockHash()
	fmt.Printf("testNet3GenesisHash: ")
	printhash(testNet3GenesisHash)

	// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
	// block for the simulation test network.  It is the same as the merkle root for
	// the main network.
	var simNetGenesisMerkleRoot = genesisMerkleRoot

	// simNetGenesisBlock defines the genesis block of the block chain which serves
	// as the public transaction ledger for the simulation test network.
	var simNetGenesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
			MerkleRoot: *simNetGenesisMerkleRoot,  // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
			Timestamp:  time.Now(),
			Bits:       0x1f7fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
			Nonce:      2,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&simNetGenesisBlock)

	// simNetGenesisHash is the hash of the first block in the block chain for the
	// simulation test network.
//	var simNetGenesisHash = simNetGenesisBlock.BlockHash()
	var simNetGenesisHash = simNetGenesisBlock.Header.BlockHash()
	fmt.Printf("simNetGenesisHash: ")
	printhash(simNetGenesisHash)

	printdef(defs)
	fmt.Printf("\ngenesisBlock\n")
	printblock(genesisBlock)
	fmt.Printf("\nregTestGenesisBlock\n")
	printblock(regTestGenesisBlock)
	fmt.Printf("\ntestNet3GenesisBlock\n")
	printblock(testNet3GenesisBlock)
	fmt.Printf("\nsimNetGenesisBlock\n")
	printblock(simNetGenesisBlock)
}
func printhash(h chainhash.Hash) {
	fmt.Printf("chainhash.Hash([chainhash.HashSize]byte{")
	hb := h.CloneBytes()
	i := 0
	for _,b := range hb {
		if (i % 8) == 0 {
			fmt.Printf("\n\t\t")
		}
		i++
		fmt.Printf("0x%02x, ", b)
	}
	fmt.Printf("\n\t}),")
}

func printblock(blk wire.MsgBlock) {
	fmt.Printf("Header {\n\tVersion:%d,\n\tPrevBlock: %s\n\tMerkleRoot: %s\n\tTimestamp: 0x%x\n\tBits: 0x%x\n\tNonce: %d\n\tTransactions:\n",
		blk.Header.Version, blk.Header.PrevBlock.String(), blk.Header.MerkleRoot.String(), blk.Header.Timestamp.Unix(),
		blk.Header.Bits, blk.Header.Nonce)
	for _, t := range blk.Transactions {
		fmt.Printf("\tMsgTx {\n\t\tVersion: 1,\n\t\tTxDef: [...]\n\t\tTxIn: {}\n\t\tTxOut: {")
		for _, to := range t.TxOut {
			fmt.Printf("\n\t\t\tTokenType: %d\n\t\t\tValue: \n\t\t\t", to.TokenType)
			h,v := to.Value.Value()
			if to.Value.IsNumeric() {
				fmt.Printf("Val: %d", v)
			} else {
				fmt.Printf("Hash: ")
				printhash(*h)
			}
			fmt.Printf("\n\t\t\tRights: ")
			for _,r := range to.Rights {
				fmt.Printf("\n\t\t\t")
				printhash(r)
			}
			fmt.Printf("\n\t\t\tPkScript: [")
			for _,r := range to.PkScript {
				fmt.Printf("0x%02x, ", r)
			}
			fmt.Printf("]\n\t\t}\n")
		}
		fmt.Printf("\n\t\tLockTime: %d\n\t}\n", t.LockTime)
	}
}

func printdef(def []wire.Definition) {
	fmt.Printf("Definitions\n")
	for _,f := range def {
		switch f.(type) {
		case *wire.VertexDef:
			v := f.(*wire.VertexDef)
			fmt.Printf("&wire.VertexDef {\n\tLat: 0x%x,\n\tLng: 0x%x,\n\tDesc:[]byte{},\n},\n",
				uint32(v.Lat), uint32(v.Lng))
			break
		case *wire.BorderDef:
			v := f.(*wire.BorderDef)
			fmt.Printf("&wire.BorderDef {\n\tFather: ");
			printhash(v.Father)
			fmt.Printf("\n\tBegin: ")
			printhash(v.Begin)
			fmt.Printf("\n\tEnd: ")
			printhash(v.End)
			fmt.Printf("\n},\n")
			break
		case *wire.PolygonDef:
			v := f.(*wire.PolygonDef)
			fmt.Printf("&wire.PolygonDef {");
			for i,l := range v.Loops {
				fmt.Printf("\tLoops: []wire.LoopDef{{	// Loop %d:\n", i)
				for _,h := range l {
					printhash(h)
				}
				fmt.Printf("\t},\n")
			}
			fmt.Printf("},\n},\n")
			break
		case *wire.RightDef:
			v := f.(*wire.RightDef)
			fmt.Printf("&wire.RightDef {Father: ")
			printhash(v.Father)
			fmt.Printf("\n\tDesc: []byte(\"%s\"),\n\tAttrib: %d,\n},\n", v.Desc, v.Attrib)
			break
		}
	}
}