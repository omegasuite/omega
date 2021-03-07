// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/btcutil/base58"
	"github.com/omegasuite/omega/token"
	"math/big"
	_ "net/http/pprof"
	"os"
	"time"
)

type geoCoords struct {
	Lat float64
	Lng float64
}

func solveGenesisBlock(msgBlock *wire.MsgBlock, bits uint32) {
	// Create some convenience variables.
	header := &msgBlock.Header

	targetDifficulty := blockchain.CompactToBig(bits)
	targetDifficulty = targetDifficulty.Mul(targetDifficulty, big.NewInt(wire.DifficultyRatio))

//	log.Printf("targetDifficulty = %s\n", targetDifficulty.String())
	for {
		header.Timestamp = time.Now()

		for i := int32(1); i < 0x7FFFFFFF; i++ {
			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = i
			hash := header.BlockHash()

			//		log.Printf("%d: solve = %s\n", i, blockchain.HashToBig(&hash).String())

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			hashNum := blockchain.HashToBig(&hash)
			if hashNum.Cmp(targetDifficulty) <= 0 {
				return
			}
		}
	}
}

func solveMinerBlock(header *wire.MingingRightBlock) {
	// Create some convenience variables.
	targetDifficulty := blockchain.CompactToBig(header.Bits)

//	log.Printf("targetDifficulty = %s\n", targetDifficulty.String())

	for {
		for i := int32(1); i < 0x7FFFFFFF; i++ {
			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = i
			hash := header.BlockHash()

			//		log.Printf("%d: solve = %s\n", i, blockchain.HashToBig(&hash).String())

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			hashNum := blockchain.HashToBig(&hash)
			if hashNum.Cmp(targetDifficulty) <= 0 {
				return
			}
		}
		header.Timestamp = time.Now()
	}
}

func main() {
	// generate initial polygon representing the globe
	var vertices = []geoCoords{ // international date line
		{Lat: 90.0000, Lng: 180.0000},
		{Lat: 75.0000, Lng: 180.0000},
		{Lat: 68.2456, Lng: -169.},
		{Lat: 65.5189, Lng: -169.},
		{Lat: 53.0863, Lng: 170.0500},
		{Lat: 47.8353, Lng: 180.0000},
		{Lat: -1.2, Lng: 180.0000},
		{Lat: -1.2, Lng: -159.6500},
		{Lat: 2.9000, Lng: -159.6500},
		{Lat: 2.9000, Lng: -162.8500},
		{Lat: 6.5000, Lng: -162.8500},
		{Lat: 6.5000, Lng: -155.9500},
		{Lat: -9.5000, Lng: -149.6500},
		{Lat: -11.7000, Lng: -149.6500},
		{Lat: -11.7000, Lng: -154.0500},
		{Lat: -10.7000, Lng: -154.0500},
		{Lat: -10.70000, Lng: -166.5500},
		{Lat: -15.6000, Lng: -172.700},
		{Lat: -45.0000, Lng: -172.700},
		{Lat: -51.1815, Lng: 180.0000},
		{Lat: -90.0000, Lng: 180.0000},
	}

	fmt.Printf("// This is generated code. Should not be manually modified.\n\n" +
		"package omega" +
		"\n\nimport (\n\t\"time\"" +
		"\n\t\"github.com/omegasuite/btcd/chaincfg/chainhash\"" +
		"\n\t\"github.com/omegasuite/btcd/wire\"" +
		"\n\t\"github.com/omegasuite/omega/token\"\n)\n\n" +
		"var IntlDateLine = [][2]float64 {	// international date line")
	for _, v := range vertices {
		fmt.Printf("\n\t{ %f, %f },", v.Lat, v.Lng)
	}
	fmt.Printf("\n}\n\nvar InitDefs = []token.Definition{")

	m := len(vertices)

	defs := make([]token.Definition, 0, 42+40+4+1+1) // 42 vertices, 40 + 4 borders, 1 polygon, 1 right

	for _, v := range vertices {
		vl := v.Lng
		if v.Lng > 0 {
			vl -= 360.0
		}
		v := token.NewVertexDef(int32(v.Lat*token.CoordPrecision), int32(vl*token.CoordPrecision), 0)
		defs = append(defs, v)
	}

	for i := len(vertices) - 1; i >= 0; i-- {
		vl := vertices[i].Lng
		if vertices[i].Lng < 0 {
			vl += 360.0
		}
		v := token.NewVertexDef(int32(vertices[i].Lat*token.CoordPrecision), int32(vl*token.CoordPrecision), 0)
		defs = append(defs, v)
	}

	b0 := token.NewBorderDef(*defs[0].(*token.VertexDef), *defs[m-1].(*token.VertexDef), chainhash.Hash{})
	defs = append(defs, b0)
	b1 := token.NewBorderDef(*defs[m-1].(*token.VertexDef), *defs[m].(*token.VertexDef), chainhash.Hash{})
	defs = append(defs, b1)
	b2 := token.NewBorderDef(*defs[m].(*token.VertexDef), *defs[2*m-1].(*token.VertexDef), chainhash.Hash{})
	defs = append(defs, b2)
	b3 := token.NewBorderDef(*defs[2*m-1].(*token.VertexDef), *defs[0].(*token.VertexDef), chainhash.Hash{})
	defs = append(defs, b3)

	for i := 0; i < m-1; i++ {
		j := i + 1
		b := token.NewBorderDef(*defs[i].(*token.VertexDef), *defs[j].(*token.VertexDef), b0.Hash())
		defs = append(defs, b)

		b = token.NewBorderDef(*defs[i+m].(*token.VertexDef), *defs[j+m].(*token.VertexDef), b2.Hash())
		defs = append(defs, b)
	}
	polygon := token.NewPolygonDef([]token.LoopDef{{b0.Hash(), b1.Hash(), b2.Hash(), b3.Hash()}})
	defs = append(defs, polygon)
	uright := token.NewRightDef(chainhash.Hash{}, []byte("All Rights"), 0x80)
	defs = append(defs, uright)

	printdef(defs)

	fmt.Printf("\n\nvar coinToken = token.Token{\n\t" +
		"TokenType: 0,\n\t" +
		"Value: &token.NumToken{Val: 600000000},\n\t" +
		"Rights: &chainhash.Hash{},\n}")

	fmt.Printf("\n\nvar polygonToken = token.Token{" +
		"\n\tTokenType: 3," +
		"\n\tValue: &token.HashToken{Hash: ")
	printhash(polygon.Hash())

	fmt.Printf("},\n\tRights: &")
	printhash(uright.Hash())
	fmt.Printf("," + "\n}")

	addresses := map[common.OmegaNet][2]string{
		common.MainNet: {"19VyyaP9gnYUUcZXoZcrBxYnpAJN14Trza", "17RaKVHAPjbFUUFpxcMLD65t1x89V2w6CQ"},
		common.RegNet: {"mhin7M4AKLfQNFQpF9gqaDEsR1a4HiJb5b", "myyeH9trR6zmJ1TrRzFCHKrCv2GaXUvyfJ"},
		common.TestNet: {"mhin7M4AKLfQNFQpF9gqaDEsR1a4HiJb5b", "myyeH9trR6zmJ1TrRzFCHKrCv2GaXUvyfJ"},
		common.SimNet: {"SPVpr8kLEgRM7Sif51hYJCB7CoCnEXLkV4", "Sfkh1wb2LSki3CmhFrFu1JnShouJMVX2nD"},
	}

	params := map[common.OmegaNet]*chaincfg.Params {
		common.MainNet: &chaincfg.MainNetParams,
		common.RegNet:  &chaincfg.RegressionNetParams,
		common.TestNet:  &chaincfg.TestNet3Params,
		common.SimNet:  &chaincfg.SimNetParams,
	}
	names := map[common.OmegaNet]string {
		common.MainNet: "MainNet",
		common.RegNet:  "RegNet",
		common.TestNet:  "TestNet",
		common.SimNet:  "SimNet",
	}

	for net, k := range addresses {
		// for coin
		addr, _, err := base58.CheckDecode(k[0])
		if err != nil {
			fmt.Printf("Failed to generate pay-to-address script")
			os.Exit(1)
		}

		coinpkScript := make([]byte, 25)
		coinpkScript[0] = params[net].PubKeyHashAddrID
		copy(coinpkScript[1:], addr)
		coinpkScript[21] = 0x41

		fmt.Printf("\n\nvar " + params[net].Name + "creator = [20]byte{")
		printKey(addr)
		fmt.Printf("}\n")
		var miner [20]byte
		copy(miner[:], addr)

		addr, _, err = base58.CheckDecode(k[1])
		if err != nil {
			fmt.Printf("Failed to generate pay-to-address script")
			os.Exit(1)
		}

		plgpkScript := make([]byte, 25)
		plgpkScript[0] = params[net].PubKeyHashAddrID
		copy(plgpkScript[1:], addr)
		plgpkScript[21] = 0x41

		if err != nil {
			fmt.Printf("Failed to generate pay-to-address script")
			os.Exit(1)
		}

		var genesisCoinbaseTx = wire.MsgTx{
			Version: 1,
			TxDef:   []token.Definition{},
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  chainhash.Hash{},
						Index: 0,
					},
					SignatureIndex: 0xffffffff,
					Sequence:       0xffffffff,
				},
			},
			TxOut: []*wire.TxOut{
				{
					PkScript: coinpkScript,
				},
			},
			LockTime: 0,
		}

		genesisCoinbaseTx.TxOut[0].TokenType = 0
		genesisCoinbaseTx.TxOut[0].Value = &token.NumToken{Val: 600000000}
		genesisCoinbaseTx.TxOut[0].Rights = &chainhash.Hash{}

		var genesisInitPolygonTx = wire.MsgTx{
			Version: 1,
			TxDef:   defs,
			TxIn:    []*wire.TxIn{},
			TxOut: []*wire.TxOut{
				{
					PkScript: plgpkScript,
				},
			},
			LockTime: 0,
		}

		genesisInitPolygonTx.TxOut[0].TokenType = 3
		genesisInitPolygonTx.TxOut[0].Value = &token.HashToken{Hash: polygon.Hash()}
		uh := uright.Hash()
		genesisInitPolygonTx.TxOut[0].Rights = &uh
		genesisInitPolygonTx.SignatureScripts = nil

		t1 := btcutil.NewTx(&genesisCoinbaseTx)
		t2 := btcutil.NewTx(&genesisInitPolygonTx)
		t1.SetIndex(0)
		t2.SetIndex(1)

		merkles := blockchain.BuildMerkleTreeStore([]*btcutil.Tx{t1, t2}, false)

		// genesisMerkleRoot is the hash of the first transaction in the genesis block
		// for the main network.
		var genesisMerkleRoot = merkles[len(merkles)-1]

		witnessMerkleTree := blockchain.BuildMerkleTreeStore([]*btcutil.Tx{t1, t2}, true)
		witnessMerkleRoot := witnessMerkleTree[len(witnessMerkleTree)-1]

		// genesisBlock defines the genesis block of the block chain which serves as the
		// public transaction ledger for the main network.
		var genesisBlock = wire.MsgBlock{
			Header: wire.BlockHeader{
				Version:    0x10000,
				PrevBlock:  chainhash.Hash{},   // 0000000000000000000000000000000000000000000000000000000000000000
				MerkleRoot: *genesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
				Nonce:      0,
			},
			Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
		}

		// because wire.DifficultyRatio is 2, so exp. portion of PowLimitBits is dec. by 2
		solveGenesisBlock(&genesisBlock, params[net].PowLimitBits)
		var genesisHash = genesisBlock.Header.BlockHash()

		genesisCoinbaseTx.SignatureScripts = [][]byte{(*witnessMerkleRoot)[:]}

		printCoinbase(params[net].Name + "coinbaseTx", &genesisCoinbaseTx)

		fmt.Printf("\n\nvar " + params[net].Name + "PolygonTx = wire.MsgTx{" +
			"\n\tVersion: 1," +
			"\n\tTxDef: InitDefs," +
			"\n\tTxIn: []*wire.TxIn{}," +
			"\n\tTxOut: []*wire.TxOut{" +
			"\n\t\t{" +
			"\n\t\t\tToken: polygonToken," +
			"\n\t\t\tPkScript: []byte{")

		printKey(genesisInitPolygonTx.TxOut[0].PkScript)

		fmt.Printf("\n\t\t\t}," +
			"\n\t\t}," +
			"\n\t}," +
			"\n\tLockTime: 0," +
			"\n}")

		fmt.Printf("\n\nvar " + names[net] + "GenesisMerkleRoot = ")
		printhash(*genesisMerkleRoot)

		fmt.Printf("\n\nvar " + names[net] + "GenesisBlock = wire.MsgBlock{"+
			"\n\tHeader: wire.BlockHeader{"+
			"\n\t\tVersion:    0x10000,"+
			"\n\t\tPrevBlock:  chainhash.Hash{},"+
			"\n\t\tMerkleRoot: " + names[net] + "GenesisMerkleRoot,"+
			"\n\t\tTimestamp:  time.Unix(0x%x, 0), "+
			"\n\t\tNonce:      %d,"+
			"\n\t},"+
			"\n\tTransactions: []*wire.MsgTx{&" + params[net].Name + "coinbaseTx, &" + params[net].Name + "PolygonTx},"+
			"\n}", genesisBlock.Header.Timestamp.Unix(), genesisBlock.Header.Nonce)

		var minerBlock = wire.MingingRightBlock{
			Version:   0x10000,
			PrevBlock: chainhash.Hash{},
			BestBlock: genesisHash,
			Timestamp: genesisBlock.Header.Timestamp,
			Bits:      params[net].PowLimitBits,
			Nonce:     0,
			Miner:     miner,
			Connection:  []byte("omegasuite.org"),
			BlackList: make([]wire.BlackList, 0),
			Utxos:     make([]wire.OutPoint, 0),
		}

		solveMinerBlock(&minerBlock)

		// genesisHash is the hash of the first block in the block chain for the main
		// network (genesis block)

		//	var genesisHash = genesisBlock.BlockHash()
		fmt.Printf("\n\nvar " + names[net] + "GenesisHash = []chainhash.Hash{\n")
		printhash(genesisHash)
		fmt.Printf(",\n")

		var genesisMinerHash = minerBlock.BlockHash()

		printhash(genesisMinerHash)
		fmt.Printf(",\n}")

		fmt.Printf("\n\nvar " + names[net] + "GenesisMinerBlock = wire.MingingRightBlock{"+
			"\n\tVersion: 0x10000,"+
			"\n\tPrevBlock:  chainhash.Hash{},"+
			"\n\tBestBlock: " + names[net] + "GenesisHash[0],"+
			"\n\t\tTimestamp:  time.Unix(0x%x, 0), "+
			"\n\tBits:      0x%x,"+
			"\n\tNonce:      %d,"+
			"\n\tConnection:      []byte{", minerBlock.Timestamp.Unix(), minerBlock.Bits, minerBlock.Nonce)

		printKey(minerBlock.Connection)

		fmt.Printf("},"+
			"\n\tBlackList: []wire.BlackList{},"+
			"\n\tUtxos: []wire.OutPoint{},"+
			"\n\tMiner: " + params[net].Name + "creator,"+
			"\n}")
	}
}

func printKey(k []byte) {
	for i := 0; i < len(k); i++ {
		if i%8 == 0 {
			fmt.Printf("\n\t\t\t\t")
		}
		fmt.Printf("0x%02x, ", k[i])
	}
}

func printCoinbase(name string, tx * wire.MsgTx) {
	fmt.Printf("\n\nvar %s = wire.MsgTx{" +
		"\n\tVersion: 1," +
		"\n\tTxDef: []token.Definition{},", name)
	fmt.Printf("\n\tTxIn: []*wire.TxIn{"+
		"\n\t\t{"+
		"\n\t\t\tPreviousOutPoint: wire.OutPoint{"+
		"\n\t\t\tHash:  chainhash.Hash{},"+
		"\n\t\t\tIndex: 0,"+
		"\n\t\t},"+
		"\n\t\tSignatureIndex: 0xffffffff,"+
		"\n\t\tSequence: 0xffffffff,"+
		"\n\t},"+
		"\n\t},"+
		"\n\tTxOut: []*wire.TxOut{"+
		"\n\t\t{"+
		"\n\t\t\tToken:coinToken,"+
		"\n\t\t\tPkScript: []byte{")

	for i := 0; i < len(tx.TxOut[0].PkScript); i++ {
		if i % 8 == 0 {
			fmt.Printf("\n\t\t\t\t")
		}
		fmt.Printf("0x%02x, ", tx.TxOut[0].PkScript[i])
	}

	fmt.Printf("\n\t\t\t},"+
		"\n\t\t},"+
		"\n\t}," +
		"\n\tSignatureScripts: [][]byte { []byte{")

	for i := 0; i < len(tx.SignatureScripts[0]); i++ {
		if i % 8 == 0 {
			fmt.Printf("\n\t\t")
		}
		fmt.Printf("0x%02x, ", tx.SignatureScripts[0][i])
	}

	fmt.Printf("\n\t} }," +
		"\n\tLockTime: 0," +
		"\n}")
}

func printhash(h chainhash.Hash) {
	fmt.Printf("chainhash.Hash{")
	hb := h.CloneBytes()
	i := 0
	for _,b := range hb {
		if (i % 8) == 0 {
			fmt.Printf("\n\t\t")
		}
		i++
		fmt.Printf("0x%02x, ", b)
	}
	fmt.Printf("\n\t}")
}

func printvertex(p token.VertexDef) {
	fmt.Printf("* token.NewVertexDef(%d, %d, %d)", p.Lat(), p.Lng(), p.Alt())
}

func printdef(def []token.Definition) {
	for _,f := range def {
		switch f.(type) {
		case *token.BorderDef:
			v := f.(*token.BorderDef)
			fmt.Printf("\n\t&token.BorderDef {\n\t\tFather: ");
			if v.Father.IsEqual(&chainhash.Hash{}) {
				fmt.Printf("chainhash.Hash{}")
			} else {
				printhash(v.Father)
			}
			fmt.Printf(",\n\t\tBegin: ")
			printvertex(v.Begin)
			fmt.Printf(",\n\t\tEnd: ")
			printvertex(v.End)
			fmt.Printf(",\n\t},")
			break
		case *token.PolygonDef:
			v := f.(*token.PolygonDef)
			fmt.Printf("\n\t&token.PolygonDef {");
			for i,l := range v.Loops {
				fmt.Printf("\tLoops: []token.LoopDef{{	// Loop %d:\n\t\t", i)
				for _,h := range l {
					printhash(h)
					fmt.Printf(",\n\t\t")
				}
				fmt.Printf("\t},\n")
			}
			fmt.Printf("\t\t},\n\t},")
			break
		case *token.RightDef:
			v := f.(*token.RightDef)
			fmt.Printf("\n\t&token.RightDef {Father: chainhash.Hash{},")
			fmt.Printf("\n\t\tDesc: []byte(\"%s\"),\n\t\tAttrib: %d,\n\t},", v.Desc, v.Attrib)
			break
		}
	}
	fmt.Printf("\n}")
}