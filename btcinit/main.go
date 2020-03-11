// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"github.com/vsergeev/btckeygenie/btckey"
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

//	log.Printf("targetDifficulty = %s\n", targetDifficulty.String())

	for i := int32(1); true; i++ {
		// Update the nonce and hash the block header.  Each
		// hash is actually a double sha256 (two hashes), so
		// increment the number of hashes completed for each
		// attempt accordingly.
		header.Nonce = i
		hash := header.BlockHash()

//		log.Printf("%d: solve = %s\n", i, blockchain.HashToBig(&hash).String())

		// The block is solved when the new block hash is less
		// than the target difficulty.  Yay!
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			return
		}
	}
}

func solveMinerBlock(header *wire.MingingRightBlock) {
	// Create some convenience variables.
	targetDifficulty := blockchain.CompactToBig(header.Bits)

//	log.Printf("targetDifficulty = %s\n", targetDifficulty.String())

	for i := int32(0); true; i++ {
		// Update the nonce and hash the block header.  Each
		// hash is actually a double sha256 (two hashes), so
		// increment the number of hashes completed for each
		// attempt accordingly.
		header.Nonce = i
		hash := header.BlockHash()

//		log.Printf("%d: solve = %s\n", i, blockchain.HashToBig(&hash).String())

		// The block is solved when the new block hash is less
		// than the target difficulty.  Yay!
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			return
		}
	}
}

func main() {
	var priv btckey.PrivateKey

	// for main net
	priv.FromWIF("cQdPVU5KSzLkD1rhvLJztvpWBu9TrVAE2iPxfgEQrzWuS5xLNRX6")

	dwif,_ := btcutil.DecodeWIF("cQdPVU5KSzLkD1rhvLJztvpWBu9TrVAE2iPxfgEQrzWuS5xLNRX6")

	privKey := dwif.PrivKey

	// generate initial polygon representing the globe
	var vertices = []geoCoords {	// international date line
		{ Lat: 90.0000, Lng: 180.0000 },
		{ Lat: 75.0000, Lng: 180.0000 },
		{ Lat: 68.2456, Lng: -169. },
		{ Lat: 65.5189, Lng: -169. },
		{ Lat: 53.0863, Lng: 170.0500 },
		{ Lat: 47.8353, Lng: 180.0000 },
		{ Lat: -1.2, Lng: 180.0000 },
		{ Lat: -1.2, Lng: -159.6500 },
		{ Lat: 2.9000, Lng: -159.6500 },
		{ Lat: 2.9000, Lng: -162.8500 },
		{ Lat: 6.5000, Lng: -162.8500 },
		{ Lat: 6.5000, Lng: -155.9500 },
		{ Lat: -9.5000, Lng: -149.6500 },
		{ Lat: -11.7000, Lng: -149.6500 },
		{ Lat: -11.7000, Lng: -154.0500 },
		{ Lat: -10.7000, Lng: -154.0500 },
		{ Lat: -10.70000, Lng: -166.5500 },
		{ Lat: -15.6000, Lng: -172.700 },
		{ Lat: -45.0000, Lng: -172.700 },
		{ Lat: -51.1815, Lng: 180.0000 },
		{ Lat: -90.0000, Lng: 180.0000 },
	}

	fmt.Printf("// This is generated code. Should not be manually modified.\n\n" +
		"package omega" +
		"\n\nimport (\n\t\"time\"" +
		"\n\t\"github.com/btcsuite/btcd/chaincfg/chainhash\""+
		"\n\t\"github.com/btcsuite/btcd/wire\"" +
		"\n\t\"github.com/btcsuite/omega/token\"\n)\n\n" +
		"var IntlDateLine = [][2]float64 {	// international date line")
	for _, v := range vertices {
		fmt.Printf("\n\t{ %f, %f },", v.Lat, v.Lng)
	}
	fmt.Printf("\n}\n\nvar InitDefs = []token.Definition{")

	m := len(vertices)

	defs := make([]token.Definition, 0, 42 + 40 + 4 + 1 + 1)	// 42 vertices, 40 + 4 borders, 1 polygon, 1 right

	for _, v := range vertices {
		vl := v.Lng
		if v.Lng > 0 {
			vl -= 360.0
		}
		v := token.NewVertexDef(int32(v.Lat * token.CoordPrecision), int32(vl * token.CoordPrecision), 0)
		defs = append(defs, v)
	}

	for i := len(vertices) - 1; i >= 0; i-- {
		vl := vertices[i].Lng
		if vertices[i].Lng < 0 {
			vl += 360.0
		}
		v := token.NewVertexDef(int32(vertices[i].Lat * token.CoordPrecision), int32(vl * token.CoordPrecision), 0)
		defs = append(defs, v)
	}

	b0 := token.NewBorderDef(defs[0].Hash(), defs[m-1].Hash(), chainhash.Hash{})
	defs = append(defs, b0)
	b1 := token.NewBorderDef(defs[m-1].Hash(), defs[m].Hash(), chainhash.Hash{})
	defs = append(defs, b1)
	b2 := token.NewBorderDef(defs[m].Hash(), defs[2 * m - 1].Hash(), chainhash.Hash{})
	defs = append(defs, b2)
	b3 := token.NewBorderDef(defs[2 * m - 1].Hash(), defs[0].Hash(), chainhash.Hash{})
	defs = append(defs, b3)

	for i := 0; i < m - 1; i++ {
		j := i + 1
		b := token.NewBorderDef(defs[i].Hash(), defs[j].Hash(), b0.Hash())
		defs = append(defs, b)

		b = token.NewBorderDef(defs[i + m].Hash(), defs[j + m].Hash(), b2.Hash())
		defs = append(defs, b)
	}
	polygon := token.NewPolygonDef([]token.LoopDef{{b0.Hash(), b1.Hash(), b2.Hash(), b3.Hash()}})
	defs = append(defs, polygon)
	uright := token.NewRightDef(chainhash.Hash{}, []byte("All Rights"), 3)
	defs = append(defs, uright)

	printdef(defs)

	fmt.Printf("\n\nvar coinToken = token.Token{\n\t" +
		"TokenType: 0,\n\t" +
		"Value: &token.NumToken{Val: 5000000000},\n\t" +
		"Rights: &chainhash.Hash{},\n}")

	// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
	// the main network, regression test network, and test network (version 3).
	// mainnet version = 0, testnet = 0x6F

	addr, err := btcutil.DecodeAddress(priv.PublicKey.ToAddress(0x6F), &chaincfg.TestNet3Params)
	if err != nil {
		fmt.Printf("Failed to generate pay-to-address script")
		os.Exit(1)
	}

	pkScript := make([]byte, 25)
	pkScript[0] = addr.Version()
	copy(pkScript[1:], addr.ScriptAddress())
	pkScript[21] = 0x41

	if err != nil {
		fmt.Printf("Failed to generate pay-to-address script")
		os.Exit(1)
	}

	var genesisCoinbaseTx = wire.MsgTx{
		Version: 1,
		TxDef: []token.Definition{},
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
				SignatureIndex: 0xffffffff,
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*wire.TxOut{
			{
				PkScript: pkScript,
			},
		},
		LockTime: 0,
	}
	genesisCoinbaseTx.TxOut[0].TokenType = 0
	genesisCoinbaseTx.TxOut[0].Value = &token.NumToken{Val: 0x12a05f200}
	genesisCoinbaseTx.TxOut[0].Rights = &chainhash.Hash{}

	var genesisInitPolygonTx = wire.MsgTx{
		Version: 1,
		TxDef: defs,
		TxIn: []*wire.TxIn{},
		TxOut: []*wire.TxOut{
			{
				PkScript: pkScript,
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
	var genesisMerkleRoot = merkles[len(merkles) - 1]

	// genesisBlock defines the genesis block of the block chain which serves as the
	// public transaction ledger for the main network.
	var genesisBlock = wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    0x10000000,
			PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
			MerkleRoot: *genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
			Timestamp:  time.Now(),
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&genesisBlock, 0x1f00ffff)
	var genesisHash = genesisBlock.Header.BlockHash()

	gotSig, _ := privKey.Sign(genesisHash[:])
	gotSigBytes := gotSig.Serialize()
	genesisCoinbaseTx.SignatureScripts = [][]byte{gotSigBytes}

	printCoinbase("genesisCoinbaseTx", gotSigBytes, true)

	fmt.Printf("\n\nvar polygonToken = token.Token{" +
		"\n\tTokenType: 3," +
		"\n\tValue: &token.HashToken{Hash: ")
	printhash(polygon.Hash())

	fmt.Printf("},\n\tRights: &")
	printhash(uright.Hash())
	fmt.Printf("," + "\n}")

	fmt.Printf("\n\nvar genesisInitPolygonTx = wire.MsgTx{" +
		"\n\tVersion: 1," +
		"\n\tTxDef: InitDefs," +
		"\n\tTxIn: []*wire.TxIn{}," +
		"\n\tTxOut: []*wire.TxOut{" +
		"\n\t\t{" +
		"\n\t\t\tToken: polygonToken," +
		"\n\t\t\tPkScript: []byte{" +
		"\n\t\t\t\t0x6f, 0x2f, 0xe0, 0xef, 0x92, 0x85, 0xa1, 0x0e, 0x86, 0x0c, 0x25, 0xe0," +
		"\n\t\t\t\t0x3c, 0x3f, 0xf8, 0x59, 0x93, 0xd3, 0xff, 0xc3, 0x5e, 0x41, 0x00, 0x00, 0x00," +
		"\n\t\t\t}," +
		"\n\t\t}," +
		"\n\t}," +
		"\n\tLockTime: 0," +
		"\n\t}")

	fmt.Printf("\n\nvar GenesisMerkleRoot = ")
	printhash(*genesisMerkleRoot)

	fmt.Printf("\n\nvar GenesisBlock = wire.MsgBlock{" +
		"\n\tHeader: wire.BlockHeader{" +
		"\n\t\tVersion:    0x10000000," +
		"\n\t\tPrevBlock:  chainhash.Hash{}," +
		"\n\t\tMerkleRoot: GenesisMerkleRoot," +
		"\n\t\tTimestamp:  time.Unix(0x%x, 0), " +
		"\n\t\tNonce:      %d," +
		"\n\t}," +
		"\n\tTransactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx}," +
		"\n}", genesisBlock.Header.Timestamp.Unix(), genesisBlock.Header.Nonce)

	fmt.Printf("\n\nvar creator = [20]byte{0x2f, 0xe0, 0xef, 0x92, 0x85, 0xa1, 0xe, 0x86, 0xc, 0x25," +
		"\n\t0xe0, 0x3c, 0x3f, 0xf8, 0x59, 0x93, 0xd3, 0xff, 0xc3, 0x5e, }")

	var minerBlock = wire.MingingRightBlock{
		Version:       0x10000000,
		PrevBlock:     chainhash.Hash{},
		BestBlock:     genesisHash,
		Timestamp:     genesisBlock.Header.Timestamp,
		Bits:          0x1f00ffff,
		Nonce:         0,
		BlackList:     make([]wire.BlackList, 0),
		Utxos:		   make([]wire.OutPoint, 0),
	}
	copy(minerBlock.Miner[:], addr.ScriptAddress())
	solveMinerBlock(&minerBlock)

	// genesisHash is the hash of the first block in the block chain for the main
	// network (genesis block)

//	var genesisHash = genesisBlock.BlockHash()
	fmt.Printf("\n\nvar  GenesisHash = []chainhash.Hash{\n")
	printhash(genesisHash)
	fmt.Printf(",\n")

	var genesisMinerHash = minerBlock.BlockHash()

	printhash(genesisMinerHash)
	fmt.Printf(",\n}")

	fmt.Printf("\n\nvar GenesisMinerBlock = wire.MingingRightBlock{" +
		"\n\tVersion:    GenesisBlock.Header.Version," +
		"\n\tPrevBlock:  chainhash.Hash{}," +
		"\n\tBestBlock: GenesisHash[0]," +
		"\n\tTimestamp:  GenesisBlock.Header.Timestamp, " +
		"\n\tBits:      0x%x," +
		"\n\tNonce:      %d," +
		"\n\tMiner: creator," +
	"\n}", minerBlock.Bits, minerBlock.Nonce)

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
//			Bits:       0x1f7fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
			Nonce:      0,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&regTestGenesisBlock, 0x1f7fffff)

	// regTestGenesisHash is the hash of the first block in the block chain for the
	// regression test network (genesis block).
//	var regTestGenesisHash = regTestGenesisBlock.BlockHash()
	var regTestGenesisHash = regTestGenesisBlock.Header.BlockHash()
	fmt.Printf("\n\nvar RegTestGenesisHash = []chainhash.Hash{\n")
	printhash(regTestGenesisHash)
	fmt.Printf(",\n")

	gotSig, _ = privKey.Sign(regTestGenesisHash[:])
	gotSigBytes = gotSig.Serialize()
	regTestGenesisBlock.Transactions[0].SignatureScripts = [][]byte{gotSigBytes}

	var regTestGenesisMinerBlock = wire.MingingRightBlock{
		Version:       0x10000000,
		PrevBlock:     chainhash.Hash{},
		BestBlock:     regTestGenesisHash,
		Timestamp:     regTestGenesisBlock.Header.Timestamp,
		Bits:          0x1f7fffff,
		Nonce:         0,
		BlackList:     make([]wire.BlackList, 0),
		Utxos:		   make([]wire.OutPoint, 0),
	}
	copy(regTestGenesisMinerBlock.Miner[:], addr.ScriptAddress())
	solveMinerBlock(&regTestGenesisMinerBlock)
	var regTestGenesisMinerHash = regTestGenesisMinerBlock.BlockHash()
	printhash(regTestGenesisMinerHash)
	fmt.Printf(",\n}\n\nvar RegTestGenesisMerkleRoot = GenesisMerkleRoot")

	printCoinbase("regGenesisCoinbaseTx", gotSigBytes, false)

	fmt.Printf("\n\nvar RegTestGenesisBlock = wire.MsgBlock{" +
		"\n\tHeader: wire.BlockHeader{" +
		"\n\t\tVersion:    0x10000000," +
		"\n\t\tPrevBlock:  chainhash.Hash{}," +
		"\n\t\tMerkleRoot: RegTestGenesisMerkleRoot," +
		"\n\t\tTimestamp:  time.Unix(0x%x, 0), " +
		"\n\t\tNonce:      %d," +
		"\n\t}," +
		"\n\tTransactions: []*wire.MsgTx{&regGenesisCoinbaseTx, &genesisInitPolygonTx}," +
		"\n}", regTestGenesisBlock.Header.Timestamp.Unix(), regTestGenesisBlock.Header.Nonce)

	fmt.Printf("\n\nvar RegTestGenesisMinerBlock = wire.MingingRightBlock{" +
		"\n\tVersion:    RegTestGenesisBlock.Header.Version," +
		"\n\tPrevBlock:  chainhash.Hash{}," +
		"\n\tBestBlock: RegTestGenesisHash[0]," +
		"\n\tTimestamp:  RegTestGenesisBlock.Header.Timestamp, " +
		"\n\tBits:      0x%x," +
		"\n\tNonce:      %d," +
		"\n\tMiner: creator," +
		"\n}", regTestGenesisMinerBlock.Bits, regTestGenesisMinerBlock.Nonce)

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
			Nonce:      0,                // 414098458
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&testNet3GenesisBlock, 0x1f00ffff)

	// testNet3GenesisHash is the hash of the first block in the block chain for the
	// test network (version 3).
//	var testNet3GenesisHash = testNet3GenesisBlock.BlockHash()
	var testNet3GenesisHash = testNet3GenesisBlock.Header.BlockHash()
	fmt.Printf("\n\nvar TestNet3GenesisHash = []chainhash.Hash{\n")
	printhash(testNet3GenesisHash)
	fmt.Printf(",\n")

	gotSig, _ = privKey.Sign(testNet3GenesisHash[:])
	gotSigBytes = gotSig.Serialize()
	testNet3GenesisBlock.Transactions[0].SignatureScripts = [][]byte{gotSigBytes}

	var testNet3GenesisMinerBlock = wire.MingingRightBlock{
		Version:       0x10000000,
		PrevBlock:     chainhash.Hash{},
		BestBlock:     testNet3GenesisHash,
		Timestamp:     testNet3GenesisBlock.Header.Timestamp,
		Bits:          0x1f00ffff,
		Nonce:         0,
		BlackList:     make([]wire.BlackList, 0),
		Utxos:		   make([]wire.OutPoint, 0),
	}
	copy(testNet3GenesisMinerBlock.Miner[:], addr.ScriptAddress())
	solveMinerBlock(&testNet3GenesisMinerBlock)
	var testNet3GenesisMinerHash = testNet3GenesisMinerBlock.BlockHash()
	printhash(testNet3GenesisMinerHash)
	fmt.Printf(",\n}\n\nvar TestNet3GenesisMerkleRoot = GenesisMerkleRoot")

	printCoinbase("test3netgenesisCoinbaseTx", gotSigBytes, false)

	fmt.Printf("\n\nvar TestNet3GenesisBlock = wire.MsgBlock{" +
		"\n\tHeader: wire.BlockHeader{" +
		"\n\t\tVersion:    0x10000000," +
		"\n\t\tPrevBlock:  chainhash.Hash{}," +
		"\n\t\tMerkleRoot: TestNet3GenesisMerkleRoot," +
		"\n\t\tTimestamp:  time.Unix(0x%x, 0), " +
		"\n\t\tNonce:      %d," +
		"\n\t}," +
		"\n\tTransactions: []*wire.MsgTx{&test3netgenesisCoinbaseTx, &genesisInitPolygonTx}," +
		"\n}", testNet3GenesisBlock.Header.Timestamp.Unix(), testNet3GenesisBlock.Header.Nonce)

	fmt.Printf("\n\nvar TestNet3GenesisMinerBlock = wire.MingingRightBlock{" +
		"\n\tVersion:    TestNet3GenesisBlock.Header.Version," +
		"\n\tPrevBlock:  chainhash.Hash{}," +
		"\n\tBestBlock: TestNet3GenesisHash[0]," +
		"\n\tTimestamp:  TestNet3GenesisBlock.Header.Timestamp, " +
		"\n\tBits:      0x%x," +
		"\n\tNonce:      %d," +
		"\n\tMiner: creator," +
		"\n}", testNet3GenesisMinerBlock.Bits, testNet3GenesisMinerBlock.Nonce)

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
			Nonce:      2,
		},
		Transactions: []*wire.MsgTx{&genesisCoinbaseTx, &genesisInitPolygonTx},
	}

	solveGenesisBlock(&simNetGenesisBlock, 0x1f7fffff)

	// simNetGenesisHash is the hash of the first block in the block chain for the
	// simulation test network.
//	var simNetGenesisHash = simNetGenesisBlock.BlockHash()
	var simNetGenesisHash = simNetGenesisBlock.Header.BlockHash()
	fmt.Printf("\n\nvar SimNetGenesisHash = []chainhash.Hash{\n")
	printhash(simNetGenesisHash)
	fmt.Printf(",\n")

	gotSig, _ = privKey.Sign(simNetGenesisHash[:])
	gotSigBytes = gotSig.Serialize()
	simNetGenesisBlock.Transactions[0].SignatureScripts = [][]byte{gotSigBytes}

	var simNetGenesisMinerBlock = wire.MingingRightBlock{
		Version:       0x10000000,
		PrevBlock:     chainhash.Hash{},
		BestBlock:     simNetGenesisHash,
		Timestamp:     simNetGenesisBlock.Header.Timestamp,
		Bits:          0x1f7fffff,
		Nonce:         0,
		BlackList:     make([]wire.BlackList, 0),
		Utxos:		   make([]wire.OutPoint, 0),
	}
	copy(simNetGenesisMinerBlock.Miner[:], addr.ScriptAddress())
	solveMinerBlock(&simNetGenesisMinerBlock)
	var simNetGenesisMinerHash = simNetGenesisMinerBlock.BlockHash()
	printhash(simNetGenesisMinerHash)

	fmt.Printf(",\n}\n\nvar SimNetGenesisMerkleRoot = GenesisMerkleRoot")
	printCoinbase("simnetgenesisCoinbaseTx", gotSigBytes, false)

	fmt.Printf("\n\nvar SimNetGenesisBlock = wire.MsgBlock{" +
		"\n\tHeader: wire.BlockHeader{" +
		"\n\t\tVersion:    0x10000000," +
		"\n\t\tPrevBlock:  chainhash.Hash{}," +
		"\n\t\tMerkleRoot: SimNetGenesisMerkleRoot," +
		"\n\t\tTimestamp:  time.Unix(0x%x, 0), " +
		"\n\t\tNonce:      %d," +
		"\n\t}," +
		"\n\tTransactions: []*wire.MsgTx{&simnetgenesisCoinbaseTx, &genesisInitPolygonTx}," +
		"\n}", simNetGenesisBlock.Header.Timestamp.Unix(), simNetGenesisBlock.Header.Nonce)

	fmt.Printf("\n\nvar SimNetGenesisMinerBlock = wire.MingingRightBlock{" +
		"\n\tVersion:    SimNetGenesisBlock.Header.Version," +
		"\n\tPrevBlock:  chainhash.Hash{}," +
		"\n\tBestBlock: SimNetGenesisHash[0]," +
		"\n\tTimestamp:  SimNetGenesisBlock.Header.Timestamp, " +
		"\n\tBits:      0x%x," +
		"\n\tNonce:      %d," +
		"\n\tMiner: creator," +
		"\n}", simNetGenesisMinerBlock.Bits, simNetGenesisMinerBlock.Nonce)
}

func printCoinbase(name string, gotSigBytes []byte, full bool) {
	if !full {
		fmt.Printf("\n\nvar %s = genesisCoinbaseTx", name)
		return
	}

	fmt.Printf("\n\nvar %s = wire.MsgTx{" +
		"\n\tVersion: 1," +
		"\n\tTxDef: []token.Definition{},", name)
	if full {
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
			"\n\t\t\tPkScript: []byte{"+
			"\n\t\t\t\t0x6f, 0x2f, 0xe0, 0xef, 0x92, 0x85, 0xa1, 0x0e, 0x86, 0x0c, 0x25, 0xe0,"+
			"\n\t\t\t\t0x3c, 0x3f, 0xf8, 0x59, 0x93, 0xd3, 0xff, 0xc3, 0x5e, 0x41, 0x00, 0x00, 0x00,"+
			"\n\t\t\t},"+
			"\n\t\t},"+
			"\n\t}," +
			"\n\tSignatureScripts: [][]byte { []byte{")
	} else {
		fmt.Printf("\n\tTxIn: genesisCoinbaseTx.TxIn,"+
			"\n\tTxOut: genesisCoinbaseTx.TxOut," +
			"\n\tSignatureScripts: [][]byte { []byte{")
	}

	// the first item in coinbase SignatureScripts is merkle root of signatures in the block
	// for genesis block, as there is no signature, it is zero hash
	for i := 0; i < 4; i++ {
		fmt.Printf("\n\t\t0, 0, 0, 0, 0, 0, 0, 0, ")
	}
/*
	for i := 0; i < len(gotSigBytes); i++ {
		if i % 8 == 0 {
			fmt.Printf("\n\t\t")
		}
		fmt.Printf("0x%02x, ", gotSigBytes[i])
	}
 */
	fmt.Printf("\n\t} }," +
		"\n\tLockTime: 0," +
		"\n\t}")
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

func printminerblock(blk wire.MingingRightBlock) {
	fmt.Printf("Header {\n\tVersion:%d,\n\tPrevBlock: %s\n\tBestBlock: %s\n\tTimestamp: 0x%x\n\tBits: 0x%x\n\tNonce: %d",
		blk.Version, blk.PrevBlock.String(), blk.BestBlock.String(), blk.Timestamp.Unix(),
		blk.Bits, blk.Nonce)
	fmt.Printf("\n\tMiner:[")
	fmt.Printf("0x%x, ", blk.Miner)
	fmt.Printf("]\n\tBlackList: %s\n", blk.BlackList)
}

func printblock(blk wire.MsgBlock) {
	fmt.Printf("Header {\n\tVersion:%d,\n\tPrevBlock: %s\n\tMerkleRoot: %s\n\tTimestamp: 0x%x\n\tNonce: %d\n\tTransactions:\n",
		blk.Header.Version, blk.Header.PrevBlock.String(), blk.Header.MerkleRoot.String(), blk.Header.Timestamp.Unix(),
		blk.Header.Nonce)
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
			fmt.Printf(",\n\t\t\tRights: ")

			printhash(*to.Rights)

			fmt.Printf(",\n\t\t\tPkScript: [")
			for _,r := range to.PkScript {
				fmt.Printf("0x%02x, ", r)
			}
			fmt.Printf("]\n\t\t}\n")
		}
		fmt.Printf("\n\t\tLockTime: %d\n\t}\n", t.LockTime)
	}
}


func printdef(def []token.Definition) {
	for _,f := range def {
		switch f.(type) {
		case *token.VertexDef:
			v := f.(*token.VertexDef)
			fmt.Printf("\n\t&token.VertexDef {\n\t\tLat: %d,\n\t\tLng: %d,\n\t},", v.Lat, v.Lng)
			break
		case *token.BorderDef:
			v := f.(*token.BorderDef)
			fmt.Printf("\n\t&token.BorderDef {\n\t\tFather: ");
			if v.Father.IsEqual(&chainhash.Hash{}) {
				fmt.Printf("chainhash.Hash{}")
			} else {
				printhash(v.Father)
			}
			fmt.Printf(",\n\t\tBegin: ")
			printhash(v.Begin)
			fmt.Printf(",\n\t\tEnd: ")
			printhash(v.End)
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