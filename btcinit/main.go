// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"btcd/blockchain"
	"btcd/chaincfg"
	"btcd/wire"
	"btcd/wire/common"
	"btcutil"
	"btcutil/base58"
	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"math/big"
	_ "net/http/pprof"
	"omega/token"
	"os"
	"time"
)

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

const BaseSubsidy = 0x108e8d71

func main() {
	fmt.Printf("\n\nvar coinToken = token.Token{\n\t"+
		"TokenType: 0,\n\t"+
		"Value: &token.NumToken{Val: %d},\n\t"+
		"Rights: &chainhash.Hash{},\n}", BaseSubsidy)

	addresses := map[common.OmegaNet][2]string{
		common.MainNet: {"1MsbUzMXZVVVxQ9ySYHvhoq4Ky6zeNwCej"},
		common.TestNet: {"n2PYn3SWNWvkjWdbA7GJXj3PBxhhZqM8D8"},
	}
	/*
		Bitcoin Address (Compressed)        1MsbUzMXZVVVxQ9ySYHvhoq4Ky6zeNwCej
		Bitcoin Testnet Address (Compressed)        n2PYn3SWNWvkjWdbA7GJXj3PBxhhZqM8D8
		Public Key Bytes (Compressed)       02808C7D7D6B96DB22EB00D2CF44A0F3CCCD79ED4A787BA9C1D9E1BB1B51698C0D
		Public Key Base64 (Compressed)      AoCMfX1rltsi6wDSz0Sg88zNee1KeHupwdnhuxtRaYwN

		Bitcoin Address (Uncompressed)      1GNqnebmBQyBE1DkZf7VgMo9Ur8EruLGg6
		Bitcoin Testnet Address (Uncompressed)      mvto5hgjzSQS17hNHE5sWH1ULqiwhDz1Eg
		Public Key Bytes (Uncompressed)     04808C7D7D6B96DB22EB00D2CF44A0F3CCCD79ED4A787BA9C1D9E1BB1B51698C0
		D02E3DABC778B1A75DD58F5D2EF8605ED5368B50ACEBA46437F1FAEF3D566F104
		Public Key Base64 (Uncompressed)    BICMfX1rltsi6wDSz0Sg88zNee1KeHupwdnhuxtRaYwNAuPavHeLGnXdWPXS74YF7VNotQrOukZDfx+u89Vm8QQ=

		Private Key WIFC (Compressed)       L5aGAxizFoBrNk42Qw4fYUdDT47KcwsJjqQuJZXAepG4A6asTZ3f
		Private Key WIF (Uncompressed)      5Ki4teYiX62Z2kjpu6TCuSk6YH7RA3v5vfA3LPKcieScc9sg9Ti
		Private Key Bytes                   F9458AF3932D2E019FF4AFC3B9D0012649A5E3529366D831FB4DB0D4F33F17B8
		Private Key Base64                  +UWK85MtLgGf9K/DudABJkml41KTZtgx+02w1PM/F7g=
		Bitcoin TestNet Address Private Key WIF (Uncompressed)        93UhUPNG7K6gzpF7XSM7n3J4BwU8KDTHGc1zR1g84PBfPH6RLUn
		Bitcoin TestNet Address Private Key WIF (Compressed)        cVwFdsiqgrt7YBXHoLsnuo8H5HQjHPxzosZNQyyg9vv4QqeMcR9o
	*/

	params := map[common.OmegaNet]*chaincfg.Params{
		common.MainNet: &chaincfg.MainNetParams,
		common.TestNet: &chaincfg.TestNet3Params,
	}
	names := map[common.OmegaNet]string{
		common.MainNet: "MainNet",
		common.TestNet: "TestNet",
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

		if err != nil {
			fmt.Printf("Failed to generate pay-to-address script")
			os.Exit(1)
		}

		var genesisCoinbaseTx = wire.MsgTx{
			Version: 0x31,
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
		genesisCoinbaseTx.TxOut[0].Value = &token.NumToken{Val: BaseSubsidy}
		genesisCoinbaseTx.TxOut[0].Rights = nil

		t1 := btcutil.NewTx(&genesisCoinbaseTx)
		t1.SetIndex(0)

		merkles := blockchain.BuildMerkleTreeStore([]*btcutil.Tx{t1}, false, wire.Version1)

		// genesisMerkleRoot is the hash of the first transaction in the genesis block
		// for the main network.
		var genesisMerkleRoot = merkles[len(merkles)-1]

		witnessMerkleTree := blockchain.BuildMerkleTreeStore([]*btcutil.Tx{t1}, true, wire.Version1)
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
			Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
		}

		// because wire.DifficultyRatio is 2, so exp. portion of PowLimitBits is dec. by 2
		solveGenesisBlock(&genesisBlock, params[net].PowLimitBits)
		var genesisHash = genesisBlock.Header.BlockHash()

		genesisCoinbaseTx.SignatureScripts = [][]byte{(*witnessMerkleRoot)[:]}

		printCoinbase(params[net].Name+"coinbaseTx", &genesisCoinbaseTx)

		fmt.Printf("\n\nvar " + names[net] + "GenesisMerkleRoot = ")
		printhash(*genesisMerkleRoot)

		fmt.Printf("\n\nvar "+names[net]+"GenesisBlock = wire.MsgBlock{"+
			"\n\tHeader: wire.BlockHeader{"+
			"\n\t\tVersion:    0x10000,"+
			"\n\t\tPrevBlock:  chainhash.Hash{},"+
			"\n\t\tMerkleRoot: "+names[net]+"GenesisMerkleRoot,"+
			"\n\t\tTimestamp:  time.Unix(0x%x, 0), "+
			"\n\t\tNonce:      %d,"+
			"\n\t},"+
			"\n\tTransactions: []*wire.MsgTx{&"+params[net].Name+"coinbaseTx},"+
			"\n}", genesisBlock.Header.Timestamp.Unix(), genesisBlock.Header.Nonce)

		var minerBlock = wire.MingingRightBlock{
			Version:       0x10000,
			PrevBlock:     chainhash.Hash{},
			BestBlock:     genesisHash,
			Timestamp:     genesisBlock.Header.Timestamp,
			Bits:          params[net].PowLimitBits,
			Nonce:         0,
			Miner:         miner,
			Connection:    []byte("gctoid.com"),
			Utxos:         nil,
			ContractLimit: 10000,
			MeanTPH:       1000,
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

		fmt.Printf("\n\nvar "+names[net]+"GenesisMinerBlock = wire.MingingRightBlock{"+
			"\n\tVersion: 0x10000,"+
			"\n\tPrevBlock:  chainhash.Hash{},"+
			"\n\tBestBlock: "+names[net]+"GenesisHash[0],"+
			"\n\t\tTimestamp:  time.Unix(0x%x, 0), "+
			"\n\tBits:      0x%x,"+
			"\n\tNonce:      %d,"+
			"\n\tContractLimit: 10000,"+
			"\n\tMeanTPH: 1000,"+
			"\n\tConnection:      []byte{", minerBlock.Timestamp.Unix(), minerBlock.Bits, minerBlock.Nonce)

		printKey(minerBlock.Connection)

		fmt.Printf("}," +
			"\n\tBlackList: []wire.BlackList{}," +
			"\n\tUtxos: []wire.OutPoint{}," +
			"\n\tMiner: " + params[net].Name + "creator," +
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

func printCoinbase(name string, tx *wire.MsgTx) {
	fmt.Printf("\n\nvar %s = wire.MsgTx{"+
		"\n\tVersion: 0x31,"+
		"\n\tTxDef: []token.Definition{},", name)
	fmt.Printf("\n\tTxIn: []*wire.TxIn{" +
		"\n\t\t{" +
		"\n\t\t\tPreviousOutPoint: wire.OutPoint{" +
		"\n\t\t\tHash:  chainhash.Hash{}," +
		"\n\t\t\tIndex: 0," +
		"\n\t\t}," +
		"\n\t\tSignatureIndex: 0xffffffff," +
		"\n\t\tSequence: 0xffffffff," +
		"\n\t}," +
		"\n\t}," +
		"\n\tTxOut: []*wire.TxOut{" +
		"\n\t\t{" +
		"\n\t\t\tToken:coinToken," +
		"\n\t\t\tPkScript: []byte{")

	for i := 0; i < len(tx.TxOut[0].PkScript); i++ {
		if i%8 == 0 {
			fmt.Printf("\n\t\t\t\t")
		}
		fmt.Printf("0x%02x, ", tx.TxOut[0].PkScript[i])
	}

	fmt.Printf("\n\t\t\t}," +
		"\n\t\t}," +
		"\n\t}," +
		"\n\tSignatureScripts: [][]byte { []byte{")

	for i := 0; i < len(tx.SignatureScripts[0]); i++ {
		if i%8 == 0 {
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
	for _, b := range hb {
		if (i % 8) == 0 {
			fmt.Printf("\n\t\t")
		}
		i++
		fmt.Printf("0x%02x, ", b)
	}
	fmt.Printf("\n\t}")
}
