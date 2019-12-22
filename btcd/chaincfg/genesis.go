// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"github.com/btcsuite/omega"
)

var InitDefs = omega.InitDefs

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network. ----
var genesisMerkleRoot = omega.GenesisMerkleRoot

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = omega.GenesisBlock
var genesisMinerBlock = omega.GenesisMinerBlock

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block). ----
var genesisHash = omega.GenesisHash[0]
var genesisMinerHash = omega.GenesisHash[1]

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var regTestGenesisHash = omega.RegTestGenesisHash[0]
var regTestGenesisMinerHash = omega.RegTestGenesisHash[1]

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = omega.RegTestGenesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = omega.RegTestGenesisBlock
var regTestGenesisMinerBlock = omega.RegTestGenesisMinerBlock

// testNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNet3GenesisHash = omega.TestNet3GenesisHash[0]
var testNet3GenesisMinerHash = omega.TestNet3GenesisHash[1]

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet3GenesisMerkleRoot = omega.TestNet3GenesisMerkleRoot

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet3GenesisBlock = omega.TestNet3GenesisBlock
var testNet3GenesisMinerBlock = omega.TestNet3GenesisMinerBlock

// simNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var simNetGenesisHash = omega.SimNetGenesisHash[0]
var simNetGenesisMinerHash = omega.SimNetGenesisHash[1]

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var simNetGenesisMerkleRoot = omega.SimNetGenesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = omega.SimNetGenesisBlock
var simNetGenesisMinerBlock = omega.SimNetGenesisMinerBlock
