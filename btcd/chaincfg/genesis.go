// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/gct/btcd/wire"
	"github.com/omegasuite/gct/omega"
)

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network. ----
var GenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x956ca476: omega.MainNetGenesisMerkleRoot,
	0xA117FE3D: omega.MainNetGenesisMerkleRootA117FE3D,
}

// GenesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var GenesisBlock = map[uint32]*wire.MsgBlock{
	0x956ca476: &omega.MainNetGenesisBlock,
	0xA117FE3D: &omega.MainNetGenesisBlockA117FE3D,
}

var GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x956ca476: &omega.MainNetGenesisMinerBlock,
	0xA117FE3D: &omega.MainNetGenesisMinerBlockA117FE3D,
}

// GenesisHash is the hash of the first block in the block chain for the main
// network (genesis block). ----
var GenesisHash = map[uint32]*chainhash.Hash{
	0x956ca476: &omega.MainNetGenesisHash[0],
	0xA117FE3D: &omega.MainNetGenesisHashA117FE3D[0],
}
var GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x956ca476: &omega.MainNetGenesisHash[1],
	0xA117FE3D: &omega.MainNetGenesisHashA117FE3D[1],
}

// RegTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var RegTestGenesisHash = map[uint32]chainhash.Hash{
	0x956ca476: chainhash.Hash{},
	0xA117FE3D: chainhash.Hash{},
}
var RegTestGenesisMinerHash = map[uint32]chainhash.Hash{
	0x956ca476: chainhash.Hash{},
	0xA117FE3D: chainhash.Hash{},
}

// RegTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var RegTestGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x956ca476: chainhash.Hash{},
	0xA117FE3D: chainhash.Hash{},
}

// TestNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var TestNet3GenesisHash = map[uint32]*chainhash.Hash{
	0x956ca476: &omega.TestNetGenesisHash[0],
	0xA117FE3D: &omega.TestNetGenesisHashA117FE3D[0],
}
var TestNet3GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x956ca476: &omega.TestNetGenesisHash[1],
	0xA117FE3D: &omega.TestNetGenesisHashA117FE3D[1],
}

// TestNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var TestNet3GenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x956ca476: omega.TestNetGenesisMerkleRoot,
	0xA117FE3D: omega.TestNetGenesisMerkleRootA117FE3D,
}

// TestNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var TestNet3GenesisBlock = map[uint32]*wire.MsgBlock{
	0x956ca476: &omega.TestNetGenesisBlock,
	0xA117FE3D: &omega.TestNetGenesisBlockA117FE3D,
}
var TestNet3GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x956ca476: &omega.TestNetGenesisMinerBlock,
	0xA117FE3D: &omega.TestNetGenesisMinerBlockA117FE3D,
}

// SimNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var SimNetGenesisHash = map[uint32]*chainhash.Hash{
	0x956ca476: &chainhash.Hash{},
	0xA117FE3D: &chainhash.Hash{},
}
var SimNetGenesisMinerHash = map[uint32]*chainhash.Hash{
	0x956ca476: &chainhash.Hash{},
	0xA117FE3D: &chainhash.Hash{},
}

// SimNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var SimNetGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x956ca476: chainhash.Hash{},
	0xA117FE3D: chainhash.Hash{},
}

// SVP
var svpgenesisBlock = omega.MainNetGenesisBlock
var svpgenesisMinerBlock = omega.MainNetGenesisMinerBlock
var svpgenesisHash = omega.MainNetGenesisHash[0]
var svpgenesisMinerHash = omega.MainNetGenesisHash[1]
var svptestNetGenesisBlock = omega.TestNetGenesisBlock
var svptestNetGenesisMinerBlock = omega.TestNetGenesisMinerBlock
var svptestNetGenesisHash = omega.TestNetGenesisHash[0]
var svptestNetGenesisMinerHash = omega.TestNetGenesisHash[1]
