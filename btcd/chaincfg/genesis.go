// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"btcd/wire"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"omega"
)

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network. ----
var GenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x4743546d: omega.MainNetGenesisMerkleRoot,
}

// GenesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var GenesisBlock = map[uint32]*wire.MsgBlock{
	0x4743546d: &omega.MainNetGenesisBlock,
}

var GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x4743546d: &omega.MainNetGenesisMinerBlock,
}

// GenesisHash is the hash of the first block in the block chain for the main
// network (genesis block). ----
var GenesisHash = map[uint32]*chainhash.Hash{
	0x4743546d: &omega.MainNetGenesisHash[0],
}
var GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x4743546d: &omega.MainNetGenesisHash[1],
}

// RegTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var RegTestGenesisHash = map[uint32]chainhash.Hash{
	0x47435472: chainhash.Hash{},
}
var RegTestGenesisMinerHash = map[uint32]chainhash.Hash{
	0x47435472: chainhash.Hash{},
}

// RegTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var RegTestGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x47435472: chainhash.Hash{},
}

// TestNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var TestNet3GenesisHash = map[uint32]*chainhash.Hash{
	0x47435474: &omega.TestNetGenesisHash[0],
	0x4e585574: &omega.TestNetGenesisHash4e585574[0],
}
var TestNet3GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x47435474: &omega.TestNetGenesisHash[1],
	0x4e585574: &omega.TestNetGenesisHash4e585574[1],
}

// TestNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var TestNet3GenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x47435474: omega.TestNetGenesisMerkleRoot,
	0x4e585574: omega.TestNetGenesisMerkleRoot4e585574,
}

// TestNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var TestNet3GenesisBlock = map[uint32]*wire.MsgBlock{
	0x47435474: &omega.TestNetGenesisBlock,
	0x4e585574: &omega.TestNetGenesisBlock4e585574,
}
var TestNet3GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x47435474: &omega.TestNetGenesisMinerBlock,
	0x4e585574: &omega.TestNetGenesisMinerBlock4e585574,
}

// SimNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var SimNetGenesisHash = map[uint32]*chainhash.Hash{
	0x47435473: &chainhash.Hash{},
	0x4743546d: &chainhash.Hash{},
}
var SimNetGenesisMinerHash = map[uint32]*chainhash.Hash{
	0x47435473: &chainhash.Hash{},
	0x4743546d: &chainhash.Hash{},
}

// SimNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var SimNetGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x47435473: chainhash.Hash{},
	0x4743546d: chainhash.Hash{},
}
