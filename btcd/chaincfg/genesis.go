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
	0x4e585553: omega.MainNetGenesisMerkleRoot,
	0x4743546d: omega.MainNetGenesisMerkleRoot4743546d,
	0x484f564d: omega.MainNetGenesisMerkleRoot484f564d,
}

// GenesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var GenesisBlock = map[uint32]*wire.MsgBlock{
	0x4e585553: &omega.MainNetGenesisBlock,
	0x4743546d: &omega.MainNetGenesisBlock4743546d,
	0x484f564d: &omega.MainNetGenesisBlock484f564d,
}

var GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x4e585553: &omega.MainNetGenesisMinerBlock,
	0x4743546d: &omega.MainNetGenesisMinerBlock4743546d,
	0x484f564d: &omega.MainNetGenesisMinerBlock484f564d,
}

// GenesisHash is the hash of the first block in the block chain for the main
// network (genesis block). ----
var GenesisHash = map[uint32]*chainhash.Hash{
	0x4e585553: &omega.MainNetGenesisHash[0],
	0x4743546d: &omega.MainNetGenesisHash4743546d[0],
	0x484f564d: &omega.MainNetGenesisHash484f564d[0],
}
var GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x4e585553: &omega.MainNetGenesisHash[1],
	0x4743546d: &omega.MainNetGenesisHash4743546d[1],
	0x484f564d: &omega.MainNetGenesisHash484f564d[1],
}

// RegTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var RegTestGenesisHash = map[uint32]chainhash.Hash{
	0x4e585572: chainhash.Hash{},
	0x47435474: chainhash.Hash{},
}
var RegTestGenesisMinerHash = map[uint32]chainhash.Hash{
	0x4e585572: chainhash.Hash{},
	0x47435474: chainhash.Hash{},
}

// RegTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var RegTestGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x4e585572: chainhash.Hash{},
	0x47435474: chainhash.Hash{},
}

// TestNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var TestNet3GenesisHash = map[uint32]*chainhash.Hash{
	0x4e585574: &omega.TestNetGenesisHash[0],
	0x47435474: &omega.TestNetGenesisHash47435474[0],
	0x484f5674: &omega.TestNetGenesisHash484f5674[0],
}
var TestNet3GenesisMinerHash = map[uint32]*chainhash.Hash{
	0x4e585574: &omega.TestNetGenesisHash[1],
	0x47435474: &omega.TestNetGenesisHash47435474[1],
	0x484f5674: &omega.TestNetGenesisHash484f5674[1],
}

// TestNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var TestNet3GenesisBlock = map[uint32]*wire.MsgBlock{
	0x4e585574: &omega.TestNetGenesisBlock,
	0x47435474: &omega.TestNetGenesisBlock47435474,
	0x484f5674: &omega.TestNetGenesisBlock484f5674,
}
var TestNet3GenesisMinerBlock = map[uint32]*wire.MingingRightBlock{
	0x4e585574: &omega.TestNetGenesisMinerBlock,
	0x47435474: &omega.TestNetGenesisMinerBlock47435474,
	0x484f5674: &omega.TestNetGenesisMinerBlock484f5674,
}

// SimNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var SimNetGenesisHash = map[uint32]*chainhash.Hash{
	0x4e585573: &chainhash.Hash{},
	0x47435474: &chainhash.Hash{},
}
var SimNetGenesisMinerHash = map[uint32]*chainhash.Hash{
	0x4e585573: &chainhash.Hash{},
	0x47435474: &chainhash.Hash{},
}

// SimNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var SimNetGenesisMerkleRoot = map[uint32]chainhash.Hash{
	0x4e585573: chainhash.Hash{},
	0x47435474: chainhash.Hash{},
}
