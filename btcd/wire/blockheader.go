// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
)

const (
	CommitteeSize				= 3			// 3
	MINER_RORATE_FREQ			= 20		// rotate committee every MINER_RORATE_FREQ blocks
	DESIRABLE_MINER_CANDIDATES	= 20		// the desirable number of miner candidate we want to have
	MinerGap					= 3			// a miner must wait between to candidacies
	SCALEFACTORCAP				= 48
)

// MaxBlockHeaderPayload is the maximum number of bytes a block header can be.
// Version 4 bytes + Timestamp 4 bytes + Bits 4 bytes + Nonce 4 bytes +
// PrevBlock and MerkleRoot hashes.
//const MaxBlockHeaderPayload = 16 + (chainhash.HashSize * 2)
const MaxBlockHeaderPayload = 24 + (chainhash.HashSize * 2)
const MaxMinerBlockHeaderPayload = 5000


type BlackList struct {
	// blacklist format：
	Address [20]byte
	Height uint32
	Hashes [2]chainhash.Hash
	Signatures [2][]byte
}

func (b * BlackList) Read(r io.Reader) error {
	if err := common.ReadElement(r, &b.Address); err != nil {
		return err
	}
	if err := common.ReadElement(r, &b.Height); err != nil {
		return err
	}
	if err := common.ReadElement(r, &b.Hashes[0]); err != nil {
		return err
	}
	s, err := common.ReadVarBytes(r, 0, 65, "signature")
	b.Signatures[0] = s
	if err != nil {
		return err
	}

	if err := common.ReadElement(r, &b.Hashes[1]); err != nil {
		return err
	}
	b.Signatures[1], err = common.ReadVarBytes(r, 0, 65, "signature")
	if err != nil {
		return err
	}

	return nil
}


func (b * BlackList) Write(w io.Writer) error {
	if err := common.WriteElement(w, b.Address); err != nil {
		return err
	}
	if err := common.WriteElement(w, b.Height); err != nil {
		return err
	}
	if err := common.WriteElement(w, b.Hashes[0]); err != nil {
		return err
	}
	if err := common.WriteVarBytes(w, 0, b.Signatures[0]); err != nil {
		return err
	}

	if err := common.WriteElement(w, b.Hashes[1]); err != nil {
		return err
	}
	if err := common.WriteVarBytes(w, 0, b.Signatures[1]); err != nil {
		return err
	}

	return nil
}

// we use a dual block chain structure. one is Tx chain (normal block chain), one is committee candidate chain
// MingingRightBlock is miner candidate chain struct
type MingingRightBlock struct {
	// Version of the block. This is not the same as the protocol version.
	Version int32

	// Hash of the previous MingingRightBlock block in the block chain.
	PrevBlock chainhash.Hash

	// ReferredBlock hash of regular block. must be a block after ReferredBlock in the previous MingingRightBlock
	// and before half way between the ReferredBlock in the previous MingingRightBlock and most recent regular block (BestBlock)
	ReferredBlock chainhash.Hash

	// The best main chain block known to the miner. Must not be before the BestBlock of the previous MingingRightBlock.
	BestBlock chainhash.Hash

	Timestamp time.Time

	// Difficulty target
	Bits uint32

	// Nonce used to generate the Miner,
	Nonce int32

	// new committee member.
	Miner []byte // address (pubkey hash) of new member for next committee

	Connection []byte	// connection info. either an IP:port address or an RSA pubkey

	BlackList []BlackList		  // the double signers and proof

	// the following condition must be met before MingingRightBlock may be accepted
	// hash of: PrevBlock + ReferredBlock + BestBlock + Miner + Nonce must be within Bits Difficulty target, which is
	// set periodically according to MingingRightBlock chain data. The target is to set based on the number of miner
	// candidates as decided by the height of MingingRightBlock chain and the height of MingingRightBlock referred by
	// latest committee in main chain upto ReferredBlock. If this is below MINER_RORATE_FREQ, the difficulty
	// is set to generate 2 MingingRightBlock every MINER_RORATE_FREQ block time. Once number of miner candidates reaches
	// MINER_RORATE_FREQ, the difficulty increases 20% for every one more candidate.

	// if current block is a POW block, the next block is either a POW block or a rotation block

	// this struct is broadcasted to everyone with the longest-chain-win rule
}

// difficulty target for new node submission is 1 min.
// committee generate a block every 3 sec. (target time)
// MINER_RORATE_FREQ is 40 blocks

// a POW block must have upto DefaultCommitteeSize - 1 nominees in its coinbase (i.e., in output's PKscript with output amount of 0)
// under following priority rule: all the NewNode in the POW block immediately preceding this block, The miner candidate.

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block header in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference the hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	Timestamp time.Time

	// ContractExec the exact number of VM steps taken to execute all contracts (not including signature validation)
	// This is set by this block's miner, and verified by those who accept the block. The purpose is to prevent
	// spammer who sends out block containing never ending contracts. It is up to each miner to decide the max number
	// of steps a contract is allowed to execute.
	ContractExec uint64

	// Nonce used to generate the block,
	// if this is < 0 && > -MINER_RORATE_FREQ, the block is generated by a committee without a Miner.
	// -Nonce = the number of blocks generated by the active miner(s). This value =
	// -((-Nonce of previous + 1) % MINER_RORATE_FREQ) if Nonce of previous <= 0, or is >= 0
	// if Nonce of previous > 0.
	// if this is == - MINER_RORATE_FREQ, the block is generated by a committee with a rotation of Miner,
	// Nonce = - height (lower 31 bits) of the Miner block providing the new miner.
	// if this is > 0, this block is generated with a POW proof when the committee stales.
	// the required difficulty is the Bits in miner block of the last rotation before this
	// block.
	Nonce int32			// always present
}

// when block is generated by a committee, the coin base Tx includes payment to committee members.
// its input includes signatures of miners who signed the Tx and signature of witnesses
// witnesses will sign the block only after the block has been decided by the committee
// every MINER_RORATE_FREQ blocks, the most senior member is removed from committee and the
// fisrt miner candidate in MingingRightBlock is added to the committee (if he is not in the committee)

// when block is generated by POW, the miner alone abtains all the award, and then a new committee
// is form in the order as below (most senior frst). Upto MINER_RORATE_FREQ - 2 miners of the miners
// of immediate preceeding POW blocks, miner of this block, miner candidates in MingingRightBlock.

// blockHeaderLen is a constant that represents the number of bytes for a block
// header.
const blockHeaderLen = 84	// or 108 with Bits & IP
const minerBlockLen = 180	// max len. if IPv6 address & port

// BlockHash computes the block identifier hash for the given block header.
func (h *BlockHeader) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, MaxBlockHeaderPayload))
	_ = writeBlockHeader(buf, 0, h)

	return chainhash.DoubleHashH(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, nonce int32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		ContractExec:       0,
		Nonce:      nonce,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {
	return common.ReadElements(r, &bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		(*common.Uint32Time)(&bh.Timestamp), &bh.ContractExec, &bh.Nonce)
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	return common.WriteElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		sec, bh.ContractExec, bh.Nonce)
}

// BlockHash computes the block identifier hash for the given block header.
func (h *MingingRightBlock) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, minerBlockLen))
	_ = writeMinerBlock(buf, 0, h)

	return chainhash.DoubleHashH(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *MingingRightBlock) BtcDecode(r io.Reader, pver uint32, _ MessageEncoding) error {
	return readMinerBlock(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *MingingRightBlock) BtcEncode(w io.Writer, pver uint32, _ MessageEncoding) error {
	return writeMinerBlock(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *MingingRightBlock) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readMinerBlock(r, 0, h)
}

func (h *MingingRightBlock) SerializeSize() int {
	return minerBlockLen
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *MingingRightBlock) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeMinerBlock(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewMinerNodeBlock(version int32, prevHash, referredHash, bestHash *chainhash.Hash,
	bits uint32, nonce int32, address []byte, ip string) *MingingRightBlock {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &MingingRightBlock{
		Version:       version,
		PrevBlock:     *prevHash,
		ReferredBlock: *referredHash,
		BestBlock:     *bestHash,
		Timestamp:     time.Unix(time.Now().Unix(), 0),
		Bits:          bits,
		Nonce:         nonce,
		Miner:         address,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readMinerBlock(r io.Reader, pver uint32, bh *MingingRightBlock) error {
	if err := common.ReadElements(r, &bh.Version, &bh.PrevBlock, &bh.ReferredBlock,
		&bh.BestBlock, (*common.Uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Nonce); err != nil {
		return err
	}
	t, err := common.ReadVarBytes(r, 0, 20, "Miner")
	if err != nil {
		return err
	}
	bh.Miner = t
	t, err = common.ReadVarBytes(r, 0, 80, "Connection")
	if err != nil {
		return err
	}
	bh.Connection = t

	d, err := common.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	bh.BlackList = make([]BlackList, d)

	for i := 0; i < int(d); i++ {
		if err := bh.BlackList[i].Read(r); err != nil {
			return err
		}
	}

	return nil
}

// writeBlockHeader writes a miner block to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeMinerBlock(w io.Writer, pver uint32, bh *MingingRightBlock) error {
	sec := uint32(bh.Timestamp.Unix())

	if err := common.WriteElements(w, bh.Version, &bh.PrevBlock,
		&bh.ReferredBlock,	bh.BestBlock, sec, bh.Bits, bh.Nonce); err != nil {
		return err
	}
	if err := common.WriteVarBytes(w, 0, bh.Miner); err != nil {
		return err
	}
	if err := common.WriteVarBytes(w, 0, bh.Connection); err != nil {
		return err
	}

	err := common.WriteVarInt(w, 0, uint64(len(bh.BlackList)))
	if err != nil {
		return err
	}

	for _, p := range bh.BlackList {
		if err := p.Write(w); err != nil {
			return err
		}
	}

	return nil
}

type MinerBlock struct {		// equivalent of btcutil.Block
	msgBlock *MingingRightBlock
	serializedBlock          []byte          // Serialized bytes for the block
	height int32
	hash * chainhash.Hash
}

func NewMinerBlockFromBlockAndBytes(msgBlock *MingingRightBlock, serializedBlock []byte) *MinerBlock {
	return &MinerBlock{
		msgBlock:        msgBlock,
		serializedBlock: serializedBlock,
		height:     -1,
	}
}

func (b * MinerBlock) MsgBlock() *MingingRightBlock {
	return b.msgBlock
}

func (b * MinerBlock) Hash() * chainhash.Hash {
	if b.hash != nil {
		return b.hash
	}

	h := b.msgBlock.BlockHash()
	b.hash = &h

	return b.hash
}

func (b * MinerBlock) SetHeight(h int32) {
	b.height = h
}

func (b *MinerBlock) Height() int32 {
	return b.height
}

// Bytes returns the serialized bytes for the Block.  This is equivalent to
// calling Serialize on the underlying wire.MsgBlock, however it caches the
// result so subsequent calls are more efficient.
func (b *MinerBlock) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlock) != 0 {
		return b.serializedBlock, nil
	}

	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, b.msgBlock.SerializeSize()))
	err := b.msgBlock.Serialize(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlock = serializedBlock
	return serializedBlock, nil
}

func NewMinerBlock(b *MingingRightBlock) * MinerBlock {
	return &MinerBlock { b, nil,int32(-1),nil }
}

func (msg *MingingRightBlock) Command() string {
	return CmdMinerBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MingingRightBlock) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxMinerBlockHeaderPayload
}
