// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package consensus

import (
	"bytes"
	"github.com/btcsuite/btcd/wire"
	"io"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
)

// difficulty target for new node submission is 1 min.
// committee generate a block every 3 sec. (target time)
// MINER_RORATE_FREQ is 40 blocks

// a POW block must have upto DefaultCommitteeSize - 1 nominees in its coinbase (i.e., in output's PKscript with output amount of 0)
// under following priority rule: all the NewNode in the POW block immediately preceding this block, The miner candidate.

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeaderX struct {
	wire.BlockHeader
	// new committee member
	Newnode   [20]byte          // address hash of new member for next committee

	// signatures
	Nsign     uint16            // number of signatures (we only need a byte, make it 2 byte so that the entire header size is even bytes)
	Signers   []*btcec.PublicKey		// signers public key. 0 = oldest. # = CommitteeSize
	Sigs      []*[65]byte 		// signatures. # = Nsign
}

// BlockHash computes the block identifier hash for the given block header.
func (h *BlockHeaderX) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, wire.MaxBlockHeaderPayload))
	_ = writeBlockHeaderX(buf, 0, h)

	return chainhash.DoubleHashH(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeaderX) BtcDecode(r io.Reader, pver uint32, enc wire.MessageEncoding) error {
	return readBlockHeaderX(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeaderX) BtcEncode(w io.Writer, pver uint32, enc wire.MessageEncoding) error {
	return writeBlockHeaderX(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeaderX) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeaderX(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeaderX) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeaderX(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, nonce int32) *BlockHeaderX {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	h := wire.BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		ContractExec:  0,
		Nonce:      nonce,
	}
	x := BlockHeaderX {}
	x.BlockHeader = h
	x.Signers = make([]*btcec.PublicKey, 0)
	x.Sigs = make([]*[65]byte, 0)
	return &x
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
func readBlockHeaderX(r io.Reader, pver uint32, bh *BlockHeaderX) error {
	return common.ReadElements(r, &bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		(*common.Uint32Time)(&bh.Timestamp), &bh.ContractExec, &bh.Nonce)
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
func writeBlockHeaderX(w io.Writer, pver uint32, bh *BlockHeaderX) error {
	sec := uint32(bh.Timestamp.Unix())
	return common.WriteElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		sec, bh.ContractExec, bh.Nonce)
}