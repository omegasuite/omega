// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	"bytes"
	"io"

	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/omega/token"
)

// TxIndexUnknown is the value returned for a transaction index that is unknown.
// This is typically because the transaction has not been inserted into a block
// yet.
const TxIndexUnknown = -1

// Tx defines a bitcoin transaction that provides easier and more efficient
// manipulation of raw transactions.  It also memoizes the hash for the
// transaction on its first access so subsequent accesses don't have to repeat
// the relatively expensive hashing operations.
type Tx struct {
	msgTx         *wire.MsgTx     // Underlying MsgTx
	txHash        *chainhash.Hash // Cached transaction hash
	txHashSignature *chainhash.Hash // Cached transaction witness hash
	txIndex       int             // Position within a block or TxIndexUnknown
	HasOuts		  bool			  // temp data indicating whether there is TxOuts added by contracts
	HasIns		  bool			  // temp data indicating whether there is TxIns added by contracts
	HasDefs		  bool			  // temp data indicating whether there is TxDefs added by contracts
	Executed	  bool			  // whether contracts in the tx have been executed
}

// MsgTx returns the underlying wire.MsgTx for the transaction.
func (t *Tx) MsgTx() *wire.MsgTx {
	// Return the cached transaction.
	return t.msgTx
}

func (t *Tx) ContainContract() bool {
	for _, p := range t.msgTx.TxOut {
		if p.IsSeparator() {
			continue
		}
		if chaincfg.IsContractAddrID(p.PkScript[0]) {
			return true
		}
	}
	return false
}

func (t *Tx) IsCoinBase() bool {
	return t.MsgTx().IsCoinBase()
}

func (s *Tx) VerifyContractOut(t *Tx) bool {
	if len(s.msgTx.TxOut) != len(t.msgTx.TxOut) {
//	if len(s.Spends) != len(t.Spends) || len(s.msgTx.TxOut) != len(t.msgTx.TxOut) {
		return false
	}

	start := false
	for i, p := range s.msgTx.TxOut {
		if p.IsSeparator() {
			continue
		}
		if start {
			if p.Diff(t.msgTx.TxOut[i]) {
				return false
			}
		} else if p.IsSeparator() {
			start = true
			if p.TokenType != t.msgTx.TxOut[i].TokenType {
				return false
			}
		}
	}
	return true
}

func (s *Tx) AddTxOut(t wire.TxOut) int {
	if !s.HasOuts {
		// this servers as a separater. only TokenType is serialized
		to := wire.TxOut{}
		to.Token = token.Token{TokenType:token.DefTypeSeparator}
		s.HasOuts = true
		s.msgTx.AddTxOut(&to)
	}
	return s.msgTx.AddTxOut(&t)
}

func (s *Tx) AddTxIn(t wire.OutPoint, sig []byte) {
	if !s.HasIns {
		s.msgTx.AddTxIn(&wire.TxIn{})
		s.HasIns = true
	}
	if len(sig) == 0 {
		if t.Index == 0 && t.Hash.IsEqual(&chainhash.Hash{}) {
			// add a padding. contract can add padding, not separator
			s.msgTx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: t,
				Sequence:         0,
				SignatureIndex:   0xFFFFFFFF,
			})
		} else {
			s.msgTx.AddTxIn(&wire.TxIn{
				PreviousOutPoint: t,
				Sequence:         0xFFFFFFFF,
				SignatureIndex:   0xFFFFFFFF,
			})
		}
	} else {
		s.msgTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: t,
			Sequence:         0xFFFFFFFF,
			SignatureIndex:   uint32(len(s.msgTx.SignatureScripts)),
		})
		csig := make([]byte, len(sig))
		copy(csig, sig)
		s.msgTx.SignatureScripts = append(s.msgTx.SignatureScripts, csig)
	}
}

func (s *Tx) AddDef(t token.Definition) chainhash.Hash {
	if !s.HasDefs {
		to := token.SeparatorDef{}
		s.msgTx.AddDef(&to)
		s.HasDefs = true
	}
	return s.msgTx.AddDef(t)
}

func (s *Tx) Match(t *Tx) bool {
	return s.msgTx.Match(t.msgTx)
}

// Hash returns the hash of the transaction.  This is equivalent to
// calling TxHash on the underlying wire.MsgTx, however it caches the
// result so subsequent calls are more efficient.
func (t *Tx) Hash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHash != nil {
		return t.txHash
	}

	// Cache the hash and return it.
	hash := t.msgTx.TxHash()	// hash w/o signature
	t.txHash = &hash
	return &hash
}

/*
func (t *Tx) FullHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHash != nil {
		return t.txHash
	}

	// Cache the hash and return it.
	hash := t.msgTx.TxFullHash()	// hash w/o signature, but contract execs
	t.txHash = &hash
	return &hash
}
 */

// WitnessHash returns the witness hash (wtxid) of the transaction.  This is
// equivalent to calling WitnessHash on the underlying wire.MsgTx, however it
// caches the result so subsequent calls are more efficient.
/*
func (t *Tx) SignatureHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHashSignature != nil {
		return t.txHashSignature
	}

	// Cache the hash and return it.
	hash := t.msgTx.SignatureHash()
	t.txHashSignature = &hash
	return &hash
}
 */

// Index returns the saved index of the transaction within a block.  This value
// will be TxIndexUnknown if it hasn't already explicitly been set.
func (t *Tx) Index() int {
	return t.txIndex
}

// SetIndex sets the index of the transaction in within a block.
func (t *Tx) SetIndex(index int) {
	t.txIndex = index
}

// NewTx returns a new instance of a bitcoin transaction given an underlying
// wire.MsgTx.  See Tx.
func NewTx(msgTx *wire.MsgTx) *Tx {
	return &Tx{
		msgTx:   msgTx,
		txIndex: TxIndexUnknown,
	}
}

// NewTxFromBytes returns a new instance of a bitcoin transaction given the
// serialized bytes.  See Tx.
func NewTxFromBytes(serializedTx []byte) (*Tx, error) {
	br := bytes.NewReader(serializedTx)
	return NewTxFromReader(br)
}

// NewTxFromReader returns a new instance of a bitcoin transaction given a
// Reader to deserialize the transaction.  See Tx.
func NewTxFromReader(r io.Reader) (*Tx, error) {
	// Deserialize the bytes into a MsgTx.
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(r)
	if err != nil {
		return nil, err
	}

	t := Tx{
		msgTx:   &msgTx,
		txIndex: TxIndexUnknown,
	}
	return &t, nil
}
