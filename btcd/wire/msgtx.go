// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/omega/token"
	"io"
	"strconv"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1
/*
	// TxSideChain is the genesis transaction of a side chain, thus all outputs in
	// this Tx will not be added to main chain Utxo database and is thus unspendable
	// in main chain. Each block can have at most one TxSideChain Tx.
	TxSideChain = 0x80000000

	// TxMainToSideChain is a Tx that transfters value from main chian to a side chain,
	// thus all outputs in this Tx will not be addded to Utxo database and is thus
	// unspendable in this chain.
	TxMainToSideChain = 0x40000000

	// TxSideChain is the Tx is a transaction that transfters from a side chain to main chain.
	// main chain keeps a wallet for each side chain. address of the wallet is hash of main chain
	// block hacing TxSideChain Tx. block of side chain. main chain accept this Tx only after it
	// is finalized in side chain. TxSideChain, TxMainToSideChain, TxSideToMainChain will appear
	// in both main chain and side chain.
	// There can be no Def or contract call in TxSideChain, TxMainToSideChain, TxSideToMainChain Tx
	TxSideToMainChain = 0x20000000

	// How to make contract based on a land in side chain work on main chain?
*/
	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + chainhash.HashSize

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / common.MinTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// freeListMaxScriptSize is the size of each buffer in the free list
	// that	is used for deserializing scripts from the wire before they are
	// concatenated into a single contiguous buffers.  This value was chosen
	// because it is slightly more than twice the size of the vast majority
	// of all "standard" scripts.  Larger scripts are still deserialized
	// properly as the free list will simply be bypassed for them.
	freeListMaxScriptSize = 512

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deserialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	freeListMaxItems = 12500
)

// scriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that have a cap according to the
// freeListMaxScriptSize constant.  It is used to provide temporary buffers for
// deserializing scripts in order to greatly reduce the number of allocations
// required.
//
// The caller can obtain a buffer from the free list by calling the Borrow
// function and should return it via the Return function when done using it.
type scriptFreeList chan []byte

// Borrow returns a byte slice from the free list with a length according the
// provided size.  A new buffer is allocated if there are any items available.
//
// When the size is larger than the max size allowed for items on the free list
// a new buffer of the appropriate size is allocated and returned.  It is safe
// to attempt to return said buffer via the Return function as it will be
// ignored and allowed to go the garbage collector.
func (c scriptFreeList) Borrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}
	return buf[:size]
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the Borrow function.  Any slices that are not of the appropriate size, such
// as those whose size is greater than the largest allowed free list item size
// are simply ignored so they can go to the garbage collector.
func (c scriptFreeList) Return(buf []byte) {
	// Ignore any buffers returned that aren't the expected size for the
	// free list.
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	// Return the buffer to the free list when it's not full.  Otherwise let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for script deserialization.  As
// previously described, this free list is maintained to significantly reduce
// the number of allocations.
var scriptPool scriptFreeList = make(chan []byte, freeListMaxItems)

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

func (o OutPoint) ToBytes() []byte {
	buf := make([]byte, chainhash.HashSize+4)
	copy(buf, o.Hash[:])
	binary.LittleEndian.PutUint32(buf[chainhash.HashSize:], o.Index)
	return buf
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines an omega transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	Sequence         uint32
	SignatureIndex   uint32		// this is an index to signature script, thus two TxIn could share one
								// signature by having the same index. This is useful when one combine
								// multiple utxos (belonging to one person) into one utxo since the signature
								// would be identical for those utxos
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes + SignatureIndex 4 bytes
	return 44
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureIndex uint32) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureIndex:   signatureIndex,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	token.Token
	PkScript []byte
}

func (t *TxOut) IsNumeric () bool {
	return t.Token.IsNumeric()
}

func (t *TxOut) HasRight () bool {
	return t.Token.HasRight()
}

func (t *TxOut) Diff(s *TxOut) bool {
	return t.Token.Diff(&s.Token) || bytes.Compare(t.PkScript, s.PkScript) != 0
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(tokenType	uint64, value token.TokenValue, rights *chainhash.Hash, pkScript []byte) *TxOut {
	t := TxOut{}
	t.TokenType = tokenType
	t.Value = value
	t.Rights = rights
	t.PkScript = pkScript
	return &t
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version  int32
	TxDef    []token.Definition
	TxIn     []*TxIn
	TxOut    []*TxOut
	SignatureScripts [][]byte		// all signatures goes here intentionally. in a block, all signatures goes to the end
	LockTime uint32
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) int {
	msg.TxIn = append(msg.TxIn, ti)
	return len(msg.TxIn) - 1
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) int {
	msg.TxOut = append(msg.TxOut, to)
	return len(msg.TxOut) - 1
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddSignature(sig []byte) int {
	if msg.SignatureScripts == nil {
		msg.SignatureScripts = make([][]byte, 0, len(msg.TxIn))
	}
	msg.SignatureScripts = append(msg.SignatureScripts, sig)
	return len(msg.SignatureScripts) - 1
}

// AddTxOut adds a vertex definition to the message.
func (msg *MsgTx) AddVertex(to *token.VertexDef) int {
	msg.TxDef = append(msg.TxDef, to)
	return len(msg.TxDef) - 1
}

// AddTxOut adds a border definition to the message.
func (msg *MsgTx) AddBorder(to *token.BorderDef) int {
	msg.TxDef = append(msg.TxDef, to)
	return len(msg.TxDef) - 1
}

// AddTxOut adds a polygon definition to the message.
func (msg *MsgTx) AddPolygon(to *token.PolygonDef) int {
	msg.TxDef = append(msg.TxDef, to)
	return len(msg.TxDef) - 1
}

// AddTxOut adds a right definition to the message.
func (msg *MsgTx) AddRight(to *token.RightDef) int {
	msg.TxDef = append(msg.TxDef, to)
	return len(msg.TxDef) - 1
}

// AddTxOut adds a definition to the message.
func (msg *MsgTx) AddDef(to token.Definition) int {
	msg.TxDef = append(msg.TxDef, to)
	return len(msg.TxDef) - 1
}

func (msg *MsgTx) RemapTxout(to * TxOut) * TxOut {
	if to.TokenType & 1 == 1 {
		h := to.Value.(*token.HashToken).Hash
		if t := token.NeedRemap(h[:]); len(t) > 0 {
			to.Value.(*token.HashToken).Hash = msg.TxDef[token.Bytetoint(t[1])].Hash()
		}
	}
	if to.Rights != nil {
		if t := token.NeedRemap((*to.Rights)[:]); len(t) > 0 {
			*to.Rights = msg.TxDef[token.Bytetoint(t[1])].Hash()
		}
	}
	return to
}

// TxHash generates the Hash for the transaction.
func (msg *MsgTx) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.

	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeStripped()))
	_ = msg.SerializeNoSignature(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

// SignatureHash generates the hash of the transaction serialized including Tx data and signatures.
// The final output is used within the Segregated Witness commitment of all the witnesses
// within a block
func (msg *MsgTx) SignatureHash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	newTx := msg.CleanCopy()

	// Deep copy the old TxOut data.
	start := false
	for _, oldTxOut := range msg.TxOut {
		if oldTxOut.TokenType == 0xFFFFFFFFFFFFFFFF {
			start = true
			newTxOut := TxOut{}
			newTxOut.TokenType = oldTxOut.TokenType
			newTx.TxOut = append(newTx.TxOut, &newTxOut)
			continue
		} else if !start {
			continue
		}

		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		oldRights := oldTxOut.Rights
		newRights := (*chainhash.Hash)(nil)
		if oldRights != nil {
			newRights = &chainhash.Hash{}
			copy(newRights[:], (*oldRights)[:])
		}

		var newVal token.TokenValue

		h,v := oldTxOut.Value.Value()
		if oldTxOut.Value.IsNumeric() {
			newVal = &token.NumToken {
				Val: v,
			}
		} else {
			newVal = &token.HashToken {
				Hash: *h,
			}
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{}
		newTxOut.TokenType = oldTxOut.TokenType
		newTxOut.Value = newVal
		newTxOut.Rights = newRights
		newTxOut.PkScript = newScript

		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return newTx
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) CleanCopy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxDef:    make([]token.Definition, 0, len(msg.TxDef)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		SignatureScripts: make([][]byte, 0, len(msg.SignatureScripts)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureIndex:   oldTxIn.SignatureIndex,
			Sequence:         oldTxIn.Sequence,
		}

		// Finally, append this fully copied txin.
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		if oldTxOut.TokenType == 0xFFFFFFFFFFFFFFFF {
			break
		}

		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		oldRights := oldTxOut.Rights
		newRights := (*chainhash.Hash)(nil)
		if oldRights != nil {
			newRights = &chainhash.Hash{}
			copy(newRights[:], (*oldRights)[:])
		}

		var newVal token.TokenValue

		h,v := oldTxOut.Value.Value()
		if oldTxOut.Value.IsNumeric() {
			newVal = &token.NumToken {
				Val: v,
			}
		} else {
			newVal = &token.HashToken {
				Hash: *h,
			}
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{}
		newTxOut.TokenType = oldTxOut.TokenType
		newTxOut.Value = newVal
		newTxOut.Rights = newRights
		newTxOut.PkScript = newScript

		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	// Deep copy the old Defnition data.
	newTx.TxDef = token.CopyDefinitions(msg.TxDef)

	// copy SignatureScripts
	for _,s := range msg.SignatureScripts {
		newTx.AddSignature(s)
	}

	return &newTx
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	// definitions
	count, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more definition than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(token.MaxDefinitionPerMessage) {
		str := fmt.Sprintf("too many definitions to fit into "+
			"max message size [count %d, max %d]", count,
			token.MaxDefinitionPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	msg.TxDef = make([]token.Definition, 0, count)
	for i := uint64(0); i < count; i++ {
		definition, err := token.ReadDefinition(r, pver, msg.Version)
		if err != nil {
			return err
		}
		msg.TxDef = append(msg.TxDef, definition)
	}

	// TxIn
	count, err = common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the inputs.
	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		ti := &txIns[i]
		msg.TxIn[i] = ti
		err = ti.readTxIn(r, pver, msg.Version)
		if err != nil {
			return err
		}
	}

	count, err = common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxOutPerMessage) {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the outputs.
	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		to := &txOuts[i]
		msg.TxOut[i] = to
		err = to.ReadTxOut(r, pver, uint32(msg.Version))
		if err != nil {
			return err
		}
	}

	msg.LockTime,err = common.BinarySerializer.Uint32(r, common.LittleEndian)
	if err != nil {
		return err
	}

	if enc == SignatureEncoding {
		err := msg.ReadSignature(r, pver)
		if err != nil {
			return err
		}
	}

	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, SignatureEncoding)
}

// DeserializeNoWitness decodes a transaction from r into the receiver, where
// the transaction encoding format within r MUST NOT utilize the new
// serialization format created to encode transaction bearing witness data
// within inputs.
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := common.BinarySerializer.PutUint32(w, common.LittleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxDef))
	if err = common.WriteVarInt(w, pver, count); err != nil {
		return err
	}

	for _, ti := range msg.TxDef {
		err = token.WriteDefinition(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxIn))
	if err = common.WriteVarInt(w, pver, count); err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = ti.writeTxIn(w, pver, msg.Version, enc)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))
	if err = common.WriteVarInt(w, pver, count); err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = to.WriteTxOut(w, pver, msg.Version, enc)
		if err != nil {
			return err
		}
	}

	if err := common.BinarySerializer.PutUint32(w, common.LittleEndian, msg.LockTime); err != nil {
		return err
	}

	if enc == SignatureEncoding {
		msg.WriteSignature(w, pver)
	}

	return nil
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the bitcoin wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//

	return msg.BtcEncode(w, 0, SignatureEncoding)	// SignatureEncoding
}

// SerializeNoWitness encodes the transaction to w in an identical manner to
// Serialize, however even if the source transaction has inputs with witness
// data, the old serialization format will still be used.
func (msg *MsgTx) SerializeNoSignature(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTx) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + common.VarIntSerializeSize(uint64(len(msg.TxDef))) + common.VarIntSerializeSize(uint64(len(msg.TxIn))) +
		common.VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txDef := range msg.TxDef {
		n += txDef.SerializeSize()
	}

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTx) SerializeSize() int {
	n := msg.baseSize()

	n += common.VarIntSerializeSize(uint64(len(msg.SignatureScripts)))
	for _, s := range msg.SignatureScripts {
		n += common.VarIntSerializeSize(uint64(len(s))) + len(s)
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the transaction, excluding any included witness data.
func (msg *MsgTx) SerializeSizeStripped() int {
	return msg.baseSize()
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxDef:   make([]token.Definition, 0, defaultTxInOutAlloc),
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
		SignatureScripts:   make([][]byte, 0, defaultTxInOutAlloc),
	}
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func readOutPoint(r io.Reader, pver uint32, version int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = common.BinarySerializer.Uint32(r, common.LittleEndian)
	return err
}

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return common.BinarySerializer.PutUint32(w, common.LittleEndian, op.Index)
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhaustion attacks and forced panics through malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := common.ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, messageError("readScript", str)
	}

	b := make([]byte, count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func (ti *TxIn) readTxIn(r io.Reader, pver uint32, version int32) error {
	err := readOutPoint(r, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	if err = readElement(r, &ti.SignatureIndex); err != nil {
		return err
	}

	return readElement(r, &ti.Sequence)
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func (ti *TxIn) writeTxIn(w io.Writer, pver uint32, version int32, enc MessageEncoding) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	if enc == SignatureEncoding {
		if err = common.BinarySerializer.PutUint32(w, common.LittleEndian, ti.SignatureIndex); err != nil {
			return err
		}
	} else if err = common.BinarySerializer.PutUint32(w, common.LittleEndian, 0xFFFFFFFF); err != nil {
		return err
	}

	return common.BinarySerializer.PutUint32(w, common.LittleEndian, ti.Sequence)
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func (to *TxOut) ReadTxOut(r io.Reader, pver uint32, version uint32) error {
	err := to.Token.ReadTxOut(r, pver, version)
	if err != nil {
		return err
	}
	to.PkScript, err = readScript(r, pver, MaxMessagePayload,
	"transaction output public key script")
	return err
}

// WriteTxOut encodes to into the protocol encoding for a transaction
// output (TxOut) to w.

func (to *TxOut) WriteTxOut(w io.Writer, pver uint32, version int32, enc MessageEncoding) error {
	err := to.Token.WriteTxOut(w, pver, version)
	if err != nil {
		return err
	}

	return common.WriteVarBytes(w, pver, to.PkScript)
}

// writeSignature encodes the bitcoin protocol encoding for a transaction
// input's witness into to w.
func (tx * MsgTx) WriteSignature(w io.Writer, pver uint32) error {
	err := common.WriteVarInt(w, pver, uint64(len(tx.SignatureScripts)))
	if err != nil {
		return err
	}
	for _, item := range tx.SignatureScripts {
		if err = common.WriteVarBytes(w, pver, item); err != nil {
			return err
		}
	}
	return nil
}

// writeSignature encodes the bitcoin protocol encoding for a transaction
// input's witness into to w.
func (tx * MsgTx) ReadSignature(r io.Reader, pver uint32) error {
	count, err := common.ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent a possible memory exhaustion attack by
	// limiting the witCount value to a sane upper bound.
	if int(count) > len(tx.TxIn) && int(count) > CommitteeSize + 1 {	// allow one for signature because coin base Tx includes signature merkle root
		str := fmt.Sprintf("more signatures than inputs (%d, %d)",
			count, len(tx.TxIn))
		return messageError("MsgTx.BtcDecode", str)
	}

	// signature data.
	for i := 0; i < int(count); i++ {
		s, err := readScript(r, pver, MaxMessagePayload,
			"transaction signature script")
		if err != nil {
			return err
		}
		tx.AddSignature(s)
	}

	return nil
}

func zeroaddr(addr []byte) bool {
	for _,t := range addr {
		if t != 0 {
			return false
		}
	}
	return true
}

func (msgTx *MsgTx) IsCoinBase() bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) != 1 {
		return false
	}

	// The previous output of a coin base must have a zero hash. index is height of the block.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if !prevOut.Hash.IsEqual(&chainhash.Hash{}) {	// prevOut.Index != math.MaxUint32 ||
		return false
	}

	if len(msgTx.TxDef) != 0 {
		return false
	}

	for _,to := range msgTx.TxOut {
		if to.TokenType != 0 {
			return false
		}
	}

	return true
}

func (msg *MsgTx) RemapDef(to token.Definition) token.Definition {
	return token.RemapDef(msg.TxDef, to)
}