/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
 */

package viewpoint

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"fmt"
)

var (
	// utxoSetBucketName is the name of the db bucket used to house the
	// unspent transaction output set.
	utxoSetBucketName = []byte("utxosetv2")

	// vertexSetBucketName is the name of the db bucket used to house the
	// vertex definition set.
	vertexSetBucketName = []byte("vertices")

	// borderSetBucketName is the name of the db bucket used to house the
	// border definition set.
	borderSetBucketName = []byte("borders")

	// polygonSetBucketName is the name of the db bucket used to house the
	// polygon definition set.
	polygonSetBucketName = []byte("polygons")

	// rightSetBucketName is the name of the db bucket used to house the
	// right definition set.
	rightSetBucketName = []byte("rights")

	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian

	// MycoinsBucketName is the name of the db bucket used to house the
	// my (Miner) coins that may be used for collateral.
//	mycoinsBucketName = []byte("mycoins")
)

type txoFlags uint8

type ViewPointSet struct {
	Db database.DB
	Utxo * UtxoViewpoint
	Vertex * VtxViewpoint
	Border * BorderViewpoint
	Polygon * PolygonViewpoint
	Rights * RightViewpoint
//	Miners * MinersViewpoint
}

func NewViewPointSet(db database.DB) * ViewPointSet {
	t := ViewPointSet {}
	t.Db = db
	t.Utxo = NewUtxoViewpoint()
	t.Vertex = NewVtxViewpoint()
	t.Border = NewBorderViewpoint()
	t.Polygon = NewPolygonViewpoint()
	t.Rights = NewRightViewpoint()
//	t.Miners = NewMinersViewpoint()
	return &t
}

func (t * ViewPointSet) SetBestHash(hash * chainhash.Hash) {
	t.Vertex.bestHash = *hash
	t.Rights.bestHash = *hash
	t.Polygon.bestHash = *hash
	t.Border.bestHash = *hash
	t.Utxo.bestHash = *hash
//	t.Miners.bestHash = *hash
}

func (t * ViewPointSet) DisconnectTransactions(db database.DB, block *btcutil.Block, stxos []SpentTxOut) error {
//	t.Miners.disconnectTransactions(block)
	err := t.Vertex.disconnectTransactions(db, block)
	if err != nil {
		return err
	}
	err = t.Rights.disconnectTransactions(db, block)
	if err != nil {
		return err
	}
	err = t.Polygon.disconnectTransactions(db, block)
	if err != nil {
		return err
	}
	err = t.Border.disconnectTransactions(db, block)
	if err != nil {
		return err
	}

	for _,tx := range block.Transactions()[1:] {
		for _, in := range tx.MsgTx().TxIn {
			entry := t.Utxo.LookupEntry(in.PreviousOutPoint)
			if entry == nil {
				return AssertError(fmt.Sprintf("view missing input %v", in.PreviousOutPoint))
			}

			if entry.TokenType&3 == 3 {
				t.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash).reference(t)
			}
		}
		for _, out := range tx.MsgTx().TxOut {
			if out.TokenType == 3 {
				t.Polygon.LookupEntry(out.Token.Value.(*token.HashToken).Hash).deReference(t)
			}
		}
	}

	return t.disconnectTransactions(db, block, stxos)
}

func (t * ViewPointSet) Commit() {
	t.Vertex.commit()
	t.Rights.commit()
	t.Polygon.commit()
	t.Border.commit()
	t.Utxo.commit()
//	t.Miners.commit()
}

func DbPutViews(dbTx database.Tx,  view * ViewPointSet) error {
//	DbPutMinersView(view.Miners)

	DbPutUtxoView(dbTx, view.Utxo)
	DbPutPolygonView(dbTx, view.Polygon)
	DbPutBorderView(dbTx, view.Border)
	DbPutVtxView(dbTx, view.Vertex)

	return DbPutRightView(dbTx, view.Rights)
}

func DbPutGensisTransaction(dbTx database.Tx, tx *btcutil.Tx, view * ViewPointSet) error {
	vtxview := view.Vertex
	bdrview := view.Border
	plgview := view.Polygon
	rtview := view.Rights

	// put out definitions
	children := make(map[chainhash.Hash][]chainhash.Hash)
	for _,d := range tx.MsgTx().TxDef {
		switch d.(type) {
		case *token.VertexDef:
			vtxview.addVertex(d.(*token.VertexDef))
			break;
		case *token.BorderDef:
			b := d.(*token.BorderDef)
			view.addBorder(b)

			if !b.Father.IsEqual(&chainhash.Hash{}) {
				if children[b.Father] != nil {
					children[b.Father] = append(children[b.Father], b.Hash())
				} else {
					children[b.Father] = make([]chainhash.Hash, 1)
					children[b.Father][0] = b.Hash()
				}
				view.Border.LookupEntry(b.Father).RefCnt++
			}
			break;
		case *token.PolygonDef:
			view.addPolygon(d.(*token.PolygonDef))
			for _, loop := range d.(*token.PolygonDef).Loops {
				for _,b := range loop {
					view.Border.LookupEntry(b).RefCnt++
				}
			}
			break;
		case *token.RightDef:
			view.addRight(d.(*token.RightDef))
			break;
		}
	}

	DbPutVtxView(dbTx, vtxview)
	DbPutBorderView(dbTx, bdrview)
	DbPutRightView(dbTx, rtview)
	DbPutPolygonView(dbTx, plgview)

	view.AddTxOuts(tx, 0)

	return DbPutUtxoView(dbTx, view.Utxo)
}

// ConnectTransactions updates the view by adding all new vertices created by all
// of the transactions in the passed block, and setting the best hash for the view
// to the passed block.
func (view * ViewPointSet) ConnectTransactions(block *btcutil.Block, stxos *[]SpentTxOut, minersonhold map[[20]byte]int32) error {
	for _, tx := range block.Transactions() {
		view.Vertex.AddVertices(tx)
		if !view.AddBorder(tx) {
			return fmt.Errorf("Attempt to add illegal border.")
		}
		if !view.AddRights(tx) {
			return fmt.Errorf("Attempt to add illegal rights.")
		}
		if !view.AddPolygon(tx) {
			return fmt.Errorf("Attempt to add illegal polygon.")
		}

		if !tx.IsCoinBase() {
			for _, in := range tx.MsgTx().TxIn {
				entry := view.Utxo.LookupEntry(in.PreviousOutPoint)
				if entry == nil {
					return AssertError(fmt.Sprintf("view missing input %v", in.PreviousOutPoint))
				}

				if entry.TokenType&3 == 3 {
					view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash).deReference(view)
				} else if entry.TokenType == 0 {
					var ou [20]byte
					copy(ou[:], entry.pkScript[1:21])
					if _,ok := minersonhold[ou]; ok {
						return fmt.Errorf("Miner attempts to spend in holding period.")
					}
				}
			}
		}
		for _, out := range tx.MsgTx().TxOut {
			if out.TokenType == 3 {
				view.Polygon.LookupEntry(out.Token.Value.(*token.HashToken).Hash).reference(view)
			}
		}
		view.ConnectTransaction(tx, block.Height(), stxos)
	}

	hash := block.Hash()

	view.SetBestHash(hash)

	return nil
}

// errNotInMainChain signifies that a block hash or height that is not in the
// main chain was requested.
type ViewPointError string

// Error implements the error interface.
func (e ViewPointError) Error() string {
	return string(e)
}
