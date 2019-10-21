// Copyright (c) 2015-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package viewpoint

import (
	"encoding/binary"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
//	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
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
)

type txoFlags uint8

type ViewPointSet struct {
	Db * database.DB
	Utxo * UtxoViewpoint
	Vertex * VtxViewpoint
	Border * BorderViewpoint
	Polygon * PolygonViewpoint
	Rights * RightViewpoint
}

func NewViewPointSet(db * database.DB) * ViewPointSet {
	t := ViewPointSet {}
	t.Db = db
	t.Utxo = NewUtxoViewpoint()
	t.Vertex = NewVtxViewpoint()
	t.Border = NewBorderViewpoint()
	t.Polygon = NewPolygonViewpoint()
	t.Rights = NewRightViewpoint()
	return &t
}

func (t * ViewPointSet) SetBestHash(hash * chainhash.Hash) {
	t.Vertex.bestHash = *hash
	t.Rights.bestHash = *hash
	t.Polygon.bestHash = *hash
	t.Border.bestHash = *hash
	t.Utxo.bestHash = *hash
}

func (t * ViewPointSet) DisconnectTransactions(db database.DB, block *btcutil.Block, stxos []SpentTxOut) error {
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
	return t.Utxo.disconnectTransactions(db, block, stxos)
}

func (t * ViewPointSet) Commit() {
	t.Vertex.commit()
	t.Rights.commit()
	t.Polygon.commit()
	t.Border.commit()
	t.Utxo.commit()
}

func DbPutViews(dbTx database.Tx,  view * ViewPointSet) error {
	DbPutVtxView(dbTx, view.Vertex)
	DbPutBorderView(dbTx, view.Border)
	DbPutPolygonView(dbTx, view.Polygon)
	DbPutRightView(dbTx, view.Rights)

	return DbPutUtxoView(dbTx, view.Utxo)
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
			}
			break;
		case *token.PolygonDef:
			plgview.addPolygon(d.(*token.PolygonDef))
			break;
		case *token.RightDef:
			rtview.addRight(d.(*token.RightDef))
			break;
		}
	}

	DbPutVtxView(dbTx, vtxview)
	DbPutBorderView(dbTx, bdrview)
	DbPutPolygonView(dbTx, plgview)
	DbPutRightView(dbTx, rtview)

	view.Utxo.AddTxOuts(tx, 0)

	return DbPutUtxoView(dbTx, view.Utxo)
}

// ConnectTransactions updates the view by adding all new vertices created by all
// of the transactions in the passed block, and setting the best hash for the view
// to the passed block.
func (view * ViewPointSet) ConnectDefTransactions(block *btcutil.Block) error {
	for _, tx := range block.Transactions() {
		view.AddBorder(tx)
		view.Polygon.AddPolygon(tx)
		view.Rights.AddRights(tx)
		view.Vertex.AddVertices(tx)
	}

	hash := block.Hash()

	view.Vertex.bestHash = *hash
	view.Rights.bestHash = *hash
	view.Polygon.bestHash = *hash
	view.Border.bestHash = *hash

	return nil
}

// errNotInMainChain signifies that a block hash or height that is not in the
// main chain was requested.
type ViewPointError string

// Error implements the error interface.
func (e ViewPointError) Error() string {
	return string(e)
}
