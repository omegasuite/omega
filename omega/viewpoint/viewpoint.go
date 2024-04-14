/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package viewpoint

import (
	"encoding/binary"

	"fmt"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega"
	"github.com/omegasuite/omega/token"
)

var (
	// utxoSetBucketName is the name of the db bucket used to house the
	// unspent transaction output set.
	utxoSetBucketName = []byte("utxosetv2")

	// vertexSetBucketName is the name of the db bucket used to house the
	// vertex definition set.
	//	vertexSetBucketName = []byte("vertices")

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
	Db      database.DB
	Utxo    *UtxoViewpoint
	Border  *BorderViewpoint
	Polygon *PolygonViewpoint
	Rights  *RightViewpoint
}

func NewViewPointSet(db database.DB) *ViewPointSet {
	t := ViewPointSet{}
	t.Db = db
	t.Utxo = NewUtxoViewpoint()
	t.Border = NewBorderViewpoint()
	t.Polygon = NewPolygonViewpoint()
	t.Rights = NewRightViewpoint()

	return &t
}

func (t *ViewPointSet) SetBestHash(hash *chainhash.Hash) {
	t.Rights.bestHash = *hash
	t.Polygon.bestHash = *hash
	t.Border.bestHash = *hash
	t.Utxo.bestHash = *hash
}

func (t *ViewPointSet) DisconnectTransactions(db database.DB, block *btcutil.Block, stxos []SpentTxOut) error {
	err := t.disconnectRightTransactions(block)
	if err != nil {
		return err
	}
	err = t.disconnectPolygonTransactions(block)
	if err != nil {
		return err
	}
	err = t.disconnectBorderTransactions(block)
	if err != nil {
		return err
	}
	/*
		for _,tx := range block.Transactions()[1:] {
			for _, in := range tx.MsgTx().TxIn {
				if in.IsSeparator() {
					continue
				}
				entry := t.Utxo.LookupEntry(in.PreviousOutPoint)
				if entry == nil {
					t.Utxo.FetchUtxosMain(db, map[wire.OutPoint]struct{}{in.PreviousOutPoint: {}})
					entry = t.Utxo.LookupEntry(in.PreviousOutPoint)
					if entry == nil {
						continue	// it's OK to have a nil
					}
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
	*/

	return t.disconnectTransactions(db, block, stxos)
}

func (t *ViewPointSet) Commit() {
	t.Rights.commit()
	t.Polygon.commit()
	t.Border.commit()
	t.Utxo.commit()
}

func DbPutViews(dbTx database.Tx, view *ViewPointSet) error {
	DbPutUtxoView(dbTx, view.Utxo)
	DbPutPolygonView(dbTx, view.Polygon)
	DbPutBorderView(dbTx, view.Border)

	return DbPutRightView(dbTx, view.Rights)
}

var GlobalBoundingBox = func() BoundingBox {
	box := BoundingBox{}
	box.Reset()
	for _, b := range omega.InitDefs {
		switch b.(type) {
		case *token.BorderDef:
			v := b.(*token.BorderDef).Begin
			box.Expand(v.Lat(), v.Lng())
		}
	}
	return box
}()

func DbPutGensisTransaction(dbTx database.Tx, tx *btcutil.Tx, view *ViewPointSet) error {
	bdrview := view.Border
	plgview := view.Polygon
	rtview := view.Rights

	for _, d := range tx.MsgTx().TxDef {
		if d.IsSeparator() {
			continue
		}
		switch d.(type) {
		case *token.BorderDef:
			b := d.(*token.BorderDef)
			view.addBorder(b)

			if !b.Father.IsEqual(&chainhash.Hash{}) {
				view.Border.LookupEntry(b.Father).RefCnt++
			}
			break
		case *token.PolygonDef:
			view.addPolygon(d.(*token.PolygonDef), true, GlobalBoundingBox)
			bdr := view.Flattern(d.(*token.PolygonDef).Loops)
			for _, loop := range bdr {
				for _, b := range loop {
					view.Border.LookupEntry(b).RefCnt++
				}
			}
			break
		case *token.RightDef:
			view.AddRight(d.(*token.RightDef))
			break
		}
	}

	DbPutBorderView(dbTx, bdrview)
	DbPutRightView(dbTx, rtview)
	DbPutPolygonView(dbTx, plgview)

	view.AddTxOuts(tx, 0)

	return DbPutUtxoView(dbTx, view.Utxo)
}

func (views *ViewPointSet) Flattern(p []token.LoopDef) []token.LoopDef {
	loops := make([]token.LoopDef, 1)
	for _, q := range p {
		if len(q) == 1 {
			plg, _ := views.FetchPolygonEntry(&q[0])
			if plg == nil {
				return nil
			}
			loops = append(loops, views.Flattern(plg.Loops)...)
		} else {
			loops = append(loops, q)
		}
	}
	return loops
}

var zerohash chainhash.Hash

// ConnectTransactions updates the view by adding all new vertices created by all
// of the transactions in the passed block, and setting the best hash for the view
// to the passed block.
func (view *ViewPointSet) ConnectTransactions(block *btcutil.Block, stxos *[]SpentTxOut) error {
	for _, tx := range block.Transactions() {
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
				if in.PreviousOutPoint.Hash.IsEqual(&zerohash) {
					continue
				}
				entry := view.Utxo.LookupEntry(in.PreviousOutPoint)
				if entry == nil {
					return AssertError(fmt.Sprintf("view missing input %v", in.PreviousOutPoint))
				}

				if entry.TokenType == 3 {
					p := view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash)
					if p == nil {
						view.FetchPolygonEntry(&entry.Amount.(*token.HashToken).Hash)
						p = view.Polygon.LookupEntry(entry.Amount.(*token.HashToken).Hash)
					}
					if p != nil {
						p.deReference(view)
					}
				}
			}
		}
		for _, out := range tx.MsgTx().TxOut {
			if out.IsSeparator() {
				continue
			}
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
