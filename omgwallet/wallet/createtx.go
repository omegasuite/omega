// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"
	"sort"

	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/txscript"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omgwallet/waddrmgr"
	"github.com/omegasuite/omgwallet/wallet/txauthor"
	"github.com/omegasuite/omgwallet/walletdb"
	"github.com/omegasuite/omgwallet/wtxmgr"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/ovm"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

// byAmount defines the methods needed to satisify sort.Interface to
// sort credits by their output amount.
type byAmount []wtxmgr.Credit

func (s byAmount) Len() int           { return len(s) }
func (s byAmount) Less(i, j int) bool {
	if s[i].Amount.TokenType != s[j].Amount.TokenType {
		return s[i].Amount.TokenType < s[j].Amount.TokenType
	}
	if (s[i].Amount.TokenType & 1) == 0 {
		return s[i].Amount.Value.(*token.NumToken).Val < s[j].Amount.Value.(*token.NumToken).Val
	}
	return s[i].Amount.Value.(*token.HashToken).Hash.String() < s[j].Amount.Value.(*token.HashToken).Hash.String()
}
func (s byAmount) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func makeInputSource(eligible []wtxmgr.Credit) txauthor.InputSource {
	// Pick largest outputs first.  This is only done for compatibility with
	// previous tx creation code, not because it's a good idea.
	sort.Sort(sort.Reverse(byAmount(eligible)))

	// Current inputs and their total value.  These are closed over by the
	// returned input source and reused across multiple calls.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]btcutil.Amount, 0, len(eligible))

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {
		n := uint32(0)
		for currentTotal < target && len(eligible) != 0 {
			nextCredit := &eligible[0]
			eligible = eligible[1:]
			nextInput := wire.NewTxIn(&nextCredit.OutPoint, n)
			n++
			if nextCredit.Amount.TokenType == 0 {
				currentTotal += btcutil.Amount(nextCredit.Amount.Value.(*token.NumToken).Val)
				currentInputs = append(currentInputs, nextInput)
				currentScripts = append(currentScripts, nextCredit.PkScript)
				currentInputValues = append(currentInputValues, btcutil.Amount(nextCredit.Amount.Value.(*token.NumToken).Val))
			}
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*waddrmgr.Manager
	addrmgrNs walletdb.ReadBucket
}

func (s secretSource) GetKey(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, false, err
	}

	mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedPubKeyAddress", addr, ma)
		return nil, false, e
	}
	privKey, err := mpka.PrivKey()
	if err != nil {
		return nil, false, err
	}
	return privKey, ma.Compressed(), nil
}

func (s secretSource) GetScript(addr btcutil.Address) ([]byte, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, err
	}

	msa, ok := ma.(waddrmgr.ManagedScriptAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedScriptAddress", addr, ma)
		return nil, e
	}
	return msa.Script()
}

// txToOutputs creates a signed transaction which includes each output from
// outputs.  Previous outputs to reedeem are chosen from the passed account's
// UTXO set and minconf policy. An additional output may be added to return
// change to the wallet.  An appropriate fee is included based on the wallet's
// current relay fee.  The wallet must be unlocked to create the transaction.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true will intentionally have no
// input scripts added and SHOULD NOT be broadcasted.
func (w *Wallet) txToOutputs(outputs []*wire.TxOut, account uint32,
	minconf int32, feeSatPerKb btcutil.Amount, dryRun bool) (
	tx *txauthor.AuthoredTx, err error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	if tx.Tx.TxOut[tx.ChangeIndex].TokenType != 0 {
		return nil, nil
	}

	dbtx, err := w.db.BeginReadWriteTx()
	if err != nil {
		return nil, err
	}
	defer dbtx.Rollback()

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	eligible, err := w.findEligibleOutputs(dbtx, account, minconf, bs)
	if err != nil {
		return nil, err
	}

	inputSource := makeInputSource(eligible)
	changeSource := func() ([]byte, error) {
		// Derive the change output script.  As a hack to allow
		// spending from the imported account, change addresses are
		// created from account 0.
		var changeAddr btcutil.Address
		var err error
		if account == waddrmgr.ImportedAddrAccount {
			changeAddr, err = w.newChangeAddress(addrmgrNs, 0)
		} else {
			changeAddr, err = w.newChangeAddress(addrmgrNs, account)
		}
		if err != nil {
			return nil, err
		}
		return txscript.PayToAddrScript(changeAddr)
	}
	tx, err = txauthor.NewUnsignedTransaction(outputs, feeSatPerKb,
		inputSource, changeSource)
	if err != nil {
		return nil, err
	}

	// Randomize change position, if change exists, before signing.  This
	// doesn't affect the serialize size, so the change amount will still
	// be valid.
	if tx.ChangeIndex >= 0 {
		tx.RandomizeChangePosition()
	}

	// If a dry run was requested, we return now before adding the input
	// scripts, and don't commit the database transaction. The DB will be
	// rolled back when this method returns to ensure the dry run didn't
	// alter the DB in any way.
	if dryRun {
		return tx, nil
	}

	err = tx.AddAllInputScripts(secretSource{w.Manager, addrmgrNs})
	if err != nil {
		return nil, err
	}

	err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
	if err != nil {
		return nil, err
	}

	if err := dbtx.Commit(); err != nil {
		return nil, err
	}

	if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
		changeAmount := btcutil.Amount(tx.Tx.TxOut[tx.ChangeIndex].Value.(*token.NumToken).Val)
		log.Warnf("Spend from imported account produced change: moving"+
			" %v from imported account into default account.", changeAmount)
	}

	// Finally, we'll request the backend to notify us of the transaction
	// that pays to the change address, if there is one, when it confirms.
	if tx.ChangeIndex >= 0 {
		changePkScript := tx.Tx.TxOut[tx.ChangeIndex].PkScript
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			changePkScript, w.chainParams,
		)
		if err != nil {
			return nil, err
		}
		if err := chainClient.NotifyReceived(addrs); err != nil {
			return nil, err
		}
	}

	return tx, nil
}

func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx, account uint32, minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	unspent, err := w.TxStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err != nil || len(addrs) != 1 {
			continue
		}
		_, addrAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			continue
		}
		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// validateMsgTx verifies transaction input scripts for tx. All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte, inputValues []btcutil.Amount) error {
	ctx := ovm.Context{}
	ctx.GetCoinBase = func() *btcutil.Tx { return nil }
	ctx.GetTx = func() *btcutil.Tx { return btcutil.NewTx(tx) }
	ctx.AddTxOutput = func(t wire.TxOut) int { return -1 }
	ctx.AddRight = func(t *token.RightDef) bool { return false }
	ctx.GetUtxo = func(hash chainhash.Hash, seq uint64) *wire.TxOut { return nil }
//	ctx.GetHash = ovm.GetHash
	ctx.BlockNumber = func() uint64 { return 0 }
	ctx.Block = func() *btcutil.Block { return nil }

	vm := ovm.NewOVM(nil)
	vm.SetContext(ctx)
	intp := ovm.NewInterpreter(vm)

	for i, prevScript := range prevScripts {
		if !intp.VerifySig(i, prevScript, tx.SignatureScripts[i]) {
			return fmt.Errorf("cannot validate transaction.")
		}
	}
	return nil
}
