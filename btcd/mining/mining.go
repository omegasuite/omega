// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

import (
	"bytes"
	"container/heap"
	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"
	"github.com/omegasuite/omega/ovm"
	"time"

	"encoding/binary"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	"github.com/omegasuite/omega/viewpoint"
)

const (
	// MinHighPriority is the minimum priority value that allows a
	// transaction to be considered high priority.
	MinHighPriority = btcutil.SatoshiPerBitcoin * 144.0 / 250

	// blockHeaderOverhead is the max number of bytes it takes to serialize
	// a block header and max possible transaction count.
	blockHeaderOverhead = wire.MaxBlockHeaderPayload + common.MaxVarIntPayload

	// CoinbaseFlags is added to the coinbase script of a generated block
	// and is used to monitor BIP16 support as well as blocks that are
	// generated via btcd.
	CoinbaseFlags = "/P2SH/btcd/"
)

// TxDesc is a descriptor about a transaction in a transaction source along with
// additional metadata.
type TxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx *btcutil.Tx

	// Added is the time when the entry was added to the source pool.
	Added time.Time

	// Height is the block height when the entry was added to the the source
	// pool.
	Height int32

	// Fee is the total fee the transaction associated with the entry pays.
	Fee int64

	// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
	FeePerKB int64
}

// TxSource represents a source of transactions to consider for inclusion in
// new blocks.
//
// The interface contract requires that all of these methods are safe for
// concurrent access with respect to the source.
type TxSource interface {
	// LastUpdated returns the last time a transaction was added to or
	// removed from the source pool.
	LastUpdated() time.Time

	// MiningDescs returns a slice of mining descriptors for all the
	// transactions in the source pool.
	MiningDescs() []*TxDesc

	RemoveTransaction(tx *btcutil.Tx, removeRedeemers bool)

	// HaveTransaction returns whether or not the passed transaction hash
	// exists in the source pool.
	HaveTransaction(hash *chainhash.Hash) bool
}

// txPrioItem houses a transaction along with extra information that allows the
// transaction to be prioritized and track dependencies on other transactions
// which have not been mined into a block yet.
type txPrioItem struct {
	tx       *btcutil.Tx
	fee      int64
	priority float64
	feePerKB int64

	// dependsOn holds a map of transaction hashes which this one depends
	// on.  It will only be set when the transaction references other
	// transactions in the source pool and hence must come after them in
	// a block.
	dependsOn map[chainhash.Hash]struct{}
}

// txPriorityQueueLessFunc describes a function that can be used as a compare
// function for a transaction priority queue (txPriorityQueue).
type txPriorityQueueLessFunc func(*txPriorityQueue, int, int) bool

// txPriorityQueue implements a priority queue of txPrioItem elements that
// supports an arbitrary compare function as defined by txPriorityQueueLessFunc.
type txPriorityQueue struct {
	lessFunc txPriorityQueueLessFunc
	items    []*txPrioItem
}

// Len returns the number of items in the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueue) Len() int {
	return len(pq.items)
}

// Less returns whether the item in the priority queue with index i should sort
// before the item with index j by deferring to the assigned less function.  It
// is part of the heap.Interface implementation.
func (pq *txPriorityQueue) Less(i, j int) bool {
	return pq.lessFunc(pq, i, j)
}

// Swap swaps the items at the passed indices in the priority queue.  It is
// part of the heap.Interface implementation.
func (pq *txPriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

// Push pushes the passed item onto the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueue) Push(x interface{}) {
	pq.items = append(pq.items, x.(*txPrioItem))
}

// Pop removes the highest priority item (according to Less) from the priority
// queue and returns it.  It is part of the heap.Interface implementation.
func (pq *txPriorityQueue) Pop() interface{} {
	n := len(pq.items)
	item := pq.items[n-1]
	pq.items[n-1] = nil
	pq.items = pq.items[0 : n-1]
	return item
}

// SetLessFunc sets the compare function for the priority queue to the provided
// function.  It also invokes heap.BlockInit on the priority queue using the new
// function so it can immediately be used with heap.Push/Pop.
func (pq *txPriorityQueue) SetLessFunc(lessFunc txPriorityQueueLessFunc) {
	pq.lessFunc = lessFunc
	heap.Init(pq)
}

// txPQByPriority sorts a txPriorityQueue by transaction priority and then fees
// per kilobyte.
func txPQByPriority(pq *txPriorityQueue, i, j int) bool {
	// Using > here so that pop gives the highest priority item as opposed
	// to the lowest.  Sort by priority first, then fee.
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}
	return pq.items[i].priority > pq.items[j].priority

}

// txPQByFee sorts a txPriorityQueue by fees per kilobyte and then transaction
// priority.
func txPQByFee(pq *txPriorityQueue, i, j int) bool {
	// Using > here so that pop gives the highest fee item as opposed
	// to the lowest.  Sort by fee first, then priority.
	if pq.items[i].feePerKB == pq.items[j].feePerKB {
		return pq.items[i].priority > pq.items[j].priority
	}
	return pq.items[i].feePerKB > pq.items[j].feePerKB
}

// newTxPriorityQueue returns a new transaction priority queue that reserves the
// passed amount of space for the elements.  The new priority queue uses either
// the txPQByPriority or the txPQByFee compare function depending on the
// sortByFee parameter and is already initialized for use with heap.Push/Pop.
// The priority queue can grow larger than the reserved space, but extra copies
// of the underlying array can be avoided by reserving a sane value.
func newTxPriorityQueue(reserve int, sortByFee bool) *txPriorityQueue {
	pq := &txPriorityQueue{
		items: make([]*txPrioItem, 0, reserve),
	}
	if sortByFee {
		pq.SetLessFunc(txPQByFee)
	} else {
		pq.SetLessFunc(txPQByPriority)
	}
	return pq
}

// BlockTemplate houses a block that has yet to be solved along with additional
// details about the fees and the number of signature operations for each
// transaction in the block.
type BlockTemplate struct {
	// Block is a block that is ready to be solved by miners.  Thus, it is
	// completely valid with the exception of satisfying the proof-of-work
	// requirement.
	Block interface{}		// wire.MsgBlock

	// Fees contains the amount of fees each transaction in the generated
	// template pays in base units.  Since the first transaction is the
	// coinbase, the first entry (offset 0) will contain the negative of the
	// sum of the fees of all other transactions.
	Fees []int64

	// SigOpCosts contains the number of signature operations each
	// transaction in the generated template performs.
	SigOpCosts []int64

	// Height is the height at which the block template connects to the main
	// Chain.
	Height int32

	// Bits is difficulty
	Bits   uint32

	// ValidPayAddress indicates whether or not the template coinbase pays
	// to an address or is redeemable by anyone.  See the documentation on
	// NewBlockTemplate for details on which this can be useful to generate
	// templates without a coinbase payment address.
	ValidPayAddress bool

	// WitnessCommitment is a commitment to the witness data (if any)
	// within the block. This field will only be populted once segregated
	// witness has been activated, and the block contains a transaction
	// which has witness data.
	WitnessCommitment []byte
}

// mergeUtxoView adds all of the entries in viewB to viewA.  The result is that
// viewA will contain all of its original entries plus all of the entries
// in viewB.  It will replace any entries in viewB which also exist in viewA
// if the entry in viewA is spent.
func mergeUtxoView(viewA *viewpoint.UtxoViewpoint, viewB *viewpoint.UtxoViewpoint) {
	viewAEntries := viewA.Entries()
	for outpoint, entryB := range viewB.Entries() {
		if entryA, exists := viewAEntries[outpoint]; !exists ||
			entryA == nil || entryA.IsSpent() {

			viewAEntries[outpoint] = entryB
		}
	}
}

// standardCoinbaseScript returns a standard script suitable for use as the
// signature script of the coinbase transaction of a new block.  In particular,
// it starts with the block height that is required by version 2 blocks and adds
// the extra nonce as well as additional coinbase flags.
func standardCoinbaseScript(nextBlockHeight int32, extraNonce uint64) ([]byte, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint64(nextBlockHeight))
	binary.Write(&buf, binary.LittleEndian, uint64(extraNonce))
	buf.Write([]byte(CoinbaseFlags))
	return buf.Bytes(), nil
}

// createCoinbaseTx returns a coinbase transaction paying an appropriate subsidy
// based on the passed block height to the provided address.  When the address
// is nil, the coinbase transaction will instead be redeemable by anyone.
//
// See the comment for NewBlockTemplate for more information about why the nil
// address handling is useful.
func createCoinbaseTx(params *chaincfg.Params, nextBlockHeight int32, addrs []btcutil.Address, chain *blockchain.BlockChain) (*btcutil.Tx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and we use index portion to store nextBlockHeight so Coinbase transactions
		// for different blocks will have different hash even when they have same outputs.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{}, uint32(nextBlockHeight)),
		SignatureIndex: 0xFFFFFFFF,
		Sequence:        wire.MaxTxInSequenceNum,
	})

	prevPows := uint(0)
	adj := int64(0)
	best := chain.BestSnapshot()
	for pw := chain.BestChain.Tip(); pw != nil && pw.Data.GetNonce() > 0; pw = pw.Parent {
		prevPows++
	}
	if prevPows != 0 {
		adj = blockchain.CalcBlockSubsidy(best.Height, params, 0) -
			blockchain.CalcBlockSubsidy(best.Height, params, prevPows)
	}

	award := blockchain.CalcBlockSubsidy(nextBlockHeight, params, prevPows)
	if award < params.MinimalAward {
		award = params.MinimalAward
	}

	val := award + adj
	val /= int64(len(addrs))

	for _,addr := range addrs {
		t := token.Token{
			TokenType: 0,
			Value:    &token.NumToken{
				Val: val,
			},
		}

		// Create the script to pay to the provided payment address if one was
		// specified.  Otherwise create a script that allows the coinbase to be
		// redeemable by anyone.
		pkScript := make([]byte, 25)
		if addr != nil {
			pkScript[0] = addr.Version()
			copy(pkScript[1:], addr.ScriptAddress())
			pkScript[21] = ovm.OP_PAY2PKH
		} else {
			pkScript[0] = params.PubKeyHashAddrID
			pkScript[1] = 1			// anything but 0
			pkScript[21] = ovm.OP_PAY2NONE
		}

		tx.AddTxOut(&wire.TxOut{
			Token:    t,
			PkScript: pkScript,
		})
	}
	return btcutil.NewTx(tx), nil
}

// spendTransaction updates the passed view by marking the inputs to the passed
// transaction as spent.  It also adds all outputs in the passed transaction
// which are not provably unspendable as available unspent transaction outputs.
func spendTransaction(utxoView *viewpoint.ViewPointSet, tx *btcutil.Tx, height int32) error {
	for _, txIn := range tx.MsgTx().TxIn {
		if txIn.IsSeparator() {
			continue
		}
		entry := utxoView.Utxo.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil {
			entry.Spend()
		}
	}

	utxoView.AddTxOuts(tx, height)
	return nil
}

// logSkippedDeps logs any dependencies which are also skipped as a result of
// skipping a transaction while generating a block template at the trace level.
func logSkippedDeps(tx *btcutil.Tx, deps map[chainhash.Hash]*txPrioItem) {
	if deps == nil {
		return
	}

	for _, item := range deps {
		log.Tracef("Skipping tx %s since it depends on %s\n",
			item.tx.Hash(), tx.Hash())
	}
}

// MinimumMedianTime returns the minimum allowed timestamp for a block building
// on the end of the provided best Chain.  In particular, it is one second after
// the median timestamp of the last several blocks per the Chain consensus
// rules.
func MinimumMedianTime(chainState *blockchain.BestState) time.Time {
	return chainState.MedianTime.Add(time.Second)
}

// medianAdjustedTime returns the current time adjusted to ensure it is at least
// one second after the median timestamp of the last several blocks per the
// Chain consensus rules.
func medianAdjustedTime(chainState *blockchain.BestState, timeSource chainutil.MedianTimeSource) time.Time {
	// The timestamp for the block must not be before the median timestamp
	// of the last several blocks.  Thus, choose the maximum between the
	// current time and one second after the past median time.  The current
	// timestamp is truncated to a second boundary before comparison since a
	// block timestamp does not supported a precision greater than one
	// second.
	newTimestamp := timeSource.AdjustedTime()
	minTimestamp := MinimumMedianTime(chainState)
	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	return newTimestamp
}

// BlkTmplGenerator provides a type that can be used to generate block templates
// based on a given mining policy and source of transactions to choose from.
// It also houses additional state required in order to ensure the templates
// are built on top of the current best Chain and adhere to the consensus rules.
type BlkTmplGenerator struct {
	policy      *Policy
	chainParams *chaincfg.Params
	txSource    TxSource
	Chain       *blockchain.BlockChain
	timeSource  chainutil.MedianTimeSource

	// only used by minerchain
	Collateral *wire.OutPoint
//	sigCache    *txscript.SigCache
//	hashCache   *txscript.HashCache
}

// NewBlkTmplGenerator returns a new block template generator for the given
// policy using transactions from the provided transaction source.
//
// The additional state-related fields are required in order to ensure the
// templates are built on top of the current best Chain and adhere to the
// consensus rules.
func NewBlkTmplGenerator(policy *Policy, params *chaincfg.Params,
	txSource TxSource, chain *blockchain.BlockChain,
	timeSource chainutil.MedianTimeSource) *BlkTmplGenerator {
//	sigCache *txscript.SigCache,
//	hashCache *txscript.HashCache) *BlkTmplGenerator {

	return &BlkTmplGenerator{
		policy:      policy,
		chainParams: params,
		txSource:    txSource,
		Chain:       chain,
		timeSource:  timeSource,
		Collateral:  nil,
//		sigCache:    sigCache,
//		hashCache:   hashCache,
	}
}

// NewBlockTemplate returns a new block template that is ready to be solved
// using the transactions from the passed transaction source pool and a coinbase
// that either pays to the passed address if it is not nil, or a coinbase that
// is redeemable by anyone if the passed address is nil.  The nil address
// functionality is useful since there are cases such as the getblocktemplate
// RPC where external mining software is responsible for creating their own
// coinbase which will replace the one generated for the block template.  Thus
// the need to have configured address can be avoided.
//
// The transactions selected and included are prioritized according to several
// factors.  First, each transaction has a priority calculated based on its
// value, age of inputs, and size.  Height which consist of larger
// amounts, older inputs, and small sizes have the highest priority.  Second, a
// fee per kilobyte is calculated for each transaction.  Height with a
// higher fee per kilobyte are preferred.  Finally, the block generation related
// policy settings are all taken into account.
//
// Height which only spend outputs from other transactions already in the
// block Chain are immediately added to a priority queue which either
// prioritizes based on the priority (then fee per kilobyte) or the fee per
// kilobyte (then priority) depending on whether or not the BlockPrioritySize
// policy setting allots space for high-priority transactions.  Height
// which spend outputs from other transactions in the source pool are added to a
// dependency map so they can be added to the priority queue once the
// transactions they depend on have been included.
//
// Once the high-priority area (if configured) has been filled with
// transactions, or the priority falls below what is considered high-priority,
// the priority queue is updated to prioritize by fees per kilobyte (then
// priority).
//
// When the fees per kilobyte drop below the TxMinFreeFee policy setting, the
// transaction will be skipped unless the BlockMinSize policy setting is
// nonzero, in which case the block will be filled with the low-fee/free
// transactions until the block size reaches that minimum size.
//
// Height sending output to a contract will cause the contract executed,
// and, if successful, the augumented (by the contract) will be added to the
// template. If a transaction has multiple contract outputs, contracts will be
// executed in the order they appear in the transaction output list.
//
// Any transactions which would cause the block to exceed the BlockMaxSize
// policy setting, exceed the maximum allowed signature operations per block, or
// otherwise cause the block to be invalid are skipped.
//
// Given the above, a block generated by this function is of the following form:
//
//   -----------------------------------  --  --
//  |      Coinbase Transaction         |   |   |
//  |-----------------------------------|   |   |
//  |                                   |   |   | ----- policy.BlockPrioritySize
//  |   High-priority Height      |   |   |
//  |                                   |   |   |
//  |-----------------------------------|   | --
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |--- policy.BlockMaxSize
//  |  Height prioritized by fee  |   |
//  |  until <= policy.TxMinFreeFee     |   |
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |
//  |-----------------------------------|   |
//  |  Low-fee/Non high-priority (free) |   |
//  |  transactions (while block size   |   |
//  |  <= policy.BlockMinSize)          |   |
//   -----------------------------------  --
func (g *BlkTmplGenerator) NewBlockTemplate(payToAddress []btcutil.Address, nonce int32) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.Chain.BestSnapshot()
	nextBlockHeight := best.Height + 1

	// Create a standard coinbase transaction paying to the provided
	// addresses.  NOTE: The coinbase value will be updated to include the
	// fees from the selected transactions later after they have actually
	// been selected.  It is created here to detect any errors early
	// before potentially doing a lot of work below.
	coinbaseTx, err := createCoinbaseTx(g.chainParams, nextBlockHeight, payToAddress, g.Chain)
	if err != nil {
		return nil, err
	}
	coinbaseSigOpCost := int64(blockchain.CountSigOps(coinbaseTx))	// * chaincfg.WitnessScaleFactor

	// Get the current source transactions and create a priority queue to
	// hold the transactions which are ready for inclusion into a block
	// along with some priority related and fee metadata.  Reserve the same
	// number of items that are available for the priority queue.  Also,
	// choose the initial sort order for the priority queue based on whether
	// or not there is an area allocated for high-priority transactions.
	sourceTxns := g.txSource.MiningDescs()
	sortedByFee := g.policy.BlockPrioritySize == 0
	priorityQueue := newTxPriorityQueue(len(sourceTxns), sortedByFee)

	// Create a slice to hold the transactions to be included in the
	// generated block with reserved space.  Also create a utxo view to
	// house all of the input transactions so multiple lookups can be
	// avoided.
	blockTxns := make([]*btcutil.Tx, 0, len(sourceTxns))
	blockTxns = append(blockTxns, coinbaseTx)

	views, Vm := g.Chain.Canvas(nil)

	blockUtxos := views.Utxo	// blockchain.NewUtxoViewpoint()

	// dependers is used to track transactions which depend on another
	// transaction in the source pool.  This, in conjunction with the
	// dependsOn map kept with each dependent transaction helps quickly
	// determine which dependent transactions are now eligible for inclusion
	// in the block once each transaction has been included.
	dependers := make(map[chainhash.Hash]map[chainhash.Hash]*txPrioItem)

	// Create slices to hold the fees and number of signature operations
	// for each of the selected transactions and add an entry for the
	// coinbase.  This allows the code below to simply append details about
	// a transaction as it is selected for inclusion in the final block.
	// However, since the total fees aren't known yet, use a dummy value for
	// the coinbase fee which will be updated later.
	txFees := make([]int64, 0, len(sourceTxns))
	txSigOpCosts := make([]int64, 0, len(sourceTxns))
	txFees = append(txFees, -1) // Updated once known
	txSigOpCosts = append(txSigOpCosts, coinbaseSigOpCost)

	log.Debugf("Considering %d transactions for inclusion to new block",
		len(sourceTxns))
	utxos := views.Utxo

	// The timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the Chain consensus rules.
	ts := medianAdjustedTime(best, g.timeSource)

	prev := g.Chain.NodeByHeight(best.Height)
	if ts.Unix() < prev.Data.TimeStamp() {
		ts = time.Unix(prev.Data.TimeStamp(), 0)
	}

mempoolLoop:
	for _, txDesc := range sourceTxns {
		// A block can't have more than one coinbase or contain
		// non-finalized transactions.
		tx := txDesc.Tx
		tx.MsgTx().Strip()
		tx.HasIns, tx.HasDefs, tx.HasOuts = false, false, false
		if blockchain.IsCoinBase(tx) {
			log.Tracef("Skipping coinbase tx %s", tx.Hash())
			continue
		}
		if !blockchain.IsFinalizedTransaction(tx, nextBlockHeight,
			g.timeSource.AdjustedTime()) {

			log.Tracef("Skipping non-finalized tx %s", tx.Hash())
			continue
		}

		// Fetch all of the utxos referenced by the this transaction.
		// NOTE: This intentionally does not fetch inputs from the
		// mempool since a transaction which depends on other
		// transactions in the mempool must come after those
		// dependencies in the final generated block.
//		view, err := g.Chain.FetchUtxoView(tx)
//		if err != nil {
//			log.Warnf("Unable to fetch utxo view for tx %s: %v",
//				tx.Hash(), err)
//			continue
//		}

		// Setup dependencies for any transactions which reference
		// other transactions in the mempool so they can be properly
		// ordered below.
		prioItem := &txPrioItem{tx: tx}
		for _, txIn := range tx.MsgTx().TxIn {
			if txIn.IsSeparator() {
				// never here
				continue
			}
			originHash := &txIn.PreviousOutPoint.Hash
			entry := views.GetUtxo(txIn.PreviousOutPoint)
			if entry == nil || entry.IsSpent() {
				if !g.txSource.HaveTransaction(originHash) {
					log.Tracef("Skipping tx %s because it "+
						"references unspent output %s "+
						"which is not available",
						tx.Hash(), txIn.PreviousOutPoint)
					continue mempoolLoop
				}

				// The transaction is referencing another
				// transaction in the source pool, so setup an
				// ordering dependency.
				deps, exists := dependers[*originHash]
				if !exists {
					deps = make(map[chainhash.Hash]*txPrioItem)
					dependers[*originHash] = deps
				}
				deps[*prioItem.tx.Hash()] = prioItem
				if prioItem.dependsOn == nil {
					prioItem.dependsOn = make(
						map[chainhash.Hash]struct{})
				}
				prioItem.dependsOn[*originHash] = struct{}{}

				// Skip the check below. We already know the
				// referenced transaction is available.
				continue
			}
		}

		// Calculate the final transaction priority using the input
		// value age sum as well as the adjusted transaction size.  The
		// formula is: sum(inputValue * inputAge) / adjustedTxSize
		prioItem.priority = CalcPriority(tx.MsgTx(), utxos,
			nextBlockHeight)

		// Calculate the fee in Satoshi/kB.
		prioItem.feePerKB = txDesc.FeePerKB
		prioItem.fee = txDesc.Fee

		// Add the transaction to the priority queue to mark it ready
		// for inclusion in the block unless it has dependencies.
		if prioItem.dependsOn == nil {
			heap.Push(priorityQueue, prioItem)
		}

		// Merge the referenced outputs from the input transactions to
		// this transaction into the block utxo view.  This allows the
		// code below to avoid a second lookup.
//		mergeUtxoView(blockUtxos, utxos)
	}

	log.Tracef("Priority queue len %d, dependers len %d",
		priorityQueue.Len(), len(dependers))

	// The starting block size is the size of the block header plus the max
	// possible transaction count size, plus the size of the coinbase
	// transaction.
//	blockWeight := uint32((blockHeaderOverhead * chaincfg.WitnessScaleFactor) +
//		blockchain.GetTransactionWeight(coinbaseTx))
	blockWeight := uint32(1)	// blockchain.GetTransactionWeight(coinbaseTx))
	blockSigOpCost := coinbaseSigOpCost
	totalFees := int64(0)

	blockMaxSize := g.Chain.GetBlockLimit(nextBlockHeight)
	coinBaseHash := chainhash.Hash{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }
	// we don't know coin Base Hash until we know all tx fees in the block.
	// we don't know all tx fees until all contracts are executed.
	// contract adds output to coinbase when mint, since we don't know coin Base Hash,
	// we use a neg hash to hold the place.

	Vm.SetCoinBaseOp(
		func(txo wire.TxOut) wire.OutPoint {
			msg := coinbaseTx.MsgTx()
			if !coinbaseTx.HasOuts {
				// this servers as a separater. only TokenType is serialized
				to := wire.TxOut{}
				to.Token = token.Token{TokenType:token.DefTypeSeparator}
				msg.AddTxOut(&to)
				coinbaseTx.HasOuts = true
			}
			msg.AddTxOut(&txo)
			op := wire.OutPoint { coinBaseHash, uint32(len(msg.TxOut) - 1)}
			views.Utxo.AddRawTxOut(op, &txo, false, nextBlockHeight)
			return op
		})
	Vm.BlockNumber = func() uint64 {
		return uint64(nextBlockHeight)
	}
	Vm.BlockTime = func() uint32 {
		return uint32(ts.Unix())
	}
//	Vm.Block = func() *btcutil.Block { return nil }
	Vm.GetCoinBase = func() *btcutil.Tx { return coinbaseTx }
	Vm.CheckExecCost = true

	paidstoragefees := make(map[[20]byte]int64)

	// Choose which transactions make it into the block.
	for priorityQueue.Len() > 0 {
		// Grab the highest priority (or highest fee per kilobyte
		// depending on the sort order) transaction.
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		tx := prioItem.tx

		// Grab any transactions which depend on this one.
		deps := dependers[*tx.Hash()]

		// Enforce maximum block size.  Also check for overflow.
//		txWeight := uint32(blockchain.GetTransactionWeight(tx))
		blockPlusTxWeight := blockWeight + 1
		if blockPlusTxWeight >= blockMaxSize {
			log.Tracef("Skipping tx %s because it would exceed "+
				"the max block weight", tx.Hash())
			logSkippedDeps(tx, deps)
			continue
		}

		// Enforce maximum signature operation cost per block.  Also
		// check for overflow.
		sigOpCost, err := blockchain.GetSigOpCost(tx, false,
			blockUtxos, true, true)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"GetSigOpCost: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}
		if blockSigOpCost+int64(sigOpCost) < blockSigOpCost ||
			blockSigOpCost+int64(sigOpCost) > chaincfg.MaxBlockSigOpsCost {
			log.Tracef("Skipping tx %s because it would "+
				"exceed the maximum sigops per block", tx.Hash())
			logSkippedDeps(tx, deps)
			continue
		}

		// Skip free transactions once the block is larger than the
		// minimum block size.
		if sortedByFee &&
			prioItem.feePerKB < int64(g.policy.TxMinFreeFee) &&
			blockPlusTxWeight >= blockMaxSize {
			log.Tracef("Skipping tx %s with feePerKB %d "+
				"< TxMinFreeFee %d and block weight %d >= "+
				"minBlockWeight %d", tx.Hash(), prioItem.feePerKB,
				g.policy.TxMinFreeFee, blockPlusTxWeight,
				blockMaxSize)
			logSkippedDeps(tx, deps)
			continue
		}

		// Prioritize by fee per kilobyte once the block is larger than
		// the priority size or there are no more high-priority
		// transactions.
		if !sortedByFee && (blockPlusTxWeight >= g.policy.BlockPrioritySize ||
			prioItem.priority <= MinHighPriority) {
			log.Tracef("Switching to sort by fees per "+
				"kilobyte blockSize %d >= BlockPrioritySize "+
				"%d || priority %.2f <= minHighPriority %.2f",
				blockPlusTxWeight, g.policy.BlockPrioritySize,
				prioItem.priority, MinHighPriority)

			sortedByFee = true
			priorityQueue.SetLessFunc(txPQByFee)

			// Put the transaction back into the priority queue and
			// skip it so it is re-priortized by fees if it won't
			// fit into the high-priority section or the priority
			// is too low.  Otherwise this transaction will be the
			// final one in the high-priority section, so just fall
			// though to the code below so it is added now.
			if blockPlusTxWeight > g.policy.BlockPrioritySize ||
				prioItem.priority < MinHighPriority {

				heap.Push(priorityQueue, prioItem)
				continue
			}
		}

		// Ensure the transaction inputs pass all of the necessary
		// preconditions before allowing it to be added to the block.
		err = blockchain.CheckTransactionInputs(tx, nextBlockHeight,
			views, g.chainParams)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionInputs: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		err = ovm.VerifySigs(tx, nextBlockHeight, g.chainParams, views)
		if err != nil {
			g.txSource.RemoveTransaction(tx, true)

			// we should roll back result of last contract execution here
			log.Infof("Remove tx %s due to error in "+
				"VerifySigs: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		// excute contracts if necessary. note, if the execution causes any change in
		// in transaction, a new copy of tx will be returned.
		savedCoinBase := *coinbaseTx.MsgTx().Copy()
		newcoins := coinbaseTx.HasOuts
		Vm.Paidfees = prioItem.fee
		err = Vm.ExecContract(tx, nextBlockHeight)
		if err != nil {
			coinbaseTx.HasOuts = newcoins
			*coinbaseTx.MsgTx() = savedCoinBase

			g.txSource.RemoveTransaction(tx, true)

			log.Infof("Remove tx %s due to error in "+
				"ExecContract: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		storage := blockchain.ContractNewStorage(tx, Vm, paidstoragefees)

		tx.Executed = true

		err = blockchain.CheckAdditionalTransactionInputs(tx, nextBlockHeight,
			views, g.chainParams)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionInputs: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		err = blockchain.CheckTransactionIntegrity(tx, views)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionIntegrity: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		fees, err := blockchain.CheckTransactionFees(tx, nextBlockHeight, storage, views, g.chainParams)
		if err != nil {
			g.txSource.RemoveTransaction(tx, true)
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionFeess: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		prioItem.fee = fees

		// Spend the transaction inputs in the block utxo view and add
		// an entry for it to ensure any transactions which reference
		// this one have it available as an input and can ensure they
		// aren't double spending.
		spendTransaction(views, tx, nextBlockHeight)

		// Add the transaction to the block, increment counters, and
		// save the fees and signature operation counts to the block
		// template.
		blockTxns = append(blockTxns, tx)
		blockWeight++ 	// += txWeight
		blockSigOpCost += int64(sigOpCost)
		totalFees += prioItem.fee
		txFees = append(txFees, prioItem.fee)
		txSigOpCosts = append(txSigOpCosts, int64(sigOpCost))

		log.Tracef("Adding tx %s (priority %.2f, feePerKB %.2f)",
			prioItem.tx.Hash(), prioItem.priority, prioItem.feePerKB)

		// Add transactions which depend on this one (and also do not
		// have any other unsatisified dependencies) to the priority
		// queue.
		for _, item := range deps {
			// Add the transaction to the priority queue if there
			// are no more dependencies after this one.
			delete(item.dependsOn, *tx.Hash())
			if len(item.dependsOn) == 0 {
				heap.Push(priorityQueue, item)
			}
		}
	}

	contractExec := uint64(g.Chain.ChainParams.ContractExecLimit) - Vm.GasLimit

	// add fees to miner outputs
	m := int64(0)
	for _, txo := range coinbaseTx.MsgTx().TxOut {
		if txo.IsSeparator() {
			break
		}
		m++
	}
	df := totalFees / m
	for _, txo := range coinbaseTx.MsgTx().TxOut {
		if txo.IsSeparator() {
			break
		}
		txo.Value.(*token.NumToken).Val += df
	}
	coinbaseTx.Executed = true

	txFees[0] = -totalFees

	// now the hash is fixed, back fill hashes in tx
	hash := coinbaseTx.Hash()
	for _,tx := range blockTxns {
		for _,txin := range tx.MsgTx().TxIn {
			if txin.PreviousOutPoint.Hash.IsEqual(&coinBaseHash) {
				txin.PreviousOutPoint.Hash = *hash
			}
		}
	}

	// Next, obtain the merkle root of a tree which consists of the
	// wtxid of all transactions in the block. The coinbase
	// transaction will have a special wtxid of all zeroes.
	witnessMerkleTree := blockchain.BuildMerkleTreeStore(blockTxns,true)
	witnessMerkleRoot := witnessMerkleTree[len(witnessMerkleTree)-1]

	msg := coinbaseTx.MsgTx()
	if msg.SignatureScripts == nil || len(msg.SignatureScripts) == 0 {
		msg.SignatureScripts = make([][]byte, 1)
	}

	msg.SignatureScripts[0] = (*witnessMerkleRoot)[:]

	// Calculate the required difficulty for the block.
	rotate := best.LastRotation

	s, err := g.Chain.Miners.BlockByHeight(int32(rotate))
	if err != nil || s == nil {
		return nil, fmt.Errorf("Miner chain not ready.")
	}
	reqDifficulty := s.MsgBlock().Bits

//	reqDifficulty := g.Chain.BestSnapshot().Bits

	// Create a new block ready to be solved.
	merkles := blockchain.BuildMerkleTreeStore(blockTxns, false)
	var msgBlock wire.MsgBlock
	msgBlock.Header = wire.BlockHeader{
		Version:    0x10000,
		PrevBlock:  best.Hash,
		MerkleRoot: *merkles[len(merkles)-1],
		Timestamp:  ts,
		ContractExec: contractExec,
		Nonce: nonce,
	}

	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	// Finally, perform a full check on the created block against the Chain
	// consensus rules to ensure it properly connects to the current best
	// Chain with no issues.
	block := btcutil.NewBlock(&msgBlock)
	block.SetHeight(nextBlockHeight)
	if err := g.Chain.CheckConnectBlockTemplate(block); err != nil {
		return nil, err
	}

	log.Debugf("Created new block template (%d transactions, %d in "+
		"fees, %d signature operations cost, target difficulty "+
		"%064x)", len(msgBlock.Transactions), totalFees, blockSigOpCost,
		blockchain.CompactToBig(reqDifficulty))

	return &BlockTemplate{
		Block:             &msgBlock,
		Fees:              txFees,
		SigOpCosts:        txSigOpCosts,
		Height:            nextBlockHeight,
		ValidPayAddress:   payToAddress != nil,
		WitnessCommitment: (*witnessMerkleRoot)[:],
		Bits:       reqDifficulty,
	}, nil
}

func (g *BlkTmplGenerator) NewMinerBlockTemplate(last *chainutil.BlockNode, payToAddress btcutil.Address) (*BlockTemplate, error) {
	// Extend the most recently known best block
	// instead of extending the longest MR chain, we will try to entend
	// a best chain that will allow us to refer the tip of TX chain as
	// best block. In most time, it would be the longest MR chain. But if
	// the longest MR chain refers to a stalled TX side chain, we should
	// switch to a side chain.

	//	best := g.Chain.Miners.BestSnapshot()
	nextBlockHeight := last.Height + 1
	lastBlk := g.Chain.Miners.NodetoHeader(last)

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the Chain consensus rules.
//	ts := medianAdjustedTime(best, g.timeSource)

	ts := g.timeSource.AdjustedTime()
	ts2 := last.CalcPastMedianTime().Add(time.Second)
	if ts.Before(ts2) {
		ts = ts2
	}

//	reqDifficulty, err := g.Chain.Miners.CalcNextRequiredDifficulty(ts)

	reqDifficulty, coll, err := g.Chain.Miners.NextRequiredDifficulty(last, ts)

	if err != nil {
		return nil, err
	}

	// Calculate the next expected block version based on the state of the
	// rule change deployments.
	nextBlockVersion, err := g.Chain.Miners.NextBlockVersion(last)
	if err != nil {
		return nil, err
	}

	if nextBlockVersion < 0x20000 {
		coll = 0
	}

	cbest := g.Chain.BestSnapshot()
	bh := cbest.Height

	h0,_ := g.Chain.BlockHeightByHash(&lastBlk.BestBlock)
	if bh < h0  {
		return nil, nil
	}

//	utxos := g.Chain.FetchMycoins(wire.Collateral(nextBlockHeight))
//	if utxos == nil {
//		return nil, fmt.Errorf("Insufficient collateral.")
//	}

	// Create a new block ready to be solved.
	msgBlock := wire.MingingRightBlock{
		Version:       nextBlockVersion,
		PrevBlock:     last.Hash,
		Timestamp:     ts,
		Bits:          reqDifficulty,
		Collateral:	   coll,
		BestBlock:     cbest.Hash,
		Utxos:		   g.Collateral,
		BlackList:     make([]wire.BlackList, 0),
	}

	copy(msgBlock.Miner[:], payToAddress.ScriptAddress())
	if nextBlockVersion >= 0x20000 {
		msgBlock.TphReports = g.Chain.Miners.TphReport(wire.MinTPSReports, last, msgBlock.Miner)
	}

	// Finally, perform a full check on the created block against the Chain
	// consensus rules to ensure it properly connects to the current best
	// Chain with no issues.
	block := wire.NewMinerBlock(&msgBlock)
	block.SetHeight(nextBlockHeight)
	if err := g.Chain.Miners.CheckConnectBlockTemplate(block); err != nil {
		return nil, err
	}

	return &BlockTemplate{
		Block:             &msgBlock,
		Bits:			   reqDifficulty,
		Fees:              nil,
		SigOpCosts:        nil,
		Height:            nextBlockHeight,
		ValidPayAddress:   payToAddress != nil,
		WitnessCommitment: nil,
	}, nil
}

// UpdateBlockTime updates the timestamp in the header of the passed block to
// the current time while taking into account the median time of the last
// several blocks to ensure the new time is after that time per the Chain
// consensus rules.  Finally, it will update the target difficulty if needed
// based on the new time for the test networks since their target difficulty can
// change based upon time.

// can't just update it w/o re-do contracts because a contract may use block time
/*
func (g *BlkTmplGenerator) UpdateBlockTime(msgBlock *wire.MsgBlock) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the Chain consensus
	// rules.
	newTime := medianAdjustedTime(g.Chain.BestSnapshot(), g.timeSource)
	msgBlock.Header.Timestamp = newTime

	return nil
}
 */

func (g *BlkTmplGenerator) UpdateMinerBlockTime(msgBlock *wire.MingingRightBlock) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the Chain consensus
	// rules.
	newTime := medianAdjustedTime(g.Chain.BestSnapshot(), g.timeSource)
	msgBlock.Timestamp = newTime

	return nil
}

// BestSnapshot returns information about the current best Chain block and
// related state as of the current point in time using the Chain instance
// associated with the block template generator.  The returned state must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (g *BlkTmplGenerator) BestSnapshot() *blockchain.BestState {
	return g.Chain.BestSnapshot()
}

func (g *BlkTmplGenerator) BestMinerSnapshot() *blockchain.BestState {
	return g.Chain.Miners.BestSnapshot()
}

// TxSource returns the associated transaction source.
//
// This function is safe for concurrent access.
func (g *BlkTmplGenerator) TxSource() TxSource {
	return g.txSource
}

func (g *BlkTmplGenerator) ActiveMiner(address btcutil.Address) bool {
	h := g.BestSnapshot().LastRotation		// .Chain.LastRotation(g.BestSnapshot().Hash)
	n := h - wire.CommitteeSize
	for n < h {
		n++
		m,_ := g.Chain.Miners.BlockByHeight(int32(n))
		if bytes.Compare(address.ScriptAddress(), m.MsgBlock().Miner[:]) == 0 {
			// if it is in committee, not allowed to do POW mining
			return true
		}
	}

	return false
}

func (g *BlkTmplGenerator) Committee() map[[20]byte]struct{} {
	h := g.BestSnapshot().LastRotation		// .Chain.LastRotation(g.BestSnapshot().Hash)

	log.Infof("Get committee at last rotation = %d", h)

	adrs := make(map[[20]byte]struct{})

	for n := h - wire.CommitteeSize + 1; n <= h; n++ {
		if m,_ := g.Chain.Miners.BlockByHeight(int32(n)); m != nil {
			adrs[m.MsgBlock().Miner] = struct{}{}
		}
	}

	return adrs
}

func AddSignature(block * btcutil.Block, privkey *btcec.PrivateKey) {
	hash := blockchain.MakeMinerSigHash(block.Height(), *block.Hash())

	sig,_ := privkey.Sign(hash)
	pubk := privkey.PubKey().SerializeCompressed()	// 33 bytes always
	st := sig.Serialize()
	if block.MsgBlock().Transactions[0].SignatureScripts == nil || len(block.MsgBlock().Transactions[0].SignatureScripts) == 0 {
		// signature 0 of coinbase is for signature merkle root
		block.MsgBlock().Transactions[0].SignatureScripts = make([][]byte, 1)
		block.MsgBlock().Transactions[0].SignatureScripts[0] = []byte{}
	}
	block.MsgBlock().Transactions[0].SignatureScripts = append(block.MsgBlock().Transactions[0].SignatureScripts, append(pubk, st...))
}