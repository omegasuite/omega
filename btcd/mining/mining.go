// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

import (
	"bytes"
	"container/heap"
	"time"

	"encoding/binary"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"github.com/btcsuite/omega/viewpoint"
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
// function.  It also invokes heap.Init on the priority queue using the new
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
func createCoinbaseTx(params *chaincfg.Params, nextBlockHeight int32, addr btcutil.Address) (*btcutil.Tx, error) {
	// Create the script to pay to the provided payment address if one was
	// specified.  Otherwise create a script that allows the coinbase to be
	// redeemable by anyone.
	pkScript := make([]byte, 25)
	if addr != nil {
		pkScript[0] = addr.Version()
		copy(pkScript[1:], addr.ScriptAddress())
		pkScript[21] = 0x41
	} else {
		pkScript[0] = 0x6F
		pkScript[1] = 1		// anything but 0
		pkScript[21] = 0x45
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex),
		SignatureIndex: 0xFFFFFFFF,
		Sequence:        wire.MaxTxInSequenceNum,
	})

	t := token.Token{
		TokenType: 0,
		Value:    &token.NumToken{
			Val: blockchain.CalcBlockSubsidy(nextBlockHeight, params),
		},
	}
	tx.AddTxOut(&wire.TxOut{
		Token: t,
		PkScript: pkScript,
	})
	return btcutil.NewTx(tx), nil
}

// spendTransaction updates the passed view by marking the inputs to the passed
// transaction as spent.  It also adds all outputs in the passed transaction
// which are not provably unspendable as available unspent transaction outputs.
func spendTransaction(utxoView *viewpoint.ViewPointSet, tx *btcutil.Tx, height int32) error {
	for _, txIn := range tx.MsgTx().TxIn {
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
func medianAdjustedTime(chainState *blockchain.BestState, timeSource blockchain.MedianTimeSource) time.Time {
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
	timeSource  blockchain.MedianTimeSource
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
	timeSource blockchain.MedianTimeSource) *BlkTmplGenerator {
//	sigCache *txscript.SigCache,
//	hashCache *txscript.HashCache) *BlkTmplGenerator {

	return &BlkTmplGenerator{
		policy:      policy,
		chainParams: params,
		txSource:    txSource,
		Chain:       chain,
		timeSource:  timeSource,
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
// value, age of inputs, and size.  Transactions which consist of larger
// amounts, older inputs, and small sizes have the highest priority.  Second, a
// fee per kilobyte is calculated for each transaction.  Transactions with a
// higher fee per kilobyte are preferred.  Finally, the block generation related
// policy settings are all taken into account.
//
// Transactions which only spend outputs from other transactions already in the
// block Chain are immediately added to a priority queue which either
// prioritizes based on the priority (then fee per kilobyte) or the fee per
// kilobyte (then priority) depending on whether or not the BlockPrioritySize
// policy setting allots space for high-priority transactions.  Transactions
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
// Transactions sending output to a contract will cause the contract executed,
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
//  |   High-priority Transactions      |   |   |
//  |                                   |   |   |
//  |-----------------------------------|   | --
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |--- policy.BlockMaxSize
//  |  Transactions prioritized by fee  |   |
//  |  until <= policy.TxMinFreeFee     |   |
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |
//  |-----------------------------------|   |
//  |  Low-fee/Non high-priority (free) |   |
//  |  transactions (while block size   |   |
//  |  <= policy.BlockMinSize)          |   |
//   -----------------------------------  --
func (g *BlkTmplGenerator) NewBlockTemplate(payToAddress btcutil.Address) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.Chain.BestSnapshot()
	nextBlockHeight := best.Height + 1

	// Create a standard coinbase transaction paying to the provided
	// address.  NOTE: The coinbase value will be updated to include the
	// fees from the selected transactions later after they have actually
	// been selected.  It is created here to detect any errors early
	// before potentially doing a lot of work below.

	coinbaseTx, err := createCoinbaseTx(g.chainParams, nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}
	coinbaseSigOpCost := int64(blockchain.CountSigOps(coinbaseTx)) * chaincfg.WitnessScaleFactor

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

	views := g.Chain.NewViewPointSet()
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

mempoolLoop:
	for _, txDesc := range sourceTxns {
		// A block can't have more than one coinbase or contain
		// non-finalized transactions.
		tx := txDesc.Tx
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
		utxos, err := g.Chain.FetchUtxoView(tx)
		if err != nil {
			log.Warnf("Unable to fetch utxo view for tx %s: %v",
				tx.Hash(), err)
			continue
		}

		// Setup dependencies for any transactions which reference
		// other transactions in the mempool so they can be properly
		// ordered below.
		prioItem := &txPrioItem{tx: tx}
		for _, txIn := range tx.MsgTx().TxIn {
			originHash := &txIn.PreviousOutPoint.Hash
			entry := utxos.LookupEntry(txIn.PreviousOutPoint)
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
		mergeUtxoView(blockUtxos, utxos)
	}

	log.Tracef("Priority queue len %d, dependers len %d",
		priorityQueue.Len(), len(dependers))

	// The starting block size is the size of the block header plus the max
	// possible transaction count size, plus the size of the coinbase
	// transaction.
	blockWeight := uint32((blockHeaderOverhead * chaincfg.WitnessScaleFactor) +
		blockchain.GetTransactionWeight(coinbaseTx))
	blockSigOpCost := coinbaseSigOpCost
	totalFees := int64(0)

	// Choose which transactions make it into the block.
	for priorityQueue.Len() > 0 {
		// Grab the highest priority (or highest fee per kilobyte
		// depending on the sort order) transaction.
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		tx := prioItem.tx

		// Grab any transactions which depend on this one.
		deps := dependers[*tx.Hash()]

		// Enforce maximum block size.  Also check for overflow.
		txWeight := uint32(blockchain.GetTransactionWeight(tx))
		blockPlusTxWeight := blockWeight + txWeight
		if blockPlusTxWeight < blockWeight ||
			blockPlusTxWeight >= g.policy.BlockMaxWeight {

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
			blockPlusTxWeight >= g.policy.BlockMinWeight {

			log.Tracef("Skipping tx %s with feePerKB %d "+
				"< TxMinFreeFee %d and block weight %d >= "+
				"minBlockWeight %d", tx.Hash(), prioItem.feePerKB,
				g.policy.TxMinFreeFee, blockPlusTxWeight,
				g.policy.BlockMinWeight)
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

		err = g.Chain.Ovm().VerifySigs(tx, nextBlockHeight)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"VerifySigs: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		// excute contracts if necessary. note, if the execution causes any change in
		// in transaction, a new copy of tx will be returned.
		otx, err := g.Chain.Ovm().ExecContract(tx, 0, nextBlockHeight, g.chainParams)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"checkContract: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		if otx != nil {
			tx = otx
		}

		err = blockchain.CheckTransactionIntegrity(tx, views)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionIntegrity: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		fees, err := blockchain.CheckTransactionFees(tx, nextBlockHeight, views, g.chainParams)
		if err != nil {
			// we should roll back result of last contract execution here
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionFeess: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		prioItem.fee = fees

		//		err = blockchain.ValidateTransactionScripts(tx, blockUtxos)
//			0, g.sigCache,			g.hashCache)
//		if err != nil {
//			log.Tracef("Skipping tx %s due to error in "+
//				"ValidateTransactionScripts: %v", tx.Hash(), err)
//			logSkippedDeps(tx, deps)
//			continue
//		}

		// Spend the transaction inputs in the block utxo view and add
		// an entry for it to ensure any transactions which reference
		// this one have it available as an input and can ensure they
		// aren't double spending.
		spendTransaction(views, tx, nextBlockHeight)

		// Add the transaction to the block, increment counters, and
		// save the fees and signature operation counts to the block
		// template.
		blockTxns = append(blockTxns, tx)
		blockWeight += txWeight
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

	// Now that the actual transactions have been selected, update the
	// block weight for the real transaction count and coinbase value with
	// the total fees accordingly.
	blockWeight -= common.MaxVarIntPayload -
		(uint32(common.VarIntSerializeSize(uint64(len(blockTxns)))) *
			chaincfg.WitnessScaleFactor)
	coinbaseTx.MsgTx().TxOut[0].Value.(*token.NumToken).Val += totalFees
	txFees[0] = -totalFees

	// Next, obtain the merkle root of a tree which consists of the
	// wtxid of all transactions in the block. The coinbase
	// transaction will have a special wtxid of all zeroes.
	witnessMerkleTree := blockchain.BuildMerkleTreeStore(blockTxns,true)
	witnessMerkleRoot := witnessMerkleTree[len(witnessMerkleTree)-1]

	msg := coinbaseTx.MsgTx()
	if msg.SignatureScripts == nil || len(msg.SignatureScripts) == 0 {
		msg.SignatureScripts = make([][]byte, 1)
	}
	if msg.SignatureScripts[0] == nil {
		msg.SignatureScripts[0] = make([]byte, 0)
	}
	msg.SignatureScripts[0] = (*witnessMerkleRoot)[:]

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the Chain consensus rules.
	ts := medianAdjustedTime(best, g.timeSource)

	reqDifficulty := g.Chain.BestSnapshot().Bits
/*
	tip := g.Chain.BestChain.Tip()
	nonce := tip.Header().Nonce
	if nonce == -wire.MINER_RORATE_FREQ + 1 {
		// this is the rotation block, difficulty is the rotate-in miner block's difficulty
		p, _ := g.Chain.BlockByHeight(g.BestSnapshot().Height + nonce)
		h := - p.MsgBlock().Header.Nonce - wire.MINER_RORATE_FREQ
		m,_ := g.Chain.Miners.BlockByHeight(h + 1)
		reqDifficulty = m.MsgBlock().Bits
	}

- difficulty target will be set differently for each case. for POW mining, it is simply current
best state Bits
- for committee mining, it does not use difficulty target. however, best state Bits changes with each
rotation
- for miner mining, it is calculated for each block the traditional way
*/

/*	reqDifficulty, err := g.Chain.CalcNextRequiredDifficulty(ts)
	if err != nil {
		return nil, err
	}
*/

	// Calculate the next expected block version based on the state of the
	// rule change deployments.
	nextBlockVersion, err := g.Chain.CalcNextBlockVersion()
	if err != nil {
		return nil, err
	}

	// Create a new block ready to be solved.
	merkles := blockchain.BuildMerkleTreeStore(blockTxns, false)
	var msgBlock wire.MsgBlock
	msgBlock.Header = wire.BlockHeader{
		Version:    nextBlockVersion,
		PrevBlock:  best.Hash,
		MerkleRoot: *merkles[len(merkles)-1],
		Timestamp:  ts,
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
		"fees, %d signature operations cost, %d weight, target difficulty "+
		"%064x)", len(msgBlock.Transactions), totalFees, blockSigOpCost,
		blockWeight, blockchain.CompactToBig(reqDifficulty))

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

func (g *BlkTmplGenerator) NewMinerBlockTemplate(payToAddress btcutil.Address) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.Chain.Miners.BestSnapshot()
	nextBlockHeight := best.Height + 1

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the Chain consensus rules.
	ts := medianAdjustedTime(best, g.timeSource)

	reqDifficulty, err := g.Chain.Miners.CalcNextRequiredDifficulty(ts)
	if err != nil {
		return nil, err
	}

	// Calculate the next expected block version based on the state of the
	// rule change deployments.
	nextBlockVersion, err := g.Chain.CalcNextBlockVersion()
	if err != nil {
		return nil, err
	}

	cbest := g.Chain.BestSnapshot()
	bh := cbest.Height

	last,_ := g.Chain.Miners.BlockByHash(&best.Hash)
	h1,_ := g.Chain.BlockHeightByHash(&last.MsgBlock().ReferredBlock)
	h0,_ := g.Chain.BlockHeightByHash(&last.MsgBlock().BestBlock)

	h2 := (bh + h1) / 2

	if bh < h0 || h2 < h1 {
		return nil, nil
	}

	h3,_ := g.Chain.BlockHashByHeight(h2)

	// Create a new block ready to be solved.
	msgBlock := wire.NewNodeBlock{
		Version:    nextBlockVersion,
		PrevBlock:  best.Hash,
		Timestamp:  ts,
		Bits:       reqDifficulty,
		ReferredBlock: *h3,
		BestBlock:	cbest.Hash,
		Newnode:	payToAddress.ScriptAddress(),
		BlackList:	[]byte{},
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
func (g *BlkTmplGenerator) UpdateBlockTime(msgBlock *wire.MsgBlock) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the Chain consensus
	// rules.
	newTime := medianAdjustedTime(g.Chain.BestSnapshot(), g.timeSource)
	msgBlock.Header.Timestamp = newTime

	// Recalculate the difficulty if running on a network that requires it.
// tmp	if g.chainParams.ReduceMinDifficulty {
//		difficulty, err := g.Chain.CalcNextRequiredDifficulty(newTime)
//		if err != nil {
//			return err
//		}
//		msgBlock.Header.Bits = difficulty
//	}

	return nil
}

func (g *BlkTmplGenerator) UpdateMinerBlockTime(msgBlock *wire.NewNodeBlock) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the Chain consensus
	// rules.
	newTime := medianAdjustedTime(g.Chain.BestSnapshot(), g.timeSource)
	msgBlock.Timestamp = newTime

	// Recalculate the difficulty if running on a network that requires it.
	// tmp	if g.chainParams.ReduceMinDifficulty {
	//		difficulty, err := g.Chain.CalcNextRequiredDifficulty(newTime)
	//		if err != nil {
	//			return err
	//		}
	//		msgBlock.Header.Bits = difficulty
	//	}

	return nil
}

// UpdateExtraNonce updates the extra nonce in the coinbase script of the passed
// block by regenerating the coinbase script with the passed value and block
// height.  It also recalculates and updates the new merkle root that results
// from changing the coinbase script.
/*
func (g *BlkTmplGenerator) UpdateExtraNonce(msgBlock *wire.MsgBlock, blockHeight int32, extraNonce uint64) error {
	coinbaseScript, err := standardCoinbaseScript(blockHeight, extraNonce)
	if err != nil {
		return err
	}
	if len(coinbaseScript) > blockchain.MaxCoinbaseScriptLen {
		return fmt.Errorf("coinbase transaction script length "+
			"of %d is out of range (min: %d, max: %d)",
			len(coinbaseScript), blockchain.MinCoinbaseScriptLen,
			blockchain.MaxCoinbaseScriptLen)
	}
	if msgBlock.Transactions[0].SignatureScripts == nil || len(msgBlock.Transactions[0].SignatureScripts) == 0 {
		msgBlock.Transactions[0].SignatureScripts = make([][]byte, 2)
		// this is the place we use to stoare merkle root of signatures
		msgBlock.Transactions[0].SignatureScripts[0] = make([]byte, 32)
	}
	msgBlock.Transactions[0].TxIn[0].SignatureIndex = 1
	msgBlock.Transactions[0].SignatureScripts[1] = coinbaseScript
//	msgBlock.Transactions[0].TxIn[0].SignatureScript = coinbaseScript

	// TODO(davec): A btcutil.Block should use saved in the state to avoid
	// recalculating all of the other transaction hashes.
	// block.Transactions[0].InvalidateCache()

	// Recalculate the merkle root with the updated extra nonce.
	block := btcutil.NewBlock(msgBlock)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions(), false)
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
	return nil
}
*/

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
		if bytes.Compare(address.ScriptAddress(), m.MsgBlock().Newnode) == 0 {
			// if it is in committee, not allowed to do POW mining
			return true
		}
	}

	return false
}

func (g *BlkTmplGenerator) Committee() map[[20]byte]struct{} {
	h := g.BestSnapshot().LastRotation		// .Chain.LastRotation(g.BestSnapshot().Hash)

	n := h - wire.CommitteeSize

//	log.Infof("Get committee at last rotation = %d", h)

	adrs := make(map[[20]byte]struct{})

	for n < h {
		n++
		m,_ := g.Chain.Miners.BlockByHeight(int32(n))

		var adr [20]byte
		copy(adr[:], m.MsgBlock().Newnode)
		adrs[adr] = struct{}{}
	}

	return adrs
}

func AddSignature(block * btcutil.Block, privkey *btcec.PrivateKey) {
	w := bytes.NewBuffer(make([]byte, 0, 36))
	binary.Write(w, common.LittleEndian, block.Height())
	binary.Write(w, common.LittleEndian, block.Hash())
	hash := chainhash.DoubleHashB(w.Bytes())

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