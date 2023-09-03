// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package netsync

import (
	"bytes"
	"container/list"
	"fmt"
	"github.com/omegasuite/omega/minerchain"
	"math/rand"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/database"
	"github.com/omegasuite/btcd/mempool"
	peerpkg "github.com/omegasuite/btcd/peer"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/consensus"
)

const (
	// minInFlightBlocks is the minimum number of blocks that should be
	// in the request queue for headers-first mode before requesting
	// more.
	minInFlightBlocks = 10

	// maxRejectedTxns is the maximum number of rejected transactions
	// hashes to store in memory.
	maxRejectedTxns = 1000

	// maxRequestedBlocks is the maximum number of requested block
	// hashes to store in memory.
	maxRequestedBlocks = wire.MaxInvPerMsg

	// maxRequestedTxns is the maximum number of requested transactions
	// hashes to store in memory.
	maxRequestedTxns = wire.MaxInvPerMsg
)

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash chainhash.Hash

// newPeerMsg signifies a newly connected peer to the block handler.
type newPeerMsg struct {
	peer *peerpkg.Peer
}

// blockMsg packages a block message and the peer it came from together
// so the block handler has access to that information.
type blockMsg struct {
	block *btcutil.Block
	peer  *peerpkg.Peer
	reply chan struct{}
}

type minerBlockMsg struct {
	block *wire.MinerBlock
	peer  *peerpkg.Peer
	reply chan struct{}
}

// sigMsg packages a block signature message and the peer it came from together
// so the block handler has access to that information.
type sigMsg struct {
	hash       chainhash.Hash
	signatures [][]byte
	peer       *peerpkg.Peer
	reply      chan struct{}
}

// invMsg packages a bitcoin inv message and the peer it came from together
// so the block handler has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *peerpkg.Peer
}

// headersMsg packages a bitcoin headers message and the peer it came from
// together so the block handler has access to that information.
type headersMsg struct {
	headers *wire.MsgHeaders
	peer    *peerpkg.Peer
}

// donePeerMsg signifies a newly disconnected peer to the block handler.
type donePeerMsg struct {
	peer *peerpkg.Peer
}

// txMsg packages a bitcoin tx message and the peer it came from together
// so the block handler has access to that information.
type txMsg struct {
	tx    *btcutil.Tx
	peer  *peerpkg.Peer
	reply chan struct{}
}

// getSyncPeerMsg is a message type to be sent across the message channel for
// retrieving the current sync peer.
type getSyncPeerMsg struct {
	reply chan int32
}

// resetConnMsg is a message type to be sent across the message channel for
// reset connections.
type resetConnMsg struct {
	all   bool
	reply chan struct{}
}

// processBlockResponse is a response sent to the reply channel of a
// processBlockMsg.
type processBlockResponse struct {
	isMain   bool
	isOrphan bool
	err      error
}

// processBlockMsg is a message type to be sent across the message channel
// for requested a block is processed.  Note this call differs from blockMsg
// above in that blockMsg is intended for blocks that came from peers and have
// extra handling whereas this message essentially is just a concurrent safe
// way to call ProcessBlock on the internal block chain instance.
type processBlockMsg struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
	reply chan processBlockResponse
}

type processConsusMsg struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

type processConsusPull struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
	reply chan processBlockResponse
}

type processMinerBlockMsg struct {
	block *wire.MinerBlock
	flags blockchain.BehaviorFlags
	reply chan processBlockResponse
}

// isCurrentMsg is a message type to be sent across the message channel for
// requesting whether or not the sync manager believes it is synced with the
// currently connected peers.
type isCurrentMsg struct {
	reply chan bool
}

// startSyncMsg is a message type to trig sync job.
type startSyncMsg struct {
	reply chan struct{}
}

// pauseMsg is a message type to be sent across the message channel for
// pausing the sync manager.  This effectively provides the caller with
// exclusive access over the manager until a receive is performed on the
// unpause channel.
type pauseMsg struct {
	unpause <-chan struct{}
}

// headerNode is used as a node in a list of headers that are linked together
// between checkpoints.
type headerNode struct {
	height int32
	hash   *chainhash.Hash
}

// peerSyncState stores additional information that the SyncManager tracks
// about a peer.
type peerSyncState struct {
	syncCandidate   bool
	requestQueue    []*wire.InvVect
	requestedTxns   map[chainhash.Hash]struct{}
	requestedBlocks map[chainhash.Hash]int
	syncTime        int64 // unix time this peer became a sync peer
}

type pendginGetBlocks struct {
	valid     bool
	heights   [2]int32
	hash      chainhash.Hash
	peer      *peerpkg.Peer
	locator   chainhash.BlockLocator
	mlocator  chainhash.BlockLocator
	stopHash  *chainhash.Hash
	mstopHash *chainhash.Hash
}

// SyncManager is used to communicate block related messages with peers. The
// SyncManager is started as by executing Start() in a goroutine. Once started,
// it selects peers to sync from and starts the initial block download. Once the
// chain is in sync, the SyncManager handles incoming block and header
// notifications and relays announcements of new blocks to peers.
type SyncManager struct {
	peerNotifier   PeerNotifier
	started        int32
	shutdown       int32
	chain          *blockchain.BlockChain
	txMemPool      *mempool.TxPool
	chainParams    *chaincfg.Params
	progressLogger *blockProgressLogger
	msgChan        chan interface{}
	wg             sync.WaitGroup
	quit           chan struct{}

	// These fields should only be accessed from the blockHandler thread
	rejectedTxns     map[chainhash.Hash]struct{}
	requestedTxns    map[chainhash.Hash]struct{}
	requestedBlocks  map[chainhash.Hash]int
	requestedOrphans map[chainhash.Hash]int

	syncPeer   *peerpkg.Peer
	peerStates map[*peerpkg.Peer]*peerSyncState

	// The following fields are used for headers-first mode.
	headersFirstMode bool
	headerList       *list.List
	startHeader      *list.Element
	nextCheckpoint   *chaincfg.Checkpoint

	// An optional fee estimator.
	feeEstimator *mempool.FeeEstimator

	// blocks already processed for consensus. we cache them to avoid double processing
	cachedBlocks map[chainhash.Hash]*btcutil.Block // block hash=>block
	castedMsg    map[chainhash.Hash]int64          // time a message is broadcated, to prevent re-casting

	syncjobs    []*pendginGetBlocks
	lastBlockOp string // for debug
	bshutdown   bool
	castmx      sync.Mutex

	tmpblksrc map[chainhash.Hash]*peerpkg.Peer
}

// resetHeaderState sets the headers-first mode state to values appropriate for
// syncing from a new peer.
func (sm *SyncManager) resetHeaderState(newestHash *chainhash.Hash, newestHeight int32) {
	sm.headersFirstMode = false
	sm.headerList.Init()
	sm.startHeader = nil

	// When there is a next checkpoint, add an entry for the latest known
	// block into the header pool.  This allows the next downloaded header
	// to prove it links to the chain properly.
	if sm.nextCheckpoint != nil {
		node := headerNode{height: newestHeight, hash: newestHash}
		sm.headerList.PushBack(&node)
	}
}

func (sm *SyncManager) ResetConnections(all bool) {
	ch := make(chan struct{}, 1)
	sm.msgChan <- resetConnMsg{all, ch}
}

func (sm *SyncManager) resetConnections(all bool) {
	if !all && len(sm.peerStates) < 100 {
		return
	}

	log.Infof("ResetConnections peers = %d", len(sm.peerStates))

	for p, _ := range sm.peerStates {
		p.Disconnect("Reset")
	}
	sm.clearSync()
}

// findNextHeaderCheckpoint returns the next checkpoint after the passed height.
// It returns nil when there is not one either because the height is already
// later than the final checkpoint or some other reason such as disabled
// checkpoints.
func (sm *SyncManager) findNextHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	checkpoints := sm.chain.Checkpoints()
	if len(checkpoints) == 0 {
		return nil
	}

	// There is no next checkpoint if the height is already after the final
	// checkpoint.
	finalCheckpoint := &checkpoints[len(checkpoints)-1]
	if height >= finalCheckpoint.Height {
		return nil
	}

	// Find the next checkpoint.
	nextCheckpoint := finalCheckpoint
	for i := len(checkpoints) - 2; i >= 0; i-- {
		if height >= checkpoints[i].Height {
			break
		}
		nextCheckpoint = &checkpoints[i]
	}
	return nextCheckpoint
}

func (sm *SyncManager) AddSyncJob(peer *peerpkg.Peer, locator, mlocator chainhash.BlockLocator, stopHash, mstopHash *chainhash.Hash, best [2]int32) {
	if sm.bshutdown {
		return
	}
	h := make([]byte, chainhash.HashSize*(len(locator)+len(mlocator)+2))
	p := 0
	for i := 0; i < len(locator); i, p = i+1, p+chainhash.HashSize {
		copy(h[p:], (*locator[i])[:])
	}
	for i := 0; i < len(mlocator); i, p = i+1, p+chainhash.HashSize {
		copy(h[p:], (*mlocator[i])[:])
	}
	if stopHash != nil {
		copy(h[p:], stopHash[:])
	}
	if mstopHash != nil {
		copy(h[p+chainhash.HashSize:], mstopHash[:])
	}
	hash := chainhash.DoubleHashH(h[:])
	for i := 0; i < len(sm.syncjobs); i++ {
		if hash == sm.syncjobs[i].hash {
			return
		}
	}

	for _, j := range sm.syncjobs {
		if best[0] >= j.heights[0] && best[1] >= j.heights[1] {
			j.valid = false
		}
	}

	sm.syncjobs = append(sm.syncjobs, &pendginGetBlocks{
		valid:     true,
		heights:   [2]int32{best[0], best[1]},
		hash:      hash,
		peer:      peer,
		locator:   locator,
		mlocator:  mlocator,
		stopHash:  stopHash,
		mstopHash: mstopHash,
	})
}

func (sm *SyncManager) updateSyncPeer() {
	if sm.bshutdown {
		return
	}

	p := sm.syncPeer
	if p != nil {
		state, ok := sm.peerStates[p]
		if ok && len(state.requestedBlocks) > 0 {
			tm := int(time.Now().Unix())
			for _, t := range state.requestedBlocks {
				if t > tm-30 {
					return
				}
			}
		}
	}

	n := len(sm.syncjobs)

	log.Debugf("updateSyncPeer: %d outstanding jobs", n)

	for n > 0 {
		j := sm.syncjobs[n-1]
		sm.syncjobs = sm.syncjobs[:n-1]
		n--
		if !j.valid {
			continue
		}
		if j.peer.Connected() {
			txmoot := false
			if j.stopHash != nil && !zeroHash.IsEqual(j.stopHash) {
				txmoot = sm.chain.NodeByHash(j.stopHash) != nil
				//				txmoot,_ = sm.chain.HaveBlock(j.stopHash)
			} else if len(j.locator) > 0 { // && *j.locator[0] != sm.chain.BestSnapshot().Hash {
				blk := sm.chain.NodeByHash(j.locator[0])
				if blk != nil && blk.Height < sm.chain.BestChain.Height() {
					txmoot = true
				}
				//				txmoot,_ = sm.chain.HaveBlock(j.locator[0])
			} else {
				txmoot = true
			}
			mnmoot := false
			if j.mstopHash != nil && !zeroHash.IsEqual(j.mstopHash) {
				mnmoot = sm.chain.Miners.NodeByHash(j.mstopHash) != nil
				//				mnmoot,_ = sm.chain.Miners.HaveBlock(j.mstopHash)
			} else if len(j.mlocator) > 0 { // && *j.mlocator[0] != sm.chain.Miners.BestSnapshot().Hash {
				blk, _ := sm.chain.Miners.BlockByHash(j.mlocator[0])
				if blk != nil && blk.Height() < sm.chain.Miners.BestSnapshot().Height {
					mnmoot = true
				}
				//				mnmoot,_ = sm.chain.Miners.HaveBlock(j.mlocator[0])
				//				mnmoot = true
			} else {
				mnmoot = true
			}
			if txmoot && mnmoot {
				continue
			}
			if txmoot {
				j.stopHash = &zeroHash
				j.locator = make([]*chainhash.Hash, 0)
			}
			if mnmoot {
				j.mstopHash = &zeroHash
				j.mlocator = make([]*chainhash.Hash, 0)
			}

			sm.syncPeer = j.peer
			j.peer.PushGetBlocksMsg(j.locator, j.mlocator, j.stopHash, j.mstopHash)
			return
		}
	}

	sm.syncPeer = nil
	sm.startSync(p)
}

func (sm *SyncManager) clearSync() {
	sm.syncPeer = nil
	sm.syncjobs = sm.syncjobs[:0]
}

// startSync will choose the best peer among the available candidate peers to
// download/sync the blockchain from.  When syncing is already running, it
// simply returns.  It also examines the candidates for any which are no longer
// candidates and removes them as needed.
func (sm *SyncManager) startSync(avoid *peerpkg.Peer) bool {
	if sm.bshutdown {
		return true
	}
	// Return now if we're already syncing.
	if sm.syncPeer != nil {
		return true
	}

	best := sm.chain.BestSnapshot()
	var bestPeer *peerpkg.Peer

	// we always choose the one that was sync peer in the most distant past. so everyone
	// has a chance to become sync peer
	tm := int64(0x7FFFFFFFFFFFFFFF)
	ss := ""

	for peer, state := range sm.peerStates {
		ss = ss + fmt.Sprintf("peer ID = %d conn = %v candidate = %v addr = %s\n",
			peer.ID(), peer.Connected(), state.syncCandidate, peer.Addr())
		if !state.syncCandidate || !peer.Connected() || state.syncTime > tm {
			continue
		}
		rd := rand.Intn(100) < 50
		if bestPeer != nil && peer != avoid {
			if sm.chain.IsCurrent() {
				// peer priority: select by committe first, length of chain
				cd := int32(best.LastRotation) - bestPeer.Committee
				cp := int32(best.LastRotation) - peer.Committee

				if cd >= 0 && cd < wire.CommitteeSize {
					if cp < 0 || cp >= wire.CommitteeSize {
						continue
					}
					if rd {
						continue
					}
				} else if !(cp >= 0 && cp < wire.CommitteeSize) {
					if rd {
						continue
					}
				}
			} else if rd {
				continue
			}
		}
		tm = state.syncTime
		bestPeer = peer
	}

	if bestPeer == nil {
		//		log.Infof("No sync peer available out of %d peers", len(sm.peerStates))
		return false
	}

	if bestPeer == avoid {
		sm.syncPeer = bestPeer
	}

	sm.peerStates[bestPeer].syncTime = time.Now().Unix()

	// Start syncing from the best peer if one was selected.
	if bestPeer != nil {
		log.Warnf("%d: Start sync with bestPeer %s", bestPeer.ID(), bestPeer.String())

		// sync miner chain and then tx chain
		// Clear the requestedBlocks if the sync peer changes, otherwise
		// we may ignore blocks we need that the last sync peer failed
		// to send.
		sm.requestedBlocks = make(map[chainhash.Hash]int)
		sm.requestedOrphans = make(map[chainhash.Hash]int)

		sm.peerStates[bestPeer].requestedBlocks = make(map[chainhash.Hash]int)

		sm.syncPeer = bestPeer

		mlocator, err := sm.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
		if err != nil {
			log.Errorf("Failed to get block locator for the "+
				"latest block: %v", err)
			return true
		}

		// Now the tx chain
		locator, err := sm.chain.LatestBlockLocator()
		if err != nil {
			log.Errorf("Failed to get block locator for the "+
				"latest block: %v", err)
			return true
		}

		mbest := sm.chain.Miners.BestSnapshot()

		deferexec := time.Second * 0
		if bestPeer.LastBlock() == best.Height && bestPeer.LastMinerBlock() == mbest.Height {
			if len(sm.syncjobs) > 0 {
				return true
			}
			// the best peer is already in sync, so wait for sometime before trying a sync job
			deferexec = time.Second * 10
		}

		log.Debugf("Syncing tx chain to block height %d  and miner height %d from peer %v",
			bestPeer.LastBlock(), bestPeer.LastMinerBlock(), bestPeer.Addr())

		// When the current height is less than a known checkpoint we
		// can use block headers to learn about which blocks comprise
		// the chain up to the checkpoint and perform less validation
		// for them.  This is possible since each header contains the
		// hash of the previous header and a merkle root.  Therefore if
		// we validate all of the received headers link together
		// properly and the checkpoint hashes match, we can be sure the
		// hashes for the blocks in between are accurate.  Further, once
		// the full blocks are downloaded, the merkle root is computed
		// and compared against the value in the header which proves the
		// full block hasn't been tampered with.
		//
		// Once we have passed the final checkpoint, or checkpoints are
		// disabled, use standard inv messages learn about the blocks
		// and fully validate them.  Finally, regression test mode does
		// not support the headers-first approach so do normal block
		// downloads when in regression test mode.GetBlocks
		if sm.nextCheckpoint != nil &&
			best.Height < sm.nextCheckpoint.Height &&
			sm.chainParams != &chaincfg.RegressionNetParams {

			bestPeer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
			sm.headersFirstMode = true
			log.Tracef("Downloading headers for blocks %d to "+
				"%d from peer %s", best.Height+1,
				sm.nextCheckpoint.Height, bestPeer.Addr())
		}
		if deferexec == 0 {
			//			log.Infof("startSync %d: PushGetBlocksMsg from %s", bestPeer.ID(), bestPeer.Addr())
			bestPeer.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
		} else {
			time.AfterFunc(deferexec, func() {
				if !bestPeer.Connected() {
					sm.msgChan <- startSyncMsg{reply: nil}
					return
				}
				//				log.Debugf("startSync %d: PushGetBlocksMsg from %s", bestPeer.ID(), bestPeer.Addr())
				bestPeer.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
			})
		}
	} else {
		log.Warnf("No sync peer candidates available or this node has the longest chain")
	}
	return true
}

// isSyncCandidate returns whether or not the peer is a candidate to consider
// syncing from.
func (sm *SyncManager) isSyncCandidate(peer *peerpkg.Peer) bool {
	// Typically a peer is not a candidate for sync if it's not a full node,
	// however regression test is special in that the regression tool is
	// not a full node and still needs to be considered a sync candidate.
	if sm.chainParams == &chaincfg.RegressionNetParams {
		// The peer is not a candidate if it's not coming from localhost
		// or the hostname can't be determined for some reason.
		host, _, err := net.SplitHostPort(peer.Addr())
		if err != nil {
			return false
		}

		if host != "127.0.0.1" && host != "localhost" {
			return false
		}
	} else {
		// The peer is not a candidate for sync if it's not a full
		// node. Additionally, if the segwit soft-fork package has
		// activated, then the peer must also be upgraded.
		nodeServices := peer.Services()
		if nodeServices&common.SFNodeNetwork != common.SFNodeNetwork {
			return false
		}
	}

	// Candidate if all checks passed.
	return true
}

// handleNewPeerMsg deals with new peers that have signalled they may
// be considered as a sync peer (they have already successfully negotiated).  It
// also starts syncing if needed.  It is invoked from the syncHandler goroutine.
func (sm *SyncManager) handleNewPeerMsg(peer *peerpkg.Peer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	log.Debugf("New valid peer %s (%s)", peer, peer.UserAgent())

	// Initialize the peer state
	isSyncCandidate := sm.isSyncCandidate(peer)
	sm.peerStates[peer] = &peerSyncState{
		syncCandidate:   isSyncCandidate,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]int),
		requestQueue:    make([]*wire.InvVect, 0, 1000),
	}

	// Start syncing by choosing the best candidate if needed.
	if isSyncCandidate && sm.syncPeer == nil {
		sm.startSync(nil)
	}
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It
// removes the peer as a candidate for syncing and in the case where it was
// the current sync peer, attempts to select a new best peer to sync from.  It
// is invoked from the syncHandler goroutine.
func (sm *SyncManager) handleDonePeerMsg(peer *peerpkg.Peer) {
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received done peer message for unknown peer %s", peer)
		return
	}

	// Remove the peer from the list of candidate peers.
	delete(sm.peerStates, peer)

	log.Infof("Lost peer %s", peer)

	// Remove requested transactions from the global map so that they will
	// be fetched from elsewhere next time we get an inv.
	for txHash := range state.requestedTxns {
		delete(sm.requestedTxns, txHash)
	}

	// Remove requested blocks from the global map so that they will be
	// fetched from elsewhere next time we get an inv.
	// TODO: we could possibly here check which peers have these blocks
	// and request them now to speed things up a little.
	for blockHash := range state.requestedBlocks {
		delete(sm.requestedBlocks, blockHash)
	}

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer.  Also, reset the headers-first state if in headers-first
	// mode so
	if sm.syncPeer == peer {
		sm.syncjobs = make([]*pendginGetBlocks, 0)
		//		p := sm.syncPeer
		sm.syncPeer = nil
		if sm.headersFirstMode {
			best := sm.chain.BestSnapshot()
			sm.resetHeaderState(&best.Hash, best.Height)
		}
		sm.updateSyncPeer()
		//		sm.startSync(p)
	}
}

// handleTxMsg handles transaction messages from all peers.
func (sm *SyncManager) handleTxMsg(tmsg *txMsg) {
	peer := tmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received tx message from unknown peer %s", peer)
		return
	}

	// NOTE:  BitcoinJ, and possibly other wallets, don't follow the spec of
	// sending an inventory message and allowing the remote peer to decide
	// whether or not they want to request the transaction via a getdata
	// message.  Unfortunately, the reference implementation permits
	// unrequested data, so it has allowed wallets that don't follow the
	// spec to proliferate.  While this is not ideal, there is no check here
	// to disconnect peers for sending unsolicited transactions to provide
	// interoperability.
	txHash := tmsg.tx.Hash()

	// Ignore transactions that we have already rejected.  Do not
	// send a reject message here because if the transaction was already
	// rejected, the transaction was unsolicited.
	if _, exists = sm.rejectedTxns[*txHash]; exists {
		log.Debugf("Ignoring unsolicited previously rejected "+
			"transaction %v from %s", txHash, peer)
		return
	}

	// Process the transaction to include validation, insertion in the
	// memory pool, orphan handling, etc.
	acceptedTxs, err := sm.txMemPool.ProcessTransaction(tmsg.tx,
		true, true, mempool.Tag(peer.ID()), false)

	// Remove transaction from request maps. Either the mempool/chain
	// already knows about it and as such we shouldn't have any more
	// instances of trying to fetch it, or we failed to insert and thus
	// we'll retry next time we get an inv.
	delete(state.requestedTxns, *txHash)
	delete(sm.requestedTxns, *txHash)

	if err != nil {
		// Do not request this transaction again until a new block
		// has been processed.
		sm.rejectedTxns[*txHash] = struct{}{}
		sm.limitMap(sm.rejectedTxns, maxRejectedTxns)

		// When the error is a rule error, it means the transaction was
		// simply rejected as opposed to something actually going wrong,
		// so log it as such.  Otherwise, something really did go wrong,
		// so log it as an actual error.
		if _, ok := err.(mempool.RuleError); ok {
			log.Debugf("Rejected transaction %v from %s: %v",
				txHash, peer, err)
		} else {
			log.Errorf("Failed to process transaction %v: %v",
				txHash, err)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		peer.PushRejectMsg(wire.CmdTx, code, reason, txHash, false)
		return
	}

	sm.peerNotifier.AnnounceNewTransactions(acceptedTxs)
}

// current returns true if we believe we are synced with our peers, false if we
// still have blocks to check
func (sm *SyncManager) current(t int) bool {
	if t == 0 && !sm.chain.IsCurrent() {
		return false
	}
	if t == 1 && !sm.chain.Miners.IsCurrent() {
		return false
	}

	// if blockChain thinks we are current and we have no syncPeer it
	// is probably right.
	p := sm.syncPeer
	if p == nil {
		return true
	}

	// No matter what chain thinks, if we are below the block we are syncing
	// to we are not current.
	if t == 0 && sm.chain.BestSnapshot().Height < p.LastBlock() {
		return false
	}
	if t == 1 && sm.chain.Miners.BestSnapshot().Height < p.LastMinerBlock() {
		return false
	}
	return true
}

// handleBlockMsg handles block messages from all peers.
func (sm *SyncManager) handleBlockMsg(bmsg *blockMsg) {
	peer := bmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received block message from unknown peer %s", peer)
		return
	}

	//	defer func() {
	//		if len(state.requestedBlocks) == 0 {	// && sm.syncPeer == peer {
	//			sm.updateSyncPeer()
	//		}
	//	}()

	behaviorFlags := blockchain.BFNone

	// if it is a block being processed by the committee, veryfy it is from the peer
	// producing, i.e. the address in coinbase signature is the peer's
	if wire.CommitteeSize > 1 && bmsg.block.MsgBlock().Header.Nonce < 0 &&
		len(bmsg.block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSigs {
		//		if len(bmsg.block.MsgBlock().Transactions[0].SignatureScripts) < 2 {
		//			log.Errorf("handleBlockMsg: blocked because of insufficient signatures. Require 2 items in coinbase signatures.")
		//			return
		//		}
		//		if bytes.Compare(peer.Miner[:], bmsg.block.MsgBlock().Transactions[0].SignatureScripts[1]) != 0 {
		//			log.Infof("handleBlockMsg: blocked because of unexpected signature")
		// not the same
		//			return
		//		}
		//		if peer.Committee < int32(sm.chain.BestSnapshot().LastRotation) - wire.CommitteeSize {
		//			log.Infof("handleBlockMsg: blocked for out of committee")
		//			return
		//		}
		behaviorFlags |= blockchain.BFNoConnect
	}

	// If we didn't ask for this block then the peer is misbehaving.
	blockHash := bmsg.block.Hash()
	/*
		if _, exists = state.requestedBlocks[*blockHash]; !exists && behaviorFlags & blockchain.BFNoConnect != blockchain.BFNoConnect {
			// The regression test intentionally sends some blocks twice
			// to test duplicate block insertion fails.  Don't disconnect
			// the peer or ignore the block when we're in regression test
			// mode in this case so the chain code is actually fed the
			// duplicate blocks.
			if sm.chainParams != &chaincfg.RegressionNetParams && peer.Committee <= 0 {
				log.Warnf("Got unrequested block %s from %s", blockHash.String(), peer.Addr())
				return
			}
		}
	*/

	// When in headers-first mode, if the block matches the hash of the
	// first header in the list of headers that are being fetched, it's
	// eligible for less validation since the headers have already been
	// verified to link together and are valid up to the next checkpoint.
	// Also, remove the list entry for all blocks except the checkpoint
	// since it is needed to verify the next round of headers links
	// properly.
	isCheckpointBlock := false
	if sm.headersFirstMode {
		firstNodeEl := sm.headerList.Front()
		if firstNodeEl != nil {
			firstNode := firstNodeEl.Value.(*headerNode)
			if blockHash.IsEqual(firstNode.hash) {
				behaviorFlags |= blockchain.BFFastAdd
				if firstNode.hash.IsEqual(sm.nextCheckpoint.Hash) {
					isCheckpointBlock = true
				} else {
					sm.headerList.Remove(firstNodeEl)
				}
			}
		}
	}

	// Remove block from request maps. Either chain will know about it and
	// so we shouldn't have any more instances of trying to fetch it, or we
	// will fail the insert and thus we'll retry next time we get an inv.
	delete(state.requestedBlocks, *blockHash)
	delete(sm.requestedBlocks, *blockHash)

	//	log.Infof("handleBlockMsg: %v", bmsg.block.MsgBlock().Header.PrevBlock)

	// Process the block to include validation, best chain selection, orphan
	// handling, etc.
	//	log.Infof("netsyc ProcessBlock %s at %d", bmsg.block.Hash().String(), bmsg.block.Height())

	var isMainchain, isOrphan bool
	var b1, b2 *blockchain.BestState
	var err error
	var missing int32
	var orp *chainhash.Hash

	if _, ok := sm.cachedBlocks[*blockHash]; behaviorFlags&blockchain.BFNoConnect != blockchain.BFNoConnect || !ok {
		isMainchain, isOrphan, err, missing, orp = sm.chain.ProcessBlock(bmsg.block, behaviorFlags)

		b1 = sm.chain.BestSnapshot()
		b2 = sm.chain.Miners.BestSnapshot()

		if missing > 0 {
			var h chainhash.BlockLocator
			if missing <= sm.chain.Miners.BestSnapshot().Height {
				mb, _ := sm.chain.Miners.BlockByHeight(missing - 1)
				h = chainhash.BlockLocator([]*chainhash.Hash{&mb.MsgBlock().PrevBlock})
			} else {
				h = sm.chain.Miners.(*minerchain.MinerChain).BlockLocatorFromHash(&zeroHash)
			}

			sm.AddSyncJob(peer,
				chainhash.BlockLocator(make([]*chainhash.Hash, 0)),
				h,
				&zeroHash, &zeroHash, [2]int32{b1.Height, b2.Height})
		}
		if orp != nil {
			if !sm.chain.Orphans.IsKnownOrphan(orp) {
				log.Infof("Requesting block %s", orp.String())
				//		peer.PushGetBlocksMsg(chainhash.BlockLocator(make([]*chainhash.Hash, 0)), chainhash.BlockLocator(make([]*chainhash.Hash, 0)), orp, &zeroHash)
				peer.QueueMessage(&wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, *orp}}}, nil)
			}
		}

		if err != nil {
			// When the error is a rule error, it means the block was simply
			// rejected as opposed to something actually going wrong, so log
			// it as such.  Otherwise, something really did go wrong, so log
			// it as an actual error.
			checkdb := true
			if _, ok := err.(blockchain.RuleError); ok {
				log.Debugf("Rejected tx block %s at %d from %s: %v", blockHash.String(),
					bmsg.block.Height(), peer, err)
				if err.(blockchain.RuleError).ErrorCode == blockchain.ErrDuplicateBlock {
					// still need to update height
					peer.UpdateLastBlockHeight(bmsg.block.Height())
					if behaviorFlags&blockchain.BFNoConnect == blockchain.BFNoConnect {
						checkdb = false
					}
				}
			} else {
				log.Errorf("Failed to process block %v: %v",
					blockHash, err)
			}

			if checkdb {
				if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
					database.ErrCorruption {
					panic(dbErr)
				}

				// Convert the error into an appropriate reject message and
				// send it.
				code, reason := mempool.ErrToRejectErr(err)
				peer.PushRejectMsg(wire.CmdBlock, code, reason, blockHash, false)
				return
			}
		}
	}

	if b1 == nil {
		b1 = sm.chain.BestSnapshot()
	}

	ht := bmsg.block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index
	if behaviorFlags&blockchain.BFNoConnect == blockchain.BFNoConnect {
		// passing it to consensus maker
		consensus.ProcessBlock(bmsg.block, behaviorFlags)
		if bmsg.block.Height() > b1.Height {
			sm.cachedBlocks[*blockHash] = bmsg.block
		}
		return
	}

	for hash, h := range sm.cachedBlocks {
		if h.Height() <= b1.Height { // block height has passed
			delete(sm.cachedBlocks, hash)
		}
	}

	// Meta-data about the new block this peer is reporting. We use this
	// below to update this peer's lastest block height and the heights of
	// other peers based on their last announced block hash. This allows us
	// to dynamically update the block heights of peers, avoiding stale
	// heights when looking for a new sync peer. Upon acceptance of a block
	// or recognition of an orphan, we also use this information to update
	// the block heights over other peers who's invs may have been ignored
	// if we are actively syncing while the chain is not yet current or
	// who may have lost the lock announcment race.
	var heightUpdate int32
	var blkHashUpdate *chainhash.Hash

	// Request the parents for the orphan block from the peer that sent it.
	if isOrphan {
		if isMainchain {
			// if isMainchain is true, it is because we don't have the best TX block, so
			// there is no need to get blocks before the orphan
			return
		} else {
			// We've just received an orphan block from a peer. In order
			// to update the height of the peer, we try to extract the
			// block height from the scriptSig of the coinbase transaction.
			heightUpdate = int32(ht)
			blkHashUpdate = blockHash

			// add a sync jon
			tlocator, _ := sm.chain.LatestBlockLocator()
			orphanRoot := sm.chain.Orphans.GetOrphanRoot(blockHash)
			if *orphanRoot == *blockHash {
				locator, _ := sm.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()

				sm.AddSyncJob(peer, tlocator, locator, orphanRoot, &zeroHash,
					[2]int32{b1.Height, b2.Height})
			}
		}

		/*
			orphanRoot := sm.chain.GetOrphanRoot(blockHash)
			locator, err := sm.chain.LatestBlockLocator()
			if err != nil {
				log.Warnf("Failed to get block locator for the "+
					"latest block: %v", err)
			} else {
				peer.PushGetBlocksMsg(locator, make(chainhash.BlockLocator, 0), orphanRoot, nil)
			}
		*/
	} else {
		// When the block is not an orphan, log information about it and
		// update the chain state.
		sm.progressLogger.LogBlockHeight(bmsg.block)

		// Update this peer's latest block height, for future
		// potential sync node candidacy.
		best := sm.chain.BestSnapshot()
		heightUpdate = best.Height
		blkHashUpdate = &best.Hash

		// Clear the rejected transactions.
		sm.rejectedTxns = make(map[chainhash.Hash]struct{})
	}

	// Update the block height for this peer. But only send a message to
	// the server for updating peer heights if this is an orphan or our
	// chain is "current". This avoids sending a spammy amount of messages
	// if we're syncing the chain from scratch.
	if blkHashUpdate != nil && heightUpdate != 0 {
		peer.UpdateLastBlockHeight(heightUpdate)
		if isOrphan || sm.current(0) {
			go sm.peerNotifier.UpdatePeerHeights(blkHashUpdate, heightUpdate,
				peer)
		}
	}

	// Nothing more to do if we aren't in headers-first mode.
	if !sm.headersFirstMode {
		return
	}

	// This is headers-first mode, so if the block is not a checkpoint
	// request more blocks using the header list when the request queue is
	// getting short.
	if !isCheckpointBlock {
		if sm.startHeader != nil &&
			len(state.requestedBlocks) < minInFlightBlocks {
			sm.fetchHeaderBlocks()
		}
		return
	}

	// This is headers-first mode and the block is a checkpoint.  When
	// there is a next checkpoint, get the next round of headers by asking
	// for headers starting from the block after this one up to the next
	// checkpoint.
	prevHeight := sm.nextCheckpoint.Height
	prevHash := sm.nextCheckpoint.Hash
	sm.nextCheckpoint = sm.findNextHeaderCheckpoint(prevHeight)
	if sm.nextCheckpoint != nil {
		locator := chainhash.BlockLocator([]*chainhash.Hash{prevHash})
		err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %v", peer.Addr(), err)
			return
		}
		log.Tracef("Downloading headers for blocks %d to %d from "+
			"peer %s", prevHeight+1, sm.nextCheckpoint.Height,
			sm.syncPeer.Addr())
		return
	}

	// This is headers-first mode, the block is a checkpoint, and there are
	// no more checkpoints, so switch to normal mode by requesting blocks
	// from the block after this one up to the end of the chain (zero hash).
	sm.headersFirstMode = false
	sm.headerList.Init()
	log.Infof("Reached the final checkpoint -- switching to normal mode")

	var mblockHash *chainhash.Hash

	mblk, _ := sm.chain.Miners.BlockByHeight(int32(sm.chain.BestSnapshot().LastRotation))
	mblockHash = mblk.Hash()

	locator := chainhash.BlockLocator([]*chainhash.Hash{blockHash})
	mlocator := chainhash.BlockLocator([]*chainhash.Hash{mblockHash})
	//	log.Debugf("handleBlockMsg: PushGetBlocksMsg from %s because  -- switching to normal mode", peer.Addr())
	err = peer.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
	if err != nil {
		log.Warnf("Failed to send getblocks message to peer %s: %v",
			peer.Addr(), err)
		return
	}
}

func (sm *SyncManager) handleMinerBlockMsg(bmsg *minerBlockMsg) {
	peer := bmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received block message from unknown peer %s", peer)
		return
	}

	defer func() {
		if len(state.requestedBlocks) == 0 { // && sm.syncPeer == peer {
			sm.updateSyncPeer()
		}
	}()

	//	log.Infof("handleMinerBlockMsg: %v", bmsg.block.MsgBlock().PrevBlock)

	// If we didn't ask for this block then the peer is misbehaving.
	blockHash := bmsg.block.Hash()
	/*
		if _, exists = state.requestedBlocks[*blockHash]; !exists {
			// The regression test intentionally sends some blocks twice
			// to test duplicate block insertion fails.  Don't disconnect
			// the peer or ignore the block when we're in regression test
			// mode in this case so the chain code is actually fed the
			// duplicate blocks.
			if sm.chainParams != &chaincfg.RegressionNetParams && peer.Committee <= 0 {
				log.Warnf("Got unrequested block %v from %s", blockHash, peer.Addr())
				return
			}
		}
	*/

	behaviorFlags := blockchain.BFNone

	// Remove block from request maps. Either chain will know about it and
	// so we shouldn't have any more instances of trying to fetch it, or we
	// will fail the insert and thus we'll retry next time we get an inv.
	delete(state.requestedBlocks, *blockHash)
	delete(sm.requestedBlocks, *blockHash)

	// Process the block to include validation, best chain selection, orphan
	// handling, etc.

	log.Tracef("sm.chain.Miners.ProcessBlock")
	if sm.chainParams.Net == common.TestNet || sm.chainParams.Net == common.SimNet || sm.chainParams.Net == common.RegNet {
		behaviorFlags |= blockchain.BFEasyBlocks
	}
	isMainchain, isOrphan, err, h := sm.chain.Miners.ProcessBlock(bmsg.block, behaviorFlags)

	b1 := sm.chain.BestSnapshot()
	b2 := sm.chain.Miners.BestSnapshot()

	if h != nil {
		ch := sm.chain.Miners.(*minerchain.MinerChain)
		iv := h.(*wire.MsgGetData).InvList[0]
		if iv.Type == common.InvTypeMinerBlock && !ch.Orphans.IsKnownOrphan(&(iv.Hash)) {
			peer.QueueMessageWithEncoding(h, nil, wire.SignatureEncoding)
		} else if iv.Type == common.InvTypeWitnessBlock && !sm.chain.Orphans.IsKnownOrphan(&(iv.Hash)) {
			peer.QueueMessageWithEncoding(h, nil, wire.SignatureEncoding)
		}

		/*
		   		sm.AddSyncJob(peer,
		   //			sm.chain.BlockLocatorFromHash(&zeroHash),
		   			chainhash.BlockLocator(make([]*chainhash.Hash, 0)),
		   			chainhash.BlockLocator(make([]*chainhash.Hash, 0)),
		   			h, &zeroHash,
		   			[2]int32{b1.Height, b2.Height})
		*/
	}

	if err != nil {
		// When the error is a rule error, it means the block was simply
		// rejected as opposed to something actually going wrong, so log
		// it as such.  Otherwise, something really did go wrong, so log
		// it as an actual error.
		if _, ok := err.(blockchain.RuleError); ok {
			log.Tracef("Rejected miner block %s from %s: %s", blockHash.String(),
				peer.String(), err.Error())
			if err.(blockchain.RuleError).ErrorCode == blockchain.ErrDuplicateBlock {
				// still need to update height
				peer.UpdateLastMinerBlockHeight(bmsg.block.Height())
				return
			}
		} else {
			log.Errorf("Failed to process miner block %s: %s",
				blockHash.String(), err.Error())
		}
		if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
			database.ErrCorruption {
			panic(dbErr)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		peer.PushRejectMsg(wire.CmdBlock, code, reason, blockHash, false)
		return
	}

	// Meta-data about the new block this peer is reporting. We use this
	// below to update this peer's lastest block height and the heights of
	// other peers based on their last announced block hash. This allows us
	// to dynamically update the block heights of peers, avoiding stale
	// heights when looking for a new sync peer. Upon acceptance of a block
	// or recognition of an orphan, we also use this information to update
	// the block heights over other peers who's invs may have been ignored
	// if we are actively syncing while the chain is not yet current or
	// who may have lost the lock announcment race.
	var heightUpdate int32
	var blkHashUpdate *chainhash.Hash

	// Request the parents for the orphan block from the peer that sent it.
	if isOrphan {
		if isMainchain {
			// if isMainchain is true, it is because we don't have the best TX block, so
			// there is no need to get blocks before the orphan
			return
		} else {
			orphanRoot := sm.chain.Miners.(*minerchain.MinerChain).Orphans.GetOrphanRoot(blockHash)
			if *orphanRoot == *blockHash {
				locator, err := sm.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
				if err != nil {
					log.Warnf("Failed to get block locator for the "+
						"latest block: %v", err)
				} else {
					tlocator, _ := sm.chain.LatestBlockLocator()

					log.Tracef("handleMinerBlockMsg: PushGetBlocksMsg from %s because received an miner orphan %s", peer.Addr(), orphanRoot.String())
					sm.AddSyncJob(peer, tlocator, locator, &zeroHash, orphanRoot,
						[2]int32{b1.Height, b2.Height})
					//			peer.PushGetBlocksMsg(tlocator, locator, &zerohash, orphanRoot)
				}
			}
		}
	} else {
		// When the block is not an orphan, log information about it and
		// update the chain state.
		sm.progressLogger.LogMinerBlockHeight(bmsg.block)

		// Update this peer's latest block height, for future
		// potential sync node candidacy.
		best := sm.chain.Miners.(*minerchain.MinerChain).BestSnapshot()
		heightUpdate = best.Height
		blkHashUpdate = &best.Hash
	}

	// Update the block height for this peer. But only send a message to
	// the server for updating peer heights if this is an orphan or our
	// chain is "current". This avoids sending a spammy amount of messages
	// if we're syncing the chain from scratch.
	if blkHashUpdate != nil && heightUpdate != 0 {
		peer.UpdateLastMinerBlockHeight(heightUpdate)
		if isOrphan || sm.current(1) {
			go sm.peerNotifier.UpdatePeerMinerHeights(blkHashUpdate, heightUpdate,
				peer)
		}
	}
}

// fetchHeaderBlocks creates and sends a request to the syncPeer for the next
// list of blocks to be downloaded based on the current list of headers.
func (sm *SyncManager) fetchHeaderBlocks() {
	// Nothing to do if there is no start header.
	if sm.startHeader == nil {
		log.Warnf("fetchHeaderBlocks called with no start header")
		return
	}

	// Build up a getdata request for the list of blocks the headers
	// describe.  The size hint will be limited to wire.MaxInvPerMsg by
	// the function, so no need to double check it here.
	gdmsg := wire.NewMsgGetDataSizeHint(uint(sm.headerList.Len()))
	numRequested := 0
	for e := sm.startHeader; e != nil; e = e.Next() {
		node, ok := e.Value.(*headerNode)
		if !ok {
			log.Warn("Header list node type is not a headerNode")
			continue
		}

		iv := wire.NewInvVect(common.InvTypeBlock, node.hash)
		haveInv, err := sm.haveInventory(iv)
		if err != nil {
			log.Warnf("Unexpected failure when checking for "+
				"existing inventory during header block "+
				"fetch: %v", err)
		}
		if !haveInv {
			syncPeerState := sm.peerStates[sm.syncPeer]

			sm.requestedBlocks[*node.hash] = 1
			syncPeerState.requestedBlocks[*node.hash] = 1

			// If we're fetching from a witness enabled peer
			// post-fork, then ensure that we receive all the
			// witness data in the blocks.
			if sm.syncPeer.IsWitnessEnabled() {
				iv.Type = common.InvTypeWitnessBlock
			}

			gdmsg.AddInvVect(iv)
			numRequested++
		}
		sm.startHeader = e.Next()
		if numRequested >= wire.MaxInvPerMsg {
			break
		}
	}
	if len(gdmsg.InvList) > 0 {
		sm.syncPeer.QueueMessage(gdmsg, nil)
	}
}

// handleHeadersMsg handles block header messages from all peers.  Headers are
// requested when performing a headers-first sync.
func (sm *SyncManager) handleHeadersMsg(hmsg *headersMsg) {
	peer := hmsg.peer
	_, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received headers message from unknown peer %s", peer)
		return
	}

	// The remote peer is misbehaving if we didn't request headers.
	msg := hmsg.headers
	numHeaders := len(msg.Headers)
	if !sm.headersFirstMode {
		log.Warnf("Got %d unrequested headers from %s -- "+
			"disconnecting", numHeaders, peer.Addr())
		peer.Disconnect("handleHeadersMsg @ headersFirstMode")
		return
	}

	// Nothing to do for an empty headers message.
	if numHeaders == 0 {
		return
	}

	// Process all of the received headers ensuring each one connects to the
	// previous and that checkpoints match.
	receivedCheckpoint := false
	var finalHash *chainhash.Hash
	for _, blockHeader := range msg.Headers {
		blockHash := blockHeader.BlockHash()
		finalHash = &blockHash

		// Ensure there is a previous header to compare against.
		prevNodeEl := sm.headerList.Back()
		if prevNodeEl == nil {
			log.Warnf("Header list does not contain a previous" +
				"element as expected -- disconnecting peer")
			peer.Disconnect("handleHeadersMsg @ prevNodeEl")
			return
		}

		// Ensure the header properly connects to the previous one and
		// add it to the list of headers.
		node := headerNode{hash: &blockHash}
		prevNode := prevNodeEl.Value.(*headerNode)
		if prevNode.hash.IsEqual(&blockHeader.PrevBlock) {
			node.height = prevNode.height + 1
			e := sm.headerList.PushBack(&node)
			if sm.startHeader == nil {
				sm.startHeader = e
			}
		} else {
			log.Warnf("Received block header that does not "+
				"properly connect to the chain from peer %s "+
				"-- disconnecting", peer.Addr())
			peer.Disconnect("handleHeadersMsg @ PrevBlock")
			return
		}

		// Verify the header at the next checkpoint height matches.
		if node.height == sm.nextCheckpoint.Height {
			if node.hash.IsEqual(sm.nextCheckpoint.Hash) {
				receivedCheckpoint = true
				log.Infof("Verified downloaded block "+
					"header against checkpoint at height "+
					"%d/hash %s", node.height, node.hash)
			} else {
				log.Warnf("Block header at height %d/hash "+
					"%s from peer %s does NOT match "+
					"expected checkpoint hash of %s -- "+
					"disconnecting", node.height,
					node.hash, peer.Addr(),
					sm.nextCheckpoint.Hash)
				peer.Disconnect("handleHeadersMsg @ nextCheckpoint")
				return
			}
			break
		}
	}

	// When this header is a checkpoint, switch to fetching the blocks for
	// all of the headers since the last checkpoint.
	if receivedCheckpoint {
		// Since the first entry of the list is always the final block
		// that is already in the database and is only used to ensure
		// the next header links properly, it must be removed before
		// fetching the blocks.
		sm.headerList.Remove(sm.headerList.Front())
		log.Tracef("Received %v block headers: Fetching blocks",
			sm.headerList.Len())
		sm.progressLogger.SetLastLogTime(time.Now())
		sm.fetchHeaderBlocks()
		return
	}

	// This header is not a checkpoint, so request the next batch of
	// headers starting from the latest known header and ending with the
	// next checkpoint.
	locator := chainhash.BlockLocator([]*chainhash.Hash{finalHash})
	err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
	if err != nil {
		log.Warnf("Failed to send getheaders message to "+
			"peer %s: %v", peer.Addr(), err)
		return
	}
}

// haveInventory returns whether or not the inventory represented by the passed
// inventory vector is known.  This includes checking all of the various places
// inventory can be when it is in different states such as blocks that are part
// of the main chain, on a side chain, in the orphan pool, and transactions that
// are in the memory pool (either the main pool or orphan pool).
func (sm *SyncManager) haveInventory(invVect *wire.InvVect) (bool, error) {
	switch invVect.Type {
	case common.InvTypeWitnessBlock:
		fallthrough
	case common.InvTypeTempBlock:
		fallthrough
	case common.InvTypeBlock:
		// Ask chain if the block is known to it in any form (main
		// chain, side chain, or orphan).
		return sm.chain.HaveBlock(&invVect.Hash)

	case common.InvTypeMinerBlock:
		// Ask chain if the block is known to it in any form (main
		// chain, side chain, or orphan).
		return sm.chain.Miners.(*minerchain.MinerChain).HaveBlock(&invVect.Hash)

	case common.InvTypeWitnessTx:
		fallthrough
	case common.InvTypeTx:
		// Ask the transaction memory pool if the transaction is known
		// to it in any form (main pool or orphan).
		if sm.txMemPool.HaveTransaction(&invVect.Hash) {
			return true, nil
		}

		// Check if the transaction exists from the point of view of the
		// end of the main chain.  Note that this is only a best effort
		// since it is expensive to check existence of every output and
		// the only purpose of this check is to avoid downloading
		// already known transactions.  Only the first two outputs are
		// checked because the vast majority of transactions consist of
		// two outputs where one is some form of "pay-to-somebody-else"
		// and the other is a change output.
		prevOut := wire.OutPoint{Hash: invVect.Hash}
		for i := uint32(0); i < 2; i++ {
			prevOut.Index = i
			entry, err := sm.chain.FetchUtxoEntry(prevOut)
			if err != nil {
				return false, err
			}
			if entry != nil && !entry.IsSpent() {
				return true, nil
			}
		}

		return false, nil
	}

	// The requested inventory is is an unsupported type, so just claim
	// it is known to avoid requesting it.
	return true, nil
}

func (sm *SyncManager) TmpBlkSrc(hash chainhash.Hash) *peerpkg.Peer {
	t, _ := sm.tmpblksrc[hash]
	return t
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (sm *SyncManager) handleInvMsg(imsg *invMsg) {
	peer := imsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received inv message from unknown peer %s", peer)
		sm.updateSyncPeer()
		return
	}

	if len(imsg.inv.InvList) == 0 {
		sm.updateSyncPeer()
		return
	}

	// Attempt to find the final block in the inventory list.  There may
	// not be one.
	lastBlock := -1
	lastMinerBlock := -1
	invVects := imsg.inv.InvList
	for i := len(invVects) - 1; i >= 0; i-- {
		if invVects[i].Type&common.InvTypeMask == common.InvTypeBlock && lastBlock == -1 {
			lastBlock = i
		}
		if invVects[i].Type == common.InvTypeMinerBlock && lastMinerBlock == -1 {
			lastMinerBlock = i
		}
	}

	// If this inv contains a block announcement, and this isn't coming from
	// our current sync peer or we're current, then update the last
	// announced block for this peer. We'll use this information later to
	// update the heights of peers based on blocks we've accepted that they
	// previously announced.
	if lastBlock != -1 {
		peer.UpdateLastAnnouncedBlock(&invVects[lastBlock].Hash)
	}
	if lastMinerBlock != -1 {
		peer.UpdateLastAnnouncedMinerBlock(&invVects[lastMinerBlock].Hash)
	}

	// If our chain is current and a peer announces a block we already
	// know of, then update their current block height.
	if lastBlock != -1 {
		//	if lastBlock != -1 && sm.current(0) {
		blkHeight, err := sm.chain.BlockHeightByHash(&invVects[lastBlock].Hash)
		if err == nil {
			peer.UpdateLastBlockHeight(blkHeight)
		}
	}
	if lastMinerBlock != -1 {
		//	if lastMinerBlock != -1 && sm.current(1) {
		blkHeight, err := sm.chain.Miners.(*minerchain.MinerChain).BlockHeightByHash(&invVects[lastMinerBlock].Hash)
		if err == nil {
			peer.UpdateLastMinerBlockHeight(blkHeight)
		}
	}

	// Ignore invs from peers that aren't the sync if we are not current.
	// Helps prevent fetching a mass of orphans.
	if peer != sm.syncPeer && ((lastBlock != -1 && !sm.current(0)) ||
		(lastMinerBlock != -1 && !sm.current(1))) {
		return
	}

	var lastIgnored *wire.InvVect
	var ignorerun int
	var lastMinerIgnored *wire.InvVect
	var ignoreMinerrun int

	b1 := sm.chain.BestSnapshot()
	b2 := sm.chain.Miners.BestSnapshot()

	// Request the advertised inventory if we don't already have it.  Also,
	// request parent blocks of orphans if we receive one we already have.
	// Finally, attempt to detect potential stalls due to long side chains
	// we already have and request more blocks to prevent them.
	for i, iv := range invVects {
		switch iv.Type {
		case common.InvTypeTempBlock:
			/*
				if _, ok := sm.tmpblksrc[iv.Hash]; !ok {
					sm.tmpblksrc[iv.Hash] = peer
				}
				continue
			*/

		case common.InvTypeBlock:
			fallthrough
		case common.InvTypeWitnessBlock:
			delete(sm.tmpblksrc, iv.Hash)

		case common.InvTypeMinerBlock:
		case common.InvTypeTx:

		case common.InvTypeWitnessTx:
		default:
			// Ignore unsupported inventory types.
			continue
		}

		// Add the inventory to the cache of known inventory
		// for the peer.
		peer.AddKnownInventory(iv)

		// Ignore inventory when we're in headers-first mode.
		if sm.headersFirstMode {
			continue
		}

		// Request the inventory if we don't already have it.
		haveInv := false
		//		if iv.Type == common.InvTypeTempBlock {
		//			_, haveInv = sm.cachedBlocks[iv.Hash]
		//		}

		if !haveInv {
			var err error
			haveInv, err = sm.haveInventory(iv)
			if err != nil {
				log.Warnf("Unexpected failure when checking for "+
					"existing inventory during inv message "+
					"processing: %v", err)
				continue
			}
		}

		if !haveInv {
			if iv.Type == common.InvTypeTx {
				// Skip the transaction if it has already been
				// rejected.
				if _, exists := sm.rejectedTxns[iv.Hash]; exists {
					continue
				}
			}

			// Add it to the request queue.
			//			log.Infof("%s does not exist add to requestQueue", iv.Hash.String())
			//			if iv.Type == common.InvTypeTempBlock {
			// we request a InvTypeWitnessBlock when inv is a InvTypeTempBlock in case
			// the block has come into the chain in client side
			//				iv.Type = common.InvTypeWitnessBlock
			//			}
			state.requestQueue = append(state.requestQueue, iv)
			continue
		}

		if (i == lastBlock || i == lastMinerBlock) && len(imsg.inv.InvList) > 1 {
			// in any case, we will request the last one in inv list to notify
			// the peer to send us new batch of inv list if any
			// TBD: optimization: instead of requesting a block which may be a waste,
			// can we ask for something else?
			state.requestQueue = append(state.requestQueue, iv)
		}

		if iv.Type&common.InvTypeBlock == common.InvTypeBlock {
			if !sm.chain.InBestChain(&iv.Hash) {
				// if the block is in a side chain, pretend it as an orphan, so we
				// will try to connect it in case the side chain becomes main chain
				po, _ := sm.chain.AnyBlockByHash(&iv.Hash)
				if po != nil {
					sm.chain.Orphans.AddOrphanBlock(blockchain.BlockToOrphan(po))
				} else {
					// try to retrieve it again
					state.requestQueue = append(state.requestQueue, iv)
					log.Infof("node not found")
				}
			}
			// The block is an orphan block that we already have.
			// When the existing orphan was processed, it requested
			// the missing parent blocks.  When this scenario
			// happens, it means there were more blocks missing
			// than are allowed into a single inventory message.  As
			// a result, once this peer requested the final
			// advertised block, the remote peer noticed and is now
			// resending the orphan block as an available block
			// to signal there are more missing blocks that need to
			// be requested.
			if sm.chain.Orphans.IsKnownOrphan(&iv.Hash) {
				// Request blocks starting at the latest known
				// up to the root of the orphan that just came
				// in.
				if !sm.chain.TryConnectOrphan(&iv.Hash) {
					if _, ok := sm.requestedOrphans[iv.Hash]; !ok || sm.requestedOrphans[iv.Hash] > 10 {
						log.Tracef("request %s is known orphan", iv.Hash.String())
						sm.requestedOrphans[iv.Hash] = 1
						orphanRoot := sm.chain.Orphans.GetOrphanRoot(&iv.Hash)
						locator, err := sm.chain.LatestBlockLocator()
						mlocator, err := sm.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
						if err != nil {
							log.Errorf("PEER: Failed to get block "+
								"locator for the latest block: "+
								"%v", err)
							continue
						}
						sm.AddSyncJob(peer, locator, mlocator, orphanRoot, &zeroHash,
							[2]int32{b1.Height, b2.Height})
					} else {
						sm.requestedOrphans[iv.Hash]++
					}
				} else {
					delete(sm.requestedOrphans, iv.Hash)
				}
				continue
			}

			lastIgnored = iv
			ignorerun++

			// We already have the final block advertised by this
			// inventory message, so force a request for more.  This
			// should only happen if we're on a really long side
			// chain.
			/*
			   			if i == lastBlock && len(imsg.inv.InvList) > 1 {
			   //				log.Infof("Request blocks after %s from remote peer", iv.Hash.String())

			   				// Request blocks after this one up to the
			   				// final one the remote peer knows about (zero
			   				// stop hash).
			   				locator := sm.chain.BlockLocatorFromHash(&iv.Hash)
			   				mlocator, _ := sm.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
			   				log.Infof("handleInvMsg PushGetBlocksMsg because done with the last inv")
			   				peer.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
			   			}
			*/
		} else if iv.Type == common.InvTypeMinerBlock {
			// The block is an orphan miner block that we already have.
			// When the existing orphan was processed, it requested
			// the missing parent blocks.  When this scenario
			// happens, it means there were more blocks missing
			// than are allowed into a single inventory message.  As
			// a result, once this peer requested the final
			// advertised block, the remote peer noticed and is now
			// resending the orphan block as an available block
			// to signal there are more missing blocks that need to
			// be requested.
			ch := sm.chain.Miners.(*minerchain.MinerChain)

			if !ch.MainChainHasBlock(&iv.Hash) {
				po, _ := ch.AnyBlockByHash(&iv.Hash)
				if po != nil {
					ch.Orphans.AddOrphanBlock(minerchain.BlockToOrphan(po))
				} else {
					// try to retrieve it again
					state.requestQueue = append(state.requestQueue, iv)
				}
			}

			if ch.Orphans.IsKnownOrphan(&iv.Hash) {
				// Request blocks starting at the latest known
				// up to the root of the orphan that just came
				// in.

				if !ch.TryConnectOrphan(&iv.Hash) {

					if _, ok := sm.requestedOrphans[iv.Hash]; !ok || sm.requestedOrphans[iv.Hash] > 10 {
						sm.requestedOrphans[iv.Hash] = 1
						orphanRoot := ch.Orphans.GetOrphanRoot(&iv.Hash)
						locator, err := ch.LatestBlockLocator()
						if err != nil {
							log.Errorf("PEER: Failed to get block "+
								"locator for the latest block: "+
								"%v", err)
							continue
						}
						log.Tracef("handleInvMsg: PushGetBlocksMsg from %s because encountered an miner orphan %s", peer.Addr(), iv.Hash.String())
						tlocator, _ := sm.chain.LatestBlockLocator()
						sm.AddSyncJob(peer, tlocator, locator, &zeroHash, orphanRoot,
							[2]int32{b1.Height, b2.Height})
						//						peer.PushGetBlocksMsg(tlocator, locator, &zeroHash, orphanRoot)
					} else {
						sm.requestedOrphans[iv.Hash]++
					}
				} else {
					delete(sm.requestedOrphans, iv.Hash)
				}
				continue
			}

			lastMinerIgnored = iv
			ignoreMinerrun++
			// We already have the final block advertised by this
			// inventory message, so force a request for more.  This
			// should only happen if we're on a really long side
			// chain.
			/*
				if i == lastMinerBlock && len(imsg.inv.InvList) > 1 {
					// Request blocks after this one up to the
					// final one the remote peer knows about (zero
					// stop hash).
					locator := ch.BlockLocatorFromHash(&iv.Hash)
					tlocator, _ := sm.chain.LatestBlockLocator()
					peer.PushGetBlocksMsg(tlocator, locator, &zeroHash, &zeroHash)
				}
			*/
		}
	}

	if ignorerun+ignoreMinerrun == len(invVects) ||
		(len(invVects) == 1 && len(sm.syncjobs) == 0 && (!sm.current(0) || !sm.current(1))) {
		// either we got nothing new. retry a new sync job
		// or we receive one inv. most likely because of new block, which
		// could interrupt our sync process
		mlocator := make([]*chainhash.Hash, 1)
		tlocator := make([]*chainhash.Hash, 1)
		if lastIgnored != nil {
			tlocator[0] = &lastIgnored.Hash
		} else {
			tlocator = nil
		}
		if lastMinerIgnored != nil {
			mlocator[0] = &lastMinerIgnored.Hash
		} else {
			mlocator = nil
		}
		if mlocator != nil || tlocator != nil {
			sm.AddSyncJob(peer, tlocator, mlocator, &zeroHash, &zeroHash,
				[2]int32{b1.Height, b2.Height})
		}
	}

	if lastIgnored != nil && ignorerun > 1 && lastIgnored.Type != common.InvTypeTempBlock {
		//		log.Infof("send back %s for %d run of ignores inv to %s", lastIgnored.Hash.String(), ignorerun, peer.Addr())
		// send back this one so the peer knows where we are
		sbmsg := &wire.MsgInv{InvList: []*wire.InvVect{lastIgnored}}
		peer.QueueMessageWithEncoding(sbmsg, nil, wire.SignatureEncoding) // | wire.FullEncoding)

		// check if it causes a reorg
		/*
			sm.chain.ChainLock.Lock()
			sm.chain.CheckSideChain(&lastIgnored.Hash)
			sm.chain.ChainLock.Unlock()
		*/
	}

	if lastMinerIgnored != nil && ignoreMinerrun > 1 {
		//		log.Infof("send back %s for %d run of ignores miner inv to %s", lastMinerIgnored.Hash.String(), ignoreMinerrun, peer.Addr())
		// send back this one so the peer knows where we are
		sbmsg := &wire.MsgInv{InvList: []*wire.InvVect{lastMinerIgnored}}
		peer.QueueMessageWithEncoding(sbmsg, nil, wire.SignatureEncoding)

		// check if it causes a reorg
		/*
			sm.chain.ChainLock.Lock()
			sm.chain.Miners.(*minerchain.MinerChain).CheckSideChain(&lastMinerIgnored.Hash)
			sm.chain.ChainLock.Unlock()
		*/
	}

	// Request as much as possible at once.  Anything that won't fit into
	// the request will be requested on the next inv message.
	numRequested := 0
	gdmsg := wire.NewMsgGetData()

	resync := false

	tm := int(time.Now().Unix())
	for len(state.requestQueue) != 0 {
		iv := state.requestQueue[0]
		state.requestQueue[0] = nil
		state.requestQueue = state.requestQueue[1:]

		switch iv.Type {
		case common.InvTypeBlock:
			fallthrough
		case common.InvTypeWitnessBlock:
			fallthrough
		case common.InvTypeMinerBlock:
			// Request the block if there is not already a pending
			// request.
			_, exists := sm.requestedBlocks[iv.Hash]
			tm0, exists2 := state.requestedBlocks[iv.Hash]
			if !exists || (exists2 && tm-tm0 > 50) {
				sm.requestedBlocks[iv.Hash] = 1
				state.requestedBlocks[iv.Hash] = tm

				sm.limitMap(sm.requestedBlocks, 2*maxRequestedBlocks)

				//				log.Infof("tx request %s add to queue list", iv.Hash.String())

				gdmsg.AddInvVect(iv)
				numRequested++
			} else {
				//				log.Infof("tx Repeated %d request for %s", state.requestedBlocks[iv.Hash], iv.Hash.String())
				if sm.requestedBlocks[iv.Hash] >= 10 {
					delete(sm.requestedBlocks, iv.Hash)
					delete(state.requestedBlocks, iv.Hash)
					// too many tries. try another peer to sync
					if !resync {
						resync = true
						defer func() {
							p := sm.syncPeer
							sm.syncPeer = nil
							sm.startSync(p)
						}()
					}
				} else {
					sm.requestedBlocks[iv.Hash]++
				}
			}

		case common.InvTypeWitnessTx:
			fallthrough
		case common.InvTypeTx:
			// Request the transaction if there is not already a
			// pending request.
			if _, exists := sm.requestedTxns[iv.Hash]; !exists {
				sm.requestedTxns[iv.Hash] = struct{}{}
				sm.limitMap(sm.requestedTxns, maxRequestedTxns)
				state.requestedTxns[iv.Hash] = struct{}{}

				// If the peer is capable, request the txn
				// including all witness data.
				if peer.IsWitnessEnabled() {
					iv.Type = common.InvTypeWitnessTx
				}

				gdmsg.AddInvVect(iv)
				numRequested++
			}
		}

		if numRequested >= wire.MaxInvPerMsg {
			break
		}
	}

	if len(gdmsg.InvList) > 0 {
		peer.QueueMessage(gdmsg, nil)
	}
}

// limitMap is a helper function for maps that require a maximum limit by
// evicting a random transaction if adding a new value would cause it to
// overflow the maximum allowed.
func (sm *SyncManager) limitMap(m interface{}, limit int) {
	switch m.(type) {
	case map[chainhash.Hash]int:
		t := m.(map[chainhash.Hash]int)
		if len(t)+1 > limit {
			// Remove a random entry from the map.  For most compilers, Go's
			// range statement iterates starting at a random item although
			// that is not 100% guaranteed by the spec.  The iteration order
			// is not important here because an adversary would have to be
			// able to pull off preimage attacks on the hashing function in
			// order to target eviction of specific entries anyways.
			for txHash := range t {
				delete(t, txHash)
				return
			}
		}

	case map[chainhash.Hash]struct{}:
		t := m.(map[chainhash.Hash]struct{})
		if len(t)+1 > limit {
			// Remove a random entry from the map.  For most compilers, Go's
			// range statement iterates starting at a random item although
			// that is not 100% guaranteed by the spec.  The iteration order
			// is not important here because an adversary would have to be
			// able to pull off preimage attacks on the hashing function in
			// order to target eviction of specific entries anyways.
			for txHash := range t {
				delete(t, txHash)
				return
			}
		}
	}
}

func (sm *SyncManager) CachedBlock(h chainhash.Hash) *btcutil.Block {
	if b, ok := sm.cachedBlocks[h]; ok {
		return b
	}
	return nil
}

func (sm *SyncManager) Broadcast(m wire.Message, ps *string) {
	sm.broadcast(nil, m, ps)
}

func (sm *SyncManager) broadcast(p *peerpkg.Peer, m wire.Message, ps *string) {
	var h chainhash.Hash
	var w bytes.Buffer

	w.Write([]byte(m.Command()))
	m.OmcEncode(&w, 0, wire.FullEncoding)
	copy(h[:], chainhash.HashB(w.Bytes()))

	sm.castmx.Lock()
	defer func() {
		sm.castmx.Unlock()
	}()

	now := time.Now().Unix()

	if _, ok := sm.castedMsg[h]; !ok {
		sm.castedMsg[h] = now
		for peer, _ := range sm.peerStates {
			if p == nil || (peer.ID() != p.ID() && (ps == nil || peer.Addr() != *ps)) {
				peer.QueueMessageWithEncoding(m, nil, wire.FullEncoding)
			}
		}
	}

	for h, t := range sm.castedMsg {
		if now-t > 5 {
			delete(sm.castedMsg, h)
		}
	}
}

// blockHandler is the main handler for the sync manager.  It must be run as a
// goroutine.  It processes block and inv messages in a separate goroutine
// from the peer handlers so the block (MsgBlock) messages are handled by a
// single thread without needing to lock memory data structures.  This is
// important because the sync manager controls which blocks are needed and how
// the fetching should proceed.
func (sm *SyncManager) blockHandler() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	sm.lastBlockOp = ""

out:
	for {
		//		if len(sm.msgChan) > 5 {
		//			log.Infof("blockHandler queue pending len = ", len(sm.msgChan))
		//		}

		select {
		case <-ticker.C:
			sm.lastBlockOp = "ticker.C"
			sm.updateSyncPeer()

		case m := <-sm.msgChan:
			log.Debugf("blockHandler took a message from sm.msgChan: ", reflect.TypeOf(m).String())
			sm.lastBlockOp = "sm.msgChan"

			switch msg := m.(type) {
			case *newPeerMsg:
				sm.handleNewPeerMsg(msg.peer)

			case *txMsg:
				sm.handleTxMsg(msg)
				msg.reply <- struct{}{}

			case *sigMsg:
				if b, ok := sm.cachedBlocks[msg.hash]; ok {
					b.MsgBlock().Transactions[0].SignatureScripts = msg.signatures
					bm := blockMsg{
						b,
						msg.peer,
						msg.reply,
					}
					sm.handleBlockMsg(&bm)
				}
				msg.reply <- struct{}{}

				// we should broadcast this message here
				b := wire.MsgSignatures{
					msg.hash,
					msg.signatures,
				}
				sm.broadcast(msg.peer, &b, nil)

			case *blockMsg:
				sm.handleBlockMsg(msg)
				msg.reply <- struct{}{}

			case *minerBlockMsg:
				sm.handleMinerBlockMsg(msg)
				msg.reply <- struct{}{}

			case *invMsg:
				sm.handleInvMsg(msg)

			case *headersMsg:
				sm.handleHeadersMsg(msg)

			case *donePeerMsg:
				sm.handleDonePeerMsg(msg.peer)

			case getSyncPeerMsg:
				var peerID int32
				p := sm.syncPeer
				if p != nil {
					peerID = p.ID()
				}
				msg.reply <- peerID

			case processBlockMsg:
				main, isOrphan, err, _, _ := sm.chain.ProcessBlock(msg.block, msg.flags)
				if msg.reply != nil {
					sm.lastBlockOp += " ... waiting reply from sm.chain.ProcessBlock "
					if err != nil {
						msg.reply <- processBlockResponse{
							isMain:   main,
							isOrphan: false,
							err:      err,
						}
					} else {
						msg.reply <- processBlockResponse{
							isMain:   main,
							isOrphan: isOrphan,
							err:      nil,
						}
					}
				}

			case processConsusMsg:
				consensus.ProcessBlock(msg.block, msg.flags)

			case processMinerBlockMsg:
				if sm.chainParams.Net == common.TestNet || sm.chainParams.Net == common.SimNet || sm.chainParams.Net == common.RegNet {
					msg.flags |= blockchain.BFEasyBlocks
				}
				main, isOrphan, err, _ := sm.chain.Miners.ProcessBlock(
					msg.block, msg.flags)
				if msg.reply != nil {
					sm.lastBlockOp += " ... waiting reply from sm.chain.Miners.ProcessBlock "
					if err != nil {
						msg.reply <- processBlockResponse{
							isMain:   main,
							isOrphan: false,
							err:      err,
						}
					} else {
						msg.reply <- processBlockResponse{
							isMain:   main,
							isOrphan: isOrphan,
							err:      nil,
						}
					}
				}

			case resetConnMsg:
				sm.resetConnections(msg.all)
				msg.reply <- struct{}{}

			case isCurrentMsg:
				msg.reply <- sm.current(0) && sm.current(1)

			case startSyncMsg:
				sm.startSync(nil)
				if msg.reply != nil {
					msg.reply <- struct{}{}
				}

			case pauseMsg:
				// Wait until the sender unpauses the manager.
				<-msg.unpause

			default:
				log.Warnf("Invalid message type in block "+
					"handler: %T", msg)
			}

			log.Debugf("blockHandler finished with message: ", reflect.TypeOf(m).String())

		case <-sm.quit:
			sm.syncjobs = sm.syncjobs[:0]
			break out
		}
		sm.lastBlockOp += " ... Done."
	}

	sm.wg.Done()
	log.Trace("Block handler done")
}

// handleBlockchainNotification handles notifications from blockchain.  It does
// things such as request orphan block parents and relay accepted blocks to
// connected peers.
func (sm *SyncManager) handleBlockchainNotification(notification *blockchain.Notification) {
	switch notification.Type {
	// A block has been accepted into the block chain.  Relay it to other
	// peers.
	case blockchain.NTBlockAccepted:
		// Don't relay if we are not current. Other peers that are
		// current should already know about it.
		switch notification.Data.(type) {
		case *btcutil.Block:
			if !sm.current(0) {
				return
			}
			block := notification.Data.(*btcutil.Block)
			// Generate the inventory vector and relay it.
			iv := wire.NewInvVect(common.InvTypeWitnessBlock, block.Hash())
			sm.peerNotifier.RelayInventory(iv, block.MsgBlock().Header)

		case *wire.MinerBlock:
			if !sm.current(1) {
				return
			}
			block := notification.Data.(*wire.MinerBlock)
			iv := wire.NewInvVect(common.InvTypeMinerBlock, block.Hash())
			sm.peerNotifier.RelayInventory(iv, block.MsgBlock())

		default:
			log.Warnf("Chain accepted notification is not a block, it is %s", reflect.TypeOf(notification.Data).String())
		}

	// A block has been connected to the main block chain.
	case blockchain.NTBlockConnected:
		if block, ok := notification.Data.(*wire.MinerBlock); ok {
			if !sm.current(1) {
				return
			}
			for peer, _ := range sm.peerStates {
				if peer.LastMinerBlock() < block.Height() && block.Height() < peer.LastMinerBlock()+50 {
					// should send an inv msg
					invVect := &wire.InvVect{
						Type: common.InvTypeMinerBlock,
						Hash: *block.Hash(),
					}
					peer.QueueInventory(invVect)
				}
			}
			//			log.Warnf("Chain NTBlockConnected notification is not a block, it is %s", reflect.TypeOf(notification.Data).String())
			break
		}

		if !sm.current(0) {
			return
		}

		block, ok := notification.Data.(*btcutil.Block)
		if ok {
			// notify peers of new height if our height is greater than we know the peer has
			for peer, _ := range sm.peerStates {
				if peer.LastBlock() < block.Height() && block.Height() < peer.LastBlock()+500 {
					invVect := &wire.InvVect{
						Type: common.InvTypeWitnessBlock,
						Hash: *block.Hash(),
					}
					peer.QueueInventory(invVect)
				}
			}

			// Remove all of the transactions (except the coinbase) in the
			// connected block from the transaction pool.  Secondly, remove any
			// transactions which are now double spends as a result of these
			// new transactions.  Finally, remove any transaction that is
			// no longer an orphan. Height which depend on a confirmed
			// transaction are NOT removed recursively because they are still
			// valid.
			for _, tx := range block.Transactions()[1:] {
				sm.txMemPool.RemoveTransaction(tx, false)
				sm.txMemPool.RemoveDoubleSpends(tx)
				sm.txMemPool.RemoveOrphan(tx)
				sm.peerNotifier.TransactionConfirmed(tx)
				acceptedTxs := sm.txMemPool.ProcessOrphans(tx)
				sm.peerNotifier.AnnounceNewTransactions(acceptedTxs)
			}

			// Register block with the fee estimator, if it exists.
			if sm.feeEstimator != nil {
				err := sm.feeEstimator.RegisterBlock(block)

				// If an error is somehow generated then the fee estimator
				// has entered an invalid state. Since it doesn't know how
				// to recover, create a new one.
				if err != nil {
					sm.feeEstimator = mempool.NewFeeEstimator(
						mempool.DefaultEstimateFeeMaxRollback,
						mempool.DefaultEstimateFeeMinRegisteredBlocks)
				}
			}
		}

	// A block has been disconnected from the main block chain.
	case blockchain.NTBlockDisconnected:
		block, ok := notification.Data.(*btcutil.Block)
		if !ok {
			//			log.Warnf("Chain NTBlockDisconnected notification is not a block, it is %s", reflect.TypeOf(notification.Data).String())
			break
		}

		// Reinsert all of the transactions (except the coinbase) into
		// the transaction pool.
		for _, tx := range block.Transactions()[1:] {
			_, _, err := sm.txMemPool.MaybeAcceptTransaction(tx,
				false, false)
			if err != nil {
				// Remove the transaction and all transactions
				// that depend on it if it wasn't accepted into
				// the transaction pool.
				sm.txMemPool.RemoveTransaction(tx, true)
			}
		}

		// Rollback previous block recorded by the fee estimator.
		if sm.feeEstimator != nil {
			sm.feeEstimator.Rollback(block.Hash())
		}
	}
}

// NewPeer informs the sync manager of a newly active peer.
func (sm *SyncManager) NewPeer(peer *peerpkg.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}
	sm.msgChan <- &newPeerMsg{peer: peer}
}

// QueueTx adds the passed transaction message and peer to the block handling
// queue. Responds to the done channel argument after the tx message is
// processed.
func (sm *SyncManager) QueueTx(tx *btcutil.Tx, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more transactions if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		log.Trace("shutting down in pogress in QueueTx")
		done <- struct{}{}
		return
	}

	sm.msgChan <- &txMsg{tx: tx, peer: peer, reply: done}
}

func (sm *SyncManager) QueueSignatures(msg *wire.MsgSignatures, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		log.Trace("shutting down in pogress in QueueBlock")
		done <- struct{}{}
		return
	}

	sm.msgChan <- &sigMsg{
		hash:       msg.Hash,
		signatures: msg.Signatures,
		peer:       peer,
		reply:      done,
	}
}

// QueueBlock adds the passed block message and peer to the block handling
// queue. Responds to the done channel argument after the block message is
// processed.
func (sm *SyncManager) QueueBlock(block *btcutil.Block, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		log.Trace("shutting down in pogress in QueueBlock")
		done <- struct{}{}
		return
	}

	sm.msgChan <- &blockMsg{block: block, peer: peer, reply: done}
}

func (sm *SyncManager) QueueMinerBlock(block *wire.MinerBlock, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		log.Trace("shutting down in pogress in QueueMinerBlock")
		done <- struct{}{}
		return
	}

	sm.msgChan <- &minerBlockMsg{block: block, peer: peer, reply: done}
}

// QueueInv adds the passed inv message and peer to the block handling queue.
func (sm *SyncManager) QueueInv(inv *wire.MsgInv, peer *peerpkg.Peer) {
	// No channel handling here because peers do not need to block on inv
	// messages.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	//	log.Infof("OnInv add to sm.msgChan, len = %d", len(sm.msgChan))

	sm.msgChan <- &invMsg{inv: inv, peer: peer}
}

// QueueHeaders adds the passed headers message and peer to the block handling
// queue.
func (sm *SyncManager) QueueHeaders(headers *wire.MsgHeaders, peer *peerpkg.Peer) {
	// No channel handling here because peers do not need to block on
	// headers messages.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	sm.msgChan <- &headersMsg{headers: headers, peer: peer}
}

// DonePeer informs the blockmanager that a peer has disconnected.
func (sm *SyncManager) DonePeer(peer *peerpkg.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}
	log.Trace("DonePeer")

	sm.msgChan <- &donePeerMsg{peer: peer}
}

// Start begins the core block handler which processes block and inv messages.
func (sm *SyncManager) Start() {
	// Already started?
	if atomic.AddInt32(&sm.started, 1) != 1 {
		return
	}

	log.Trace("Starting sync manager")
	sm.wg.Add(1)
	go sm.blockHandler()
}

// Stop gracefully shuts down the sync manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (sm *SyncManager) Stop() error {
	log.Infof("Stopping Sync manager ")
	if atomic.AddInt32(&sm.shutdown, 1) != 1 {
		log.Warnf("Sync manager is already in the process of shutting down")
		return nil
	}

	sm.bshutdown = true

	//	log.Tracef("Sync manager shutting down. Last message was:\n%s", sm.lastBlockOp)

	close(sm.quit)
	sm.wg.Wait()

	log.Infof("Sync manager stopped")
	return nil
}

// SyncPeerID returns the ID of the current sync peer, or 0 if there is none.
func (sm *SyncManager) SyncPeerID() int32 {
	reply := make(chan int32)
	sm.msgChan <- getSyncPeerMsg{reply: reply}
	return <-reply
}

// ProcessBlock makes use of ProcessBlock on an internal instance of a block
// chain.
func (sm *SyncManager) ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) (bool, error) {
	reply := make(chan processBlockResponse, 1)

	if block.MsgBlock().Header.Nonce < 0 && wire.CommitteeSize > 1 && len(block.MsgBlock().Transactions[0].SignatureScripts) <= wire.CommitteeSigs {
		log.Debugf("procssing a comittee block, height = %d", block.Height())
		sm.msgChan <- processBlockMsg{block: block, flags: flags | blockchain.BFSubmission, reply: reply}

		response := <-reply
		if response.err != nil {
			fmt.Printf("netsync.ProcessBlock processBlockMsg got error: %s", response.err.Error())
			return false, response.err
		}

		// for local consensus generation
		//		log.Infof("send for consensus generation at %d", block.Height())
		fmt.Printf("send for consensus generation at %d", block.Height())
		sm.msgChan <- processConsusMsg{block: block, flags: flags}
		// treating these blocks as orphans because we may need to pull them upon request
		return false, nil
	} else {
		sm.msgChan <- processBlockMsg{block: block, flags: flags, reply: reply}
		response := <-reply
		return response.isOrphan || !response.isMain, response.err
	}
}

// ProcessMinerBlock makes use of ProcessBlock on an internal instance of a block
// chain.
func (sm *SyncManager) ProcessMinerBlock(block *wire.MinerBlock, flags blockchain.BehaviorFlags) (bool, error) {
	reply := make(chan processBlockResponse, 1)
	sm.msgChan <- processMinerBlockMsg{block: block, flags: flags, reply: reply}
	response := <-reply
	return !response.isMain || response.isOrphan, response.err
}

// IsCurrent returns whether or not the sync manager believes it is synced with
// the connected peers.
func (sm *SyncManager) IsCurrent() bool {
	reply := make(chan bool)
	sm.msgChan <- isCurrentMsg{reply: reply}
	return <-reply
}

// Pause pauses the sync manager until the returned channel is closed.
//
// Note that while paused, all peer and block processing is halted.  The
// message sender should avoid pausing the sync manager for long durations.
func (sm *SyncManager) Pause() chan<- struct{} {
	c := make(chan struct{})
	sm.msgChan <- pauseMsg{c}
	return c
}

// New constructs a new SyncManager. Use Start to begin processing asynchronous
// block, tx, and inv updates.
func New(config *Config) (*SyncManager, error) {
	sm := SyncManager{
		peerNotifier:     config.PeerNotifier,
		chain:            config.Chain,
		txMemPool:        config.TxMemPool,
		chainParams:      config.ChainParams,
		rejectedTxns:     make(map[chainhash.Hash]struct{}),
		requestedTxns:    make(map[chainhash.Hash]struct{}),
		requestedBlocks:  make(map[chainhash.Hash]int),
		requestedOrphans: make(map[chainhash.Hash]int),
		peerStates:       make(map[*peerpkg.Peer]*peerSyncState),
		progressLogger:   newBlockProgressLogger("Processed", log),
		msgChan:          make(chan interface{}, config.MaxPeers*3),
		headerList:       list.New(),
		quit:             make(chan struct{}),
		feeEstimator:     config.FeeEstimator,
		cachedBlocks:     make(map[chainhash.Hash]*btcutil.Block),
		castedMsg:        make(map[chainhash.Hash]int64),
		syncjobs:         make([]*pendginGetBlocks, 0),
		syncPeer:         nil,
		tmpblksrc:        make(map[chainhash.Hash]*peerpkg.Peer),
	}

	best := sm.chain.BestSnapshot()
	if !config.DisableCheckpoints {
		// Initialize the next checkpoint based on the current height.
		sm.nextCheckpoint = sm.findNextHeaderCheckpoint(best.Height)
		if sm.nextCheckpoint != nil {
			sm.resetHeaderState(&best.Hash, best.Height)
		}
	} else {
		log.Info("Checkpoints are disabled")
	}

	sm.chain.Subscribe(sm.handleBlockchainNotification)
	sm.chain.Miners.Subscribe(sm.handleBlockchainNotification)

	return &sm, nil
}
