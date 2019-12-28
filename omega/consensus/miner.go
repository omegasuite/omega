package consensus

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCommitteeSize			= 3
	DefaultSenatorSize			= 50
	DefaultBond					= 500
	DefaultDifficulty				= 20
	DefaultCandidateDfct			= 15
	DefaultStaleTime				= 10		// Time (s) elapsed since last new block/TX received before committee is considered stale
	maxTxPerBlock = 50000 / 8
)

type Config struct {
	Blocks        int64  // number of blocks in chain
	LastBlockNum  int64  // last blocks num = Blocks - 1
	CommitteeSize int    // committee size = 3
	Difficulty    byte   // difficulty level
	Deposit       int64  // deposit for candidate node
	CandidateDfct int    // candidate difficulty	= CommitteeSize + Difficulty
	LastHash      chainhash.Hash // hash of last block
	Debug	      int // hash of last block

	Myself 		  [20]byte // my account address. Hash of pub key
	Bonder		  *[20]byte		// bond account address. Hash of pub key
	PrivKey 	  *btcec.PrivateKey
	DataDir		  string
}

// Miner keeps most current chain status
// Mamage multiple synerss
// Dispatch messages to the proper syner
type Miner struct {
	Cfg			  Config

	Committee 	  Committee

	sync      	map[int64]*Syncer
	syncMutex 	* sync.Mutex

	running int64

	miningstatus int

	BlkDone chan int64
}

func ProcessBlock(b *blockchain.BlockChain, block *btcutil.Block, flags blockchain.BehaviorFlags) (bool, bool, error) {
	return b.ProcessBlock(block, flags)
}

func CreateMiner(committeeSize int32, senators int32, pk *btcec.PrivateKey, adr *[20]byte, bond int64, diff byte, cdiff int, DataDir string) *Miner {
	p := Miner{}
	p.sync = make(map[int64]*Syncer, 0)
	p.syncMutex = &sync.Mutex{}

	p.Committee = *NewCommittee(committeeSize, *adr)
	p.Cfg.Deposit = bond
	p.Cfg.Bonder = nil
	p.Cfg.CommitteeSize = int(committeeSize)
	p.Cfg.Difficulty = diff
	p.Cfg.CandidateDfct = cdiff
	p.Cfg.Myself = *adr
	p.Cfg.PrivKey = pk
	p.Cfg.DataDir = DataDir

	return &p
}

func (self *Miner) Init(blks int64, h * chainhash.Hash, b *[20]byte) {
	self.Cfg.Blocks =  blks
	self.Cfg.LastBlockNum  = blks - 1
	self.Cfg.LastHash = *h
	self.Cfg.Bonder = b
}

var doneque = make(map[int64]bool, 0)
var Mutex sync.Mutex

func (self * Miner) StopMining() {
	self.syncMutex.Lock()
	for _,sync := range self.sync {
		sync.Reset()
	}
	self.sync = make(map[int64]*Syncer)
	self.syncMutex.Unlock()
	doneque = make(map[int64]bool, 0)
}

func (self * Miner) TxRcvd(tx []*mempool.TxDesc) {
	for _,sync := range self.sync {
		sync.TxRcvd(tx)
	}
}

func (self * Miner) Domining(blockHeight int32, head * wire.BlockHeader) * Syncer {
	Mutex.Lock()

	self.miningstatus = 1
	self.syncMutex.Lock()

	if len(self.sync) > 5 {
		min := self.Cfg.LastBlockNum
		for a,_ := range self.sync {
			if a < min {
				min = a
			}
		}
		if min < self.Cfg.LastBlockNum - 10 {
			self.sync[min].Reset()		// to release PendingCheck chan
			delete(self.sync, min)
		}
	}

	blkNum := int64(blockHeight)
	self.running = blkNum

	var sync * Syncer
	var ok bool
	if sync,ok = self.sync[blkNum]; !ok {
		sync = CreateSyncer(self, blkNum)
		self.sync[blkNum] = sync
	} else {
		if self.Committee.Start + self.Committee.CommitteeSize > int32(blkNum) {
			return nil
		}
		for self.Committee.Start + self.Committee.CommitteeSize < int32(blkNum) {
			// add first node to senator if qualified

			self.Committee.Rotate()
		}
		sync.SetCommittee(self)
	}
	self.syncMutex.Unlock()

	sync.Reset()

	Mutex.Unlock()

	self.miningstatus = 5
	sync.Init(&head.MerkleRoot)

	cls := func () {
		n := int64(0)

		if _, ok := doneque[blkNum]; !ok {
			for n != blkNum {
				n = <-self.BlkDone

				if n > blkNum {
					doneque[n] = true
				}

				self.miningstatus = 7
			}
//		} else {
//			delete(doneque, blkNum)
		}
		for i,_ := range doneque {
			if i < blkNum {
				delete(doneque, i)
			}
		}

		self.miningstatus = 8

		if n == blkNum {
			self.syncMutex.Lock()
			delete(self.sync, blkNum)
			self.syncMutex.Unlock()
		}

		self.miningstatus = 3

		self.syncMutex.Lock()
		for i, _ := range self.sync {
			self.sync[i].Status = 0
		}
		self.sync = make(map[int64]*Syncer, 0)
		self.syncMutex.Unlock()
	}

	go cls()

	return sync
//	sync.DoMining(head)
}

func (self *Miner) BlockByHash(blk *chainhash.Hash) (*btcutil.Block,error)  {
	for _,s := range self.sync {
		if s.Root == *blk {
			nextBlockVersion := int32(1)

			var msgBlock wire.MsgBlock
			msgBlock.Header = wire.BlockHeader{
				Version:    nextBlockVersion,
				PrevBlock:  self.Cfg.LastHash,
				MerkleRoot: s.Root,
				Timestamp:  s.nbk.Timestamp,
				//		Bits:       reqDifficulty,
			}
			msgBlock.Transactions = *s.txs
			b := btcutil.NewBlock(&msgBlock)
			b.SetHeight(int32(self.Cfg.Blocks))
			return b, nil
		}
	}
	return nil, &wire.MessageError{"miner.BlockByHash", "Not in mining"}
}

func (self *Miner) GetSyncer(blk int64) * Syncer {
	var s * Syncer
	var ok bool
	self.syncMutex.Lock()
	if s,ok = self.sync[blk]; !ok {
		s = CreateSyncer(nil, blk)
		self.sync[blk] = s
	}
	self.syncMutex.Unlock()
	return s
}

func VerifyMsg(msg OmegaMessage, pubkey * btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

func (self *Miner) KnowledgeFunc(p *peer.Peer, msg *MsgKnowledge) {	//w http.ResponseWriter, r *http.Request) {
	if !VerifyMsg(*msg, self.Committee.PubKey(&msg.From).PubKey()) {
		return
	}
	blk := int64(msg.Height)
	if s := self.GetSyncer(blk); s != nil {
		s.KnowledgeFunc(p, msg)	// w, r)
	}
}

func (self *Miner) OnTmpMerkleBlock(p *peer.Peer, msg *MsgTmpMerkleBlock) {	//w http.ResponseWriter, r *http.Request) {
	for i,s := range self.sync {
		if s.Root !=  msg.Blk.Header.MerkleRoot {
			continue
		}
		s.Validatercvblk <- struct { from int32
			blk MsgTmpMerkleBlock } { from: int32(i), blk: *msg }
	}
}

func (self *Miner) Candidate(p *peer.Peer, msg *MsgCandidate) {	// w http.ResponseWriter, r *http.Request) {
	if !VerifyMsg(*msg, self.Committee.PubKey(&msg.F).PubKey()) {
		return
	}
	blk := int64(msg.Height)
	if s := self.GetSyncer(blk); s != nil {
		s.Candidate(p, msg)
	}
}

func (self *Miner) CandidateReply(msg *MsgCandidateResp) {	// w http.ResponseWriter, r *http.Request) {
	respMutex.Lock()
	r,ok := candidacyResp[msg.Nonce]
	respMutex.Unlock()
	if !ok {
		return
	}

	k := self.Committee.Addresses[r.Q]
	if !VerifyMsg(*msg, k.PubKey()) {
		return
	}
	if strings.Compare(msg.Reply, "consent") == 0 {
		r.Sync.consents[r.Q] = 1
		r.Sync.ckconsensus(r.BlkNum)
	} else if strings.Compare(msg.Reply, "reject") == 0 {
		r.Sync.consents[r.Q] = 0
	} else {
		time.Sleep(1 * time.Second)
		r.Client.QueueMessage(r.Msg, nil)
		return
	}
	respMutex.Lock()
	delete(candidacyResp, nonce)
	for i,r := range candidacyResp {
		if r.BlkNum < int64(msg.Height - 10) {
			delete(candidacyResp, i)
		}
	}
	respMutex.Unlock()
}

func (self *Miner) ConsensusReply(msg *MsgConsensusResp) {	// w http.ResponseWriter, r *http.Request) {
	respMutex.Lock()
	r,ok := consensResp[msg.Nonce]
	respMutex.Unlock()
	if !ok {
		return
	}

	k := self.Committee.Addresses[r.Q]
	if !VerifyMsg(*msg, k.PubKey()) {
		return
	}

	if strings.Compare(string(msg.Sign[:]), "reject") == 0 {
		return
	}

	if strings.Compare(string(msg.Sign[:]), "retry") == 0 {
		time.Sleep(1 * time.Second)
		r.Client.QueueMessage(r.Msg, nil)
		return
	}

	self.miningstatus = 55

	Mutex.Lock()
//	r.Sync.nbk.Sigs[r.Sync.nbk.Nsign] = &msg.Sign
//	r.Sync.nbk.Nsign++
	Mutex.Unlock()
/*
	if r.Sync.nbk.Nsign > uint16(r.Sync.Cfg.CommitteeSize/2) && r.BlkNum == r.Sync.Cfg.Blocks {
		r.Sync.releasenb(r.BlkNum)
		self.miningstatus = 58
		return
	}
*/

	self.miningstatus = 59
	respMutex.Lock()
	delete(consensResp, nonce)
	for i,r := range candidacyResp {
		if r.BlkNum < int64(msg.Height - 10) {
			delete(consensResp, i)
		}
	}
	respMutex.Unlock()
}

func (self *Miner) Release(p *peer.Peer, msg *MsgRelease) {	// w http.ResponseWriter, r *http.Request) {
	if !VerifyMsg(*msg, self.Committee.PubKey(&msg.F).PubKey()) {
		return
	}
	blk := int64(msg.Height)
	if s := self.GetSyncer(blk); s != nil {
		s.Release(p, msg)
	}
}
func (self *Miner) Cancel(p *peer.Peer, msg *MsgCancel) { // w http.ResponseWriter, r *http.Request) {
	if !VerifyMsg(*msg, self.Committee.PubKey(&msg.From).PubKey()) {
		return
	}
	blk := int64(msg.Height)
	if s := self.GetSyncer(blk); s != nil {
		s.Cancel(p, msg)
	}
}
func (self *Miner) Consensus(p *peer.Peer, msg *MsgConsensus) { // w http.ResponseWriter, r *http.Request) {
	if !VerifyMsg(*msg, self.Committee.PubKey(&msg.F).PubKey()) {
		return
	}
	blk := int64(msg.Height)
	if s := self.GetSyncer(blk); s != nil {
		s.Consensus(p, msg)
	}
}

var pendingBlks = make([]int32, 0, 10)
var npendings = int32(0)
var overflown = false

func (self *Miner) Newblock(blk int32) {
	// This block has been validated and added to the chain
	self.DoNewblock(blk, true)
	for npendings > 0 {
		if !self.DoNewblock(pendingBlks[0], false) {
			return
		}
		Mutex.Lock()
		if npendings > 0 {
			for i := int32(1); i < npendings; i++ {
				pendingBlks[i-1] = pendingBlks[i]
			}
			npendings--
			if npendings == 0 && overflown {
				pendingBlks = make([]int32, 0, 10)
				overflown = false
			}
		}
		Mutex.Unlock()
	}
}

func (self *Miner) DoNewblock(blk int32, add bool) bool {
	Mutex.Lock()

	if blk <= int32(self.Cfg.LastBlockNum) {
		// block height is less than the last block we know in chain
		Mutex.Unlock()
		return true
	}
	if blk > int32(self.Cfg.Blocks) {
		if add && (npendings == 0 || pendingBlks[npendings-1] != blk) {
			if npendings >= 10 {
				pendingBlks = append(pendingBlks, blk)
				overflown = true
			} else {
				pendingBlks[npendings] = blk
			}
			npendings++
		}
		Mutex.Unlock()
		return false
	}

	self.Cfg.Blocks++
	self.Cfg.LastBlockNum++

	lastBlk := self.Cfg.LastBlockNum

	self.syncMutex.Lock()
	if _, ok := self.sync[int64(blk - 1)]; ok {
		self.sync[int64(blk - 1)].Status = 0
		self.sync[int64(blk - 1)].finish<-true
		self.sync[int64(blk - 1)].Finished<-nil		// tell (m *CPUMiner) solveBlock to quit w/o a submitting new block
	}
	self.syncMutex.Unlock()

	// add first node to senator if qualified

	self.Committee.Rotate()
	Mutex.Unlock()

	if len(self.sync) > 0 {
		self.BlkDone <- (lastBlk - 1)
	}

	return true
}

func (self *Miner) ValidZeroBlock(msg *wire.MsgBlock) bool {
	return false
}

func (self *Miner) Debug(w http.ResponseWriter, r *http.Request) {
}
