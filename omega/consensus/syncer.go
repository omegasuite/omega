package consensus

import (
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/math"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

type Syncer struct {
	Cfg		 Config

	global   * Miner

	runnable bool
	committee Committee

	agreed   int
	httpCnt  int
	sigGiven int
	mode     int

	consents map[int32]int
	forest   map[int32]chainhash.Hash		// blocks mined by others
	validated map[int32]bool				// are those blocks validated?
	waitingTx map[int32][]*wire.InvVect

	nbk        BlockHeaderX
	txs 	  *[]*wire.MsgTx
	knowledges *Knowledgebase

	consusNode int

	Status int

	mutex *sync.Mutex

	miningstatus int
	Root chainhash.Hash

	waitState [3][3]bool

	pendings map[int]chan bool
	pends int
	Finished chan *BlockHeaderX

	validateBlock chan int32
	Validatercvblk chan struct { from int32
				blk MsgTmpMerkleBlock }
	finish chan bool
}

func (self *Syncer) SetCommittee(c *Miner) {
	self.Cfg = c.Cfg
	self.committee = c.Committee
	self.knowledges.SetCommittee(&self.committee)
	self.mode = 0
	self.runnable = true
}

func CreateSyncer(c *Miner, me int64) *Syncer {
	p := Syncer{}
	p.runnable = (c != nil)
	p.Cfg = c.Cfg
	p.mode = 0
	p.global = c
	p.pendings = make(map[int]chan bool, 0)
	if p.runnable {
		fmt.Printf("syner.Create: p.runnable=true\n")
		p.committee = c.Committee
	} else {
		p.pends = 0
		p.Cfg.Blocks = me
		p.Cfg.LastBlockNum = me - 1
		fmt.Printf("%d: syner.Create: p.runnable=false\n", me)
	}
	p.agreed = -1
	p.httpCnt = 0
	p.sigGiven = 0
	p.consents = make(map[int32]int, c.Cfg.CommitteeSize)
	p.forest = make(map[int32]chainhash.Hash, c.Cfg.CommitteeSize)
	p.validated = make(map[int32]bool, c.Cfg.CommitteeSize)

	if p.runnable {
		p.knowledges = CreateKnowledge(&p.Cfg, &p.committee)
	} else {
		p.knowledges = CreateKnowledge(&p.Cfg, nil)
	}
	p.consusNode = -1
	p.miningstatus = 0
	p.mutex = &sync.Mutex{}
	p.Status = 1
	p.Root = chainhash.Hash{}

	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			p.waitState[i][j] = false
		}
	}

	go p.validator()

	return &p
}

func (self * Syncer) validator() {
out:
	for {
		select {
			case originator := <-self.validateBlock:
				// pull a new temp block, when we receive a message including an unvalidated temp block first time
				ok := false
				for i,h := range self.forest {
					if h == self.forest[originator] && self.validated[i] {
						ok = true
					}
				}
				if ok || self.forest[originator] == self.Root {
					continue
				}
				d := wire.NewMsgGetData()
				h := self.forest[originator]
				iv := wire.NewInvVect(common.InvTypeTempBlock, &h)
				d.AddInvVect(iv)
				self.committee.Pool[originator].QueueMessage(d, nil)

			case blk := <-self.Validatercvblk:
				if blk.blk.Blk.Header.MerkleRoot != self.forest[blk.from] {
					continue
				}
				txh := make(map[chainhash.Hash]bool, len(*self.txs))
				for _,tx := range *self.txs {
					txh[tx.TxHash()] = true
				}
				d := wire.NewMsgGetData()
				dd := wire.NewMsgGetData()
				n := 0
				for _,tx := range blk.blk.Blk.Hashes {
					if txh[*tx] {
						continue
					}
					if (n % (wire.MaxInvPerMsg + 1)) == wire.MaxInvPerMsg {
						self.committee.Pool[blk.from].QueueMessage(d, nil)
						d = wire.NewMsgGetData()
					}
					iv := wire.NewInvVect(common.InvTypeTx, tx)
					d.AddInvVect(iv)
					dd.AddInvVect(iv)
					n++
				}
				if n > 0 {
					self.waitingTx[blk.from] = dd.InvList
					self.validated[blk.from] = false
					self.committee.Pool[blk.from].QueueMessage(d, nil)
				} else {
					self.validated[blk.from] = true
				}

			case _ = <-self.finish:
				break out
		}
	}
}

func (self * Syncer) TxRcvd(txns []*mempool.TxDesc) {
	n := make(map[int32]int, len(self.waitingTx))
	for _,tn := range txns {
		h := tn.Tx.Hash()
		for i, sync := range self.waitingTx {
			if self.validated[i] {
				continue
			}
			if _,ok := n[i]; !ok {
				n[i] = len(sync)
			}
			for j, t := range sync {
				if *h == t.Hash {
					self.waitingTx[i][j] = nil
					n[i]--
				}
			}
			if n[i] == 0 {
				self.waitingTx[i] = make([]*wire.InvVect, 0)
				self.validated[i] = true
			}
		}
	}
	for i, sync := range self.waitingTx {
		 if n[i] != 0 && n[i] < len(sync) {
			tmp := make([]*wire.InvVect, n[i])
			k := 0
			for _, t := range sync {
				if t != nil {
					tmp[k] = t
					k++
				}
			}
			self.waitingTx[i] = tmp
		}
	}
}

func (self *Syncer) Init(r *chainhash.Hash) {
	self.Root = *r
}

func (self *Syncer) Free() {
}
func (self *Syncer) Reset() {
	self.Status = 1
	if self.runnable {
		self.mutex.Lock()
		for _,p := range self.pendings {
			p <- true
		}
		self.pendings = make(map[int]chan bool, 0)
		self.mutex.Unlock()
	}
}

func (self *Syncer) DoMining(head * BlockHeaderX, txs *[]*wire.MsgTx) {
	self.nbk = *head
	self.txs = txs

	if self.Status == 0 {
		return
	}

	mp := self.committee.P(self.Cfg.Myself)

	self.knowledges.Knowledge[mp][mp] |= 1 << uint(mp)
	self.forest[int32(mp)] = self.nbk.MerkleRoot
	blkNum := self.Cfg.Blocks
	for i, nd := range self.committee.Addresses {
		if self.committee.Pool[i] == nil {
			continue
		}
		c := nd.AddressPubKeyHash().Hash160()
		if *c == self.Cfg.Myself {
			continue
		}
		q := int(self.committee.P(*c))
		var k [1]int
		k[0] = mp

		knowledge := NewMsgKnowledge()
		knowledge.Height = int32(blkNum)
		knowledge.Finder = self.Cfg.Myself
		knowledge.From = self.Cfg.Myself
		knowledge.K = k[:]
		knowledge.M = head.MerkleRoot
		sig, _ := self.Cfg.PrivKey.Sign(knowledge.DoubleHashB())
		knowledge.Signatures[mp] = sig.Serialize()

		skf := func () {
			done := make(chan struct{})
			self.committee.Pool[i].QueueMessage(knowledge, done)
			_ = <- done
			self.knowledges.Knowledge[mp][mp] |= 1 << uint(q)
			self.knowledges.Knowledge[mp][q] |= 1 << uint(mp)
			self.miningstatus = 23
			self.candidacy(blkNum)
		}
		go skf()
	}
}

func (self *Syncer) releasenb(blkNum int64) {
	if self.Status == 0 {
		return
	}

	self.miningstatus = 61
	Mutex.Lock()
	self.miningstatus = 66
	if blkNum != self.Cfg.Blocks || blkNum != self.Cfg.LastBlockNum || blkNum != self.global.Cfg.LastBlockNum {
		Mutex.Unlock()
		self.miningstatus = 67
		return
	}

	self.Status = 0
	self.miningstatus = 68
	self.global.Cfg.Blocks++
	self.global.Cfg.LastBlockNum++
	self.Cfg.Blocks++
	self.Cfg.LastBlockNum++

	self.miningstatus = 62

	self.knowledges.InitKnowledge()

	self.consusNode = self.agreed

	self.nbk.Timestamp = time.Now()
	self.global.Cfg.LastHash = self.nbk.BlockHash()
	h := btcutil.Hash160(self.global.Cfg.LastHash.CloneBytes())
	b := math.MustParseBig256(string(h))
	b = b.Mul(b, big.NewInt(2))		// we use 2X value in searching!
	file,_ := os.Open(self.Cfg.DataDir + "/miners.dat")
	seld := bTreeSearch(b, nil, file)
	copy(self.nbk.Newnode[:], seld[:])

	self.miningstatus = 63
	self.global.Committee.Rotate()
	Mutex.Unlock()

	self.consusNode = -1
	self.miningstatus = 64
	self.global.BlkDone <- blkNum
	self.finish <- true
	self.Finished <- &self.nbk
}

func (self * Miner) AcceptBlk(nbk *wire.BlockHeader, m * string) {
	self.Committee.Rotate()

	Mutex.Unlock()
}

var nonce = int(1)
type candidateResp struct {
	Sync * Syncer
	BlkNum int64
	Q int32
	Msg *MsgCandidate
	Client * peer.Peer
}
var candidacyResp = make(map[int]candidateResp)
var respMutex = sync.Mutex{}

func (self *Syncer) candidacy(blkNum int64) {
	if self.Status == 0 {
		return
	}

	self.mutex.Lock()
	if self.agreed != -1 || blkNum != self.Cfg.Blocks || !self.knowledges.Qualified() {
		self.mutex.Unlock()
		return
	}

	mp := self.committee.P(self.Cfg.Myself)
	self.agreed = mp
	self.mutex.Unlock()

	self.consents[int32(mp)] = 1

	msg := NewMsgCandidate(int32(self.Cfg.LastBlockNum), self.Cfg.Myself, self.Root, nonce)
	nonce++

	sig, _ := self.Cfg.PrivKey.Sign(msg.DoubleHashB())
	msg.Signature = sig.Serialize()

	for q, _ := range self.committee.Addresses {
		if q - self.committee.Start == int32(mp) {
			continue
		}

		go self.sendCandidate(self.committee.Pool[q], msg, blkNum, mp, q)
	}
}

func (self *Syncer) sendCandidate(client * peer.Peer, msg *MsgCandidate, blkNum int64, mp int, q int32) {
	if self.Status == 0 {
		return
	}

	self.miningstatus = 35
	self.httpCnt++

	self.waitState[1][q] = true

	if blkNum != self.Cfg.Blocks {
		return
	}

	respMutex.Lock()
	candidacyResp[msg.Nonce] = candidateResp{Sync:self, BlkNum:blkNum, Q:q, Msg:msg, Client:client}
	respMutex.Unlock()

	client.QueueMessage(msg, nil)
}

func (self *Syncer) ckconsensus(blkNum int64) {
	if self.Status == 0 {
		return
	}

	self.miningstatus = 41
	self.mutex.Lock()
	if blkNum != self.Cfg.Blocks || self.nbk.Nsign != 0 {
		self.mutex.Unlock()
		return
	}
	self.miningstatus = 42
	mp := self.committee.P(self.Cfg.Myself)
	self.mutex.Unlock()

	self.miningstatus = 43

	s := 0
	for i := 0; i < int(self.Cfg.CommitteeSize); i++ {
		s += self.consents[int32(i)]
	}
	Mutex.Lock()
	//	port, _ := strconv.Atoi(cfg.GetSelf()) // uid = port
	if s > int(self.Cfg.CommitteeSize/2) && self.agreed == mp {	//-1 {
		h := self.nbk.BlockHash()
		sig, _ := self.Cfg.PrivKey.Sign(h.CloneBytes())
		self.nbk.Sigs = make([]*[65]byte, self.Cfg.CommitteeSize)
		i := self.committee.P(self.Cfg.Myself)
		self.nbk.Sigs[i] = &[65]byte{}
		copy(self.nbk.Sigs[i][:], sig.Serialize())
		self.nbk.Signers =  make([]*btcec.PublicKey, self.Cfg.CommitteeSize)
		k := self.committee.Addresses[int32(i)]
		self.nbk.Signers[i] = k.PubKey()
		self.nbk.Nsign = 1

		Mutex.Unlock()

		self.miningstatus = 44
		//		fmt.Printf("%s collecting signatures\n", cfg.GetSelf())
		for q, _ := range self.committee.Addresses {
			if q - self.committee.Start == int32(self.agreed) {
				continue
			}
			msg := NewMsgConsensus()
			msg.Height = int32(self.Cfg.Blocks)
			msg.F = self.Cfg.Myself
			msg.M = self.nbk.BlockHash()
			sig, _ = self.Cfg.PrivKey.Sign(msg.DoubleHashB())
			copy(msg.Signature[:], sig.Serialize())
			go self.sendConsus(self.committee.Pool[q], msg, blkNum, q)
		}
	} else {
		Mutex.Unlock()
	}
}

type consensusResp struct {
	Sync * Syncer
	BlkNum int64
	Q int32
	Msg *MsgConsensus
	Client * peer.Peer
}
var consensResp = make(map[int]consensusResp)

func (self *Syncer) sendConsus(client * peer.Peer, msg * MsgConsensus, blkNum int64, q int32) {
	if self.Status == 0 {
		return
	}

	self.miningstatus = 51

	self.waitState[2][q] = true

	if blkNum != self.Cfg.Blocks {
		return
	}

	respMutex.Lock()
	consensResp[nonce] = consensusResp{self, blkNum, q, msg, client}
	respMutex.Unlock()

	nonce++

	client.QueueMessage(msg, nil)
}

func (self *Syncer) PendingCheck() {
	if !self.runnable {
		t := make(chan bool)
		self.mutex.Lock()
		self.pends++
		self.pendings[self.pends] = t
		self.mutex.Unlock()
		_ = <-t
	}
}

func (self *Syncer) KnowledgeFunc(p *peer.Peer, msg *MsgKnowledge) {
	// received knowledge passed to us
	if self.Status == 0 {
		//		w.Write([]byte("Ignore"))
		return
	}
	self.PendingCheck()

	if self.agreed > 0 {
		//		w.Write([]byte("Ignore"))
		return
	}

	f := int32(self.committee.P(msg.From))
	if _,ok := self.forest[f]; !ok {
		self.forest[f] = msg.M
		self.validateBlock <- f
	}

	blk := self.knowledges.ProcKnowledge(self, msg)
	if blk >= 0 {
		self.candidacy(blk)
	}
}

func (self *Syncer) Candidate(p *peer.Peer, msg *MsgCandidate) {
	// received a request for confirmation of candidacy
	d := MsgCandidateResp{Height: msg.Height, Nonce: msg.Nonce}

	blk := msg.Height
	from := msg.F
	fmp := self.committee.P(from)
	me := self.committee.P(self.Cfg.Myself)

	defer func (d MsgCandidateResp) {
		sig, _ := self.Cfg.PrivKey.Sign(d.DoubleHashB())
		d.Signature = sig.Serialize()
		p.QueueMessage(d, nil)
	} (d)

	d.Reply = "retry"

	if self.Status == 0 {
		d.Reply = "reject"
		return
	}
	self.PendingCheck()

	if self.sigGiven != 0 || !self.committee.In(self.Cfg.Myself) || !self.committee.In(from) ||
			blk != int32(self.Cfg.Blocks) || (self.knowledges.Qualified() && me > fmp) {
		d.Reply = "reject"
		return
	}

	if _,ok := self.forest[int32(fmp)]; !ok {
		self.forest[int32(fmp)] = msg.M
		self.validateBlock <- int32(fmp)
	}

	if !self.validated[int32(fmp)] {
		return
	}

	merkle := msg.M

	if self.agreed == fmp {
		d.Reply = "consent"
		return
	} else if self.agreed != -1 {
		release := MsgRelease{}
		release.Height = blk
		release.K = me

		self.mutex.Lock()
		if fmp < self.agreed || self.agreed != me {
			self.mutex.Unlock()
			d.Reply = "reject"
			return
		}
		self.agreed = fmp
		h := merkle	// chainhash.NewHashFromStr(merkle)
		self.forest[int32(fmp)] = h
		self.mutex.Unlock()

		for i,p := range self.committee.Pool {
			self.consents[i] = 0
			if i == int32(me) {
				continue
			}
			p.QueueMessage(&release, nil)
		}

		d.Reply = "consent"
		return
	}

	//	qualified := 0
	//	for i := 0; i < int(cfg.CommitteeSize); i++ {
	s := 0
	for k := uint(0); k < 64; k += 4 {
		s += Mapping16[((self.knowledges.Knowledge[fmp][me] >> k) & 0xF)]
	}

	if s > int(self.Cfg.CommitteeSize/2) {
		self.mutex.Lock()
		if self.agreed == -1 {
			self.agreed = fmp
			self.forest[int32(fmp)] = merkle
			d.Reply = "consent"
		}
		self.mutex.Unlock()
	}
}
func (self *Syncer) Release(p *peer.Peer, msg * MsgRelease) {
	if self.Status == 0 {
		return
	}
	self.PendingCheck()

	blk := msg.Height
	if blk != int32(self.Cfg.Blocks) {
		return
	}

	k := msg.K
	if self.agreed == k && self.agreed != self.committee.P(self.Cfg.Myself) {
		self.agreed = -1
	}
	//	fmt.Fprintln(w, "done")
}
func (self *Syncer) Cancel(p *peer.Peer, msg * MsgCancel) {
	if self.Status == 0 {
		return
	}
	self.PendingCheck()

	blk := msg.Height
	if blk != int32(self.Cfg.Blocks) {
		return
	}
	//	fmt.Fprintln(w, "Hello, you hit foo!")
}
func (self *Syncer) Consensus(p *peer.Peer, msg * MsgConsensus) {
	result := 0
	h := msg.M

	defer func (result int) {
		reply := MsgConsensusResp{}
		reply.Height = msg.Height
		reply.F = self.Cfg.Myself
		reply.Nonce = msg.Nonce

		if result == -1 {
			copy(reply.Sign[:], []byte("reject"))
		} else if result == -2 {
			copy(reply.Sign[:], []byte("retry"))
		} else {
			sig, _ := self.Cfg.PrivKey.Sign(h.CloneBytes())
			copy(reply.Sign[:], sig.Serialize())
		}

		sig, _ := self.Cfg.PrivKey.Sign(reply.DoubleHashB())
		copy(reply.Signature[:], sig.Serialize())

		p.QueueMessage(&reply, nil)
	} (result)

	if self.Status == 0 {
		result = -1
		return
	}

	self.PendingCheck()

	//	url := "http://" + j + "/consensus?blk=" + fmt.Sprintf("%d", cfg.LastBlockNum) + "&F=" + cfg.GetSelf() + "&M=" + nbk.Merkle
	blk := msg.Height
	if blk != int32(self.Cfg.Blocks) {
		result = -1
		return
	}
	from := msg.F
	if !self.committee.In(from) {
		result = -1
		return
	}

	fmp := self.committee.P(from)

	f := int32(fmp)
	if _,ok := self.forest[f]; !ok {
		self.forest[f] = h
		self.validateBlock <- f
	}

	if !self.validated[f] {
		result = -2
		return
	}

	if self.sigGiven != 0 && self.sigGiven != fmp{
		result = -1
		return
	}

	if self.agreed != -1 && self.agreed != fmp {
		result = -1
		return
	}

	if h != self.forest[int32(fmp)] {
		result = -1
		fmt.Printf("%s: Fraud warning inconsist merkle while giving signature to %d. %s vs. %s\n", self.Cfg.Myself, fmp, self.forest[int32(fmp)], h)
	}
	self.sigGiven = fmp
}

func (self *Syncer) Debug(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "----- Syncer.knowledges -------\n")
	self.knowledges.Debug(w, r)

	fmt.Fprintf(w, "----- Syncer.sendQ -------\n")

	fmt.Fprintf(w, "----------\n mining status = %d\n", self.miningstatus)
	fmt.Fprintf(w, "agreed block = %d\n", self.agreed)
	fmt.Fprintf(w, "outstanding http count = %d\n", self.httpCnt)
	a, _ := json.Marshal(self.Cfg.Blocks)
	fmt.Fprintf(w, "lastBlk = %s\n", a)
	a, _ = json.Marshal(self.nbk)
	fmt.Fprintf(w, "nbk = %s\n", a)
	a, _ = json.Marshal(self.consents)
	fmt.Fprintf(w, "consents = %s\n", a)
	a, _ = json.Marshal(self.waitState)
	fmt.Fprintf(w, "waitState = %s\n", a)
	fmt.Fprintf(w, "sigGiven for block = %d\n", self.sigGiven)
	fmt.Fprintf(w, "number of signatures = %d, signatures = %s\n", self.nbk.Nsign, self.nbk.Sigs)
	fmt.Fprintf(w, "Merkle root = %s, tree = nil\n", self.Root)
	fmt.Fprintf(w, "----- Syncer completed -------\n\n")
}
