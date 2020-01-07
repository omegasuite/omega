package consensus

import (
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mining"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/omega/token"
	"net/http"
	"reflect"
)

type tree struct {
	creator  [20]byte
	fees uint64
	hash chainhash.Hash
	header * wire.BlockHeader
	block * btcutil.Block
}

type Syncer struct {
	// one syncer handles one height level consensus
	// if current height is below the best chain, syncer quits
	// if current height is more than the best chain, syncer wait, but accept all incoming messages
	// syncer quits when it finishes one height level and the block is connected to the main chain

	Runnable bool

	Committee int32
	Base int32

	Members map[[20]byte]int32
	Names map[int32][20]byte

	Me [20]byte
	Myself int32

	Malice map[[20]byte]struct {}

	// a node may annouce to be a candidate if he believes he is the best choice
	// if he believes another one is the best, send his knowledge about the best to the best

	// a node received the candidacy announcement returns an agree message if he believes
	// the node is better than himself and is known to more than 1/ nodes (qualified)
	// a node rejects candidacy announcement should send his knowledge of the best in reply

	// a node collected more than 1/2 agrees may annouce the fact by broadcasting the agreements it
	// collected.

	agrees   map[int32]struct{}		// those who I have agree me to be a candidate
	agreed   int32			// the one who I have agreed. can not back out until released by
	sigGiven int32			// who I have given my signature
	mode     int32

	consents map[[20]byte]int32
	forest   map[[20]byte]*tree		// blocks mined
	signed   map[[20]byte]struct{}

	knowledges *Knowledgebase

	newtree chan tree
	quit chan bool

	Height int32

	Chain * blockchain.BlockChain

	pending map[string][]Message
	pulling map[chainhash.Hash]struct{}
	Initialized bool

	messages chan Message
}

func (self *Syncer) run() {
out:
	for {
		select {
		case tree := <- self.newtree:
			if !self.validateMsg(tree.creator, nil, nil) {
				continue
			}

			if _, ok := self.forest[tree.creator]; !ok {
				// each creator may submit only one tree
				self.forest[tree.creator] = &tree
				c := self.Members[tree.creator]
				self.knowledges.ProcessTree(c)
				if pend, ok := self.pending[wire.CmdBlock]; ok {	// is that ok?
					delete(self.pending, wire.CmdBlock)
					for _,m := range pend {
						self.messages <- m
					}
				}
			} else if tree.hash != self.forest[tree.creator].hash {
				self.Malice[tree.creator] = struct {}{}
				delete(self.forest, tree.creator)
				c := self.Members[tree.creator]
				self.knowledges.Malice(c)
			}

		case m := <- self.messages:
			log.Infof("processing %s message", reflect.TypeOf(m).String())
			switch m.(type) {
			case *MsgKnowledge:		// passing knowledge
				k := m.(*MsgKnowledge)
				if !self.validateMsg(k.Finder, &k.M, m) {
					continue
				}
				if self.knowledges.ProcKnowledge(k) {
					self.candidacy()
				}

			case *MsgCandidate:		// announce candidacy
				k := m.(*MsgCandidate)
				if !self.validateMsg(k.F, &k.M, m) {
					continue
				}
				self.Candidate(k)

			case *MsgCandidateResp:		// response to candidacy announcement
				k := m.(*MsgCandidateResp)
				if !self.validateMsg(k.From, &k.M, m) {
					continue
				}
				self.candidateResp(k)

			case *MsgRelease:			// grant a release from duty
				k := m.(*MsgRelease)
				if !self.validateMsg(k.From, nil, m) {
					continue
				}
				self.Release(k)

			case *MsgConsensus:			// announce consensus reached
				k := m.(*MsgConsensus)
				if !self.validateMsg(k.From, nil, m) {
					continue
				}
				self.Consensus(k)

			case *MsgSignature:		// give signature
				self.Signature(m.(*MsgSignature))
			}

		case <-self.quit:
			break out
		}
	}

	for {
		select {
		case <-self.newtree:
		case m := <- self.messages:
			switch m.(type) {
			case *MsgSignature:
				log.Info("handling MsgSignature on quit")
				self.Signature(m.(*MsgSignature))
			}

		default:
			if self.Runnable && self.forest[self.Me] != nil && self.forest[self.Me].block != nil &&
				len(self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSize / 2 + 1 {
				log.Info("passing NewConsusBlock on quit")
				miner.server.NewConsusBlock(self.forest[self.Me].block)
			}
			self.Runnable = false
			log.Info("sync quit")
			return
		}
	}
}

func (self *Syncer) releasenb() {
	self.Runnable = false
	self.Quit()

	miner.server.NewConsusBlock(self.forest[self.Me].block)

	cleaner(self.Height)
}

func (self *Syncer) Signature(msg * MsgSignature) {
	// verify signature
	hash := mining.MakeMinerSigHash(self.Height, self.forest[self.Me].hash)

	k,err := btcec.ParsePubKey(msg.Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
	if err != nil {
		return
	}

	s, err := btcec.ParseDERSignature(msg.Signature[btcec.PubKeyBytesLenCompressed:], btcec.S256())
	if err != nil {
		return
	}

	if !s.Verify(hash, k) {
		return
	}

	self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts[1 + self.Members[msg.From]] = msg.Signature[:]
	self.signed[msg.From] = struct{}{}

	if len(self.signed) > wire.CommitteeSize / 2 + 1 {
		self.quit <- true
	}
}

func (self *Syncer) Consensus(msg * MsgConsensus) {
	if self.agreed == self.Members[msg.From] || self.agreed == -1 {
		// verify signature
		hash := mining.MakeMinerSigHash(self.Height, self.forest[msg.From].hash)

		k,err := btcec.ParsePubKey(msg.Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		if err != nil {
			return
		}

		s, err := btcec.ParseDERSignature(msg.Signature[btcec.PubKeyBytesLenCompressed:], btcec.S256())
		if err != nil {
			return
		}

		if !s.Verify(hash, k) {
			return
		}

		if privKey := miner.server.GetPrivKey(self.Me); privKey != nil {
			sig, _ := privKey.Sign(hash)
			msg := MsgSignature {
				Height:    self.Height,
				From:      self.Me,
			}

			s := sig.Serialize()
			copy(msg.Signature[:], privKey.PubKey().SerializeCompressed())
			copy(msg.Signature[btcec.PubKeyBytesLenCompressed:], s)

			// add signature to block
			self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts[1 + self.Myself] = msg.Signature[:]
			self.signed[self.Me] = struct{}{}

			miner.server.CommitteeCast(self.Myself, &msg)
		}
	}
}

func (self *Syncer) Release(msg * MsgRelease) {
	if self.agreed == self.Members[msg.From] {
		self.agreed = msg.Better
		self.knowledges.ProcFlatKnowledge(msg.Better, msg.K)

		d := MsgCandidateResp{Height: msg.Height, K: self.makeAbout(msg.Better).K, From: self.Me, Reply:"consent"}
		miner.server.CommitteeMsg(msg.Better, &d)
	}
}

func (self *Syncer) ckconsensus() {
	if len(self.agrees) <= wire.CommitteeSize / 2 {
		return
	}

	hash := mining.MakeMinerSigHash(self.Height, self.forest[self.Me].hash)

	if privKey := miner.server.GetPrivKey(self.Me); privKey != nil {
		sig, _ := privKey.Sign(hash)
		msg := MsgConsensus{
			Height:    self.Height,
			From:      self.Me,
		}

		copy(msg.Signature[:], privKey.PubKey().SerializeCompressed())
		copy(msg.Signature[btcec.PubKeyBytesLenCompressed:], sig.Serialize())

		miner.server.CommitteeCast(self.Myself, &msg)
	}
}

func (self *Syncer) makeRelease(better int32) *MsgRelease {
	return &MsgRelease{
		Better: better,
		K:      self.makeAbout(better).K,
		Height: self.Height,
		From:   self.Me,
	}
}

func (self *Syncer) candidateResp(msg *MsgCandidateResp) {
	if msg.Reply == "consent" {
		if self.agreed != self.Myself {
			// release the node from obligation and notify him about new agreed
			miner.server.CommitteeMsg(self.Members[msg.From], self.makeRelease(self.agreed))
		} else {
			self.knowledges.ProcFlatKnowledge(msg.better, msg.K)
			self.agrees[self.Members[msg.From]] = struct{}{}
			self.ckconsensus()
		}
	} else if msg.Reply == "reject" && len(msg.K) != 0 {
		if _,ok := self.forest[self.Names[msg.better]]; !ok {
			if self.pull(msg.M, msg.better) {
				self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
			}
			return
		}

		if self.knowledges.ProcFlatKnowledge(msg.better, msg.K) {
			// gained more knowledge, check if we are better than msg.better, if not
			// release nodes in agrees
			if self.knowledges.Qualified(msg.better) &&
				self.forest[self.Names[msg.better]].fees > self.forest[self.Me].fees ||
				(self.forest[self.Names[msg.better]].fees == self.forest[self.Me].fees && msg.better > self.Myself) {
				for r, _ := range self.agrees {
					miner.server.CommitteeMsg(r, self.makeRelease(msg.better))
				}

				self.agreed = msg.better
				d := MsgCandidateResp{Height: msg.Height, K: self.makeAbout(msg.better).K, From: self.Me, Reply:"consent"}
				miner.server.CommitteeMsg(msg.better, &d)

				self.agrees = make(map[int32]struct{})
				return
			}
		}
	}
}

func (self *Syncer) candidacy() {
	if self.agreed != -1 || !self.knowledges.Qualified(self.Myself) {
		return
	}

	fees := self.forest[self.Me].fees
	better := -1
	for i := 0; i < wire.CommitteeSize; i++ {
		if t, ok := self.forest[self.Names[int32(i)]]; ok && (t.fees > fees || (t.fees == fees && int32(i) > self.Myself)) && self.knowledges.Qualified(int32(i)) {
			// there is a better candidate
			// someone else is the best, send him knowledge about him that he does not know
			better = i
		}
	}

	if better != -1 {
		t := self.forest[self.Names[int32(better)]]
		if t.block == nil {
			self.pull(t.hash, int32(better))
		} else {
			miner.server.CommitteeMsg(int32(better)+self.Base, self.makeAbout(int32(better)))
		}
		return
	}

	mp := self.Myself
	self.agreed = mp

	self.consents[self.Me] = 1

	msg := NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)

	miner.server.CommitteeCast(mp, msg)
}

func (self *Syncer) Candidate(msg *MsgCandidate) {
	// received a request for confirmation of candidacy
	d := MsgCandidateResp{Height: msg.Height, K: []int64{}, From: self.Me}

	from := msg.F
	fmp := self.Members[from]

	if _,ok := self.Members[from]; !self.Runnable || !ok {
		d.Reply = "reject"
		miner.server.CommitteeMsg(fmp, &d)
		return
	}

	if _,ok := self.forest[from]; !ok {
		if self.pull(msg.M, fmp) {
			self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
		}
		return
	}

	if self.sigGiven != -1 {
		d.Reply = "reject"
		for _,p := range self.knowledges.Knowledge[self.sigGiven] {
			d.K = append(d.K, p)
		}
		d.better = self.sigGiven
		miner.server.CommitteeMsg(fmp, &d)
		return
	}

	if self.agreed != -1 || self.agreed == fmp {
		d.Reply = "consent"
		self.agreed = fmp
		miner.server.CommitteeMsg(fmp, &d)
		return
	}

	// check whether fmp is better than agreed, if not reject it, if yes, give no response

	if self.forest[self.Names[self.agreed]].fees > self.forest[from].fees ||
		(self.forest[self.Names[self.agreed]].fees == self.forest[from].fees && self.agreed > fmp) {
		d.Reply = "reject"
		for _,p := range self.knowledges.Knowledge[self.agreed] {
			d.K = append(d.K, p)
		}
		d.better = self.agreed
		miner.server.CommitteeMsg(fmp, &d)
		return
	}
}

func CreateSyncer() *Syncer {
	p := Syncer{}

	p.quit = make(chan bool)
	p.pending = make(map[string][]Message, 0)
	p.newtree = make(chan tree, wire.CommitteeSize * 3)	// will hold trees before runnable
	p.messages = make(chan Message, wire.CommitteeSize * 3)
	p.pulling = make(map[chainhash.Hash]struct{})
	p.agrees = make(map[int32]struct{})
	p.signed = make(map[[20]byte]struct{})
	p.Members = make(map[[20]byte]int32)
	p.Names = make(map[int32][20]byte)
	p.Malice = make(map[[20]byte]struct {})

	p.mode = 0
	p.agreed = -1

	p.sigGiven = 0
	p.consents = make(map[[20]byte]int32, wire.CommitteeSize)
	p.forest = make(map[[20]byte]*tree, wire.CommitteeSize)

	p.Runnable = false
	p.Initialized = false

	return &p
}


func (self *Syncer) validateMsg(finder [20]byte, m * chainhash.Hash, msg Message) bool {
	if _, ok := self.Malice[finder]; ok {
		return false
	}
	c, ok := self.Members[finder]
	if !ok {
		return false
	}
	if _, ok := self.forest[finder]; m != nil && !ok {
		if _, ok := self.pending[wire.CmdBlock]; !ok {
			self.pending[wire.CmdBlock] = make([]Message, 0)
		}
		self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
		self.pull(*m, c)
		return false
	} else if m != nil && self.forest[finder].hash != *m {
//		self.Malice[finder] = struct {}{}
//		delete(self.forest, finder)
//		self.knowledges.Malice(c)
		return false
	}
	return true
}

func (p * Syncer) Initialize(chain * blockchain.BlockChain, height int32) {
	p.Initialized = true

	p.Chain = chain
	p.Height = height

	best := chain.BestSnapshot()
	p.Runnable = p.Height == best.Height + 1

	if p.Runnable {
		p.SetCommittee(int32(best.LastRotation))
	}
}

func (self *Syncer) SetCommittee(c int32) {
	self.Committee = c
	self.Base = c - wire.CommitteeSize + 1

	me := miner.server.MyPlaceInCommittee(c)
	self.knowledges = CreateKnowledge(self)

	in := false

	for i := c - wire.CommitteeSize + 1; i <= c; i++ {
		blk,_ := self.Chain.Miners.BlockByHeight(i)
		if blk == nil {
			continue
		}
		var adr [20]byte
		copy(adr[:], blk.MsgBlock().Miner)
		who := i - (c - wire.CommitteeSize + 1)
		self.Members[adr] = who
		self.Names[who] = adr

		if me == i {
			copy(self.Me[:], blk.MsgBlock().Miner)
			self.Myself = who
			in = true
		}
	}

	if !in {
		self.Quit()
		return
	}

	log.Info("Consensus running block at %d", self.Height)

	go self.run()
}

func (self *Syncer) UpdateChainHeight(h int32) {
	if h < self.Height {
		return
	}
	if h > self.Height {
		self.Quit()
		return
	}
	if !self.Runnable {
		best := self.Chain.BestSnapshot()

		if best.Height > self.Height {
			self.Quit()
			return
		}

		self.Runnable = self.Height == best.Height + 1

		if self.Runnable {
			self.SetCommittee(int32(best.LastRotation))
		}
	}
}

/*
func (self *Syncer) HeaderInit(block *MsgMerkleBlock) {
	var adr [20]byte
	copy(adr[:], block.From[:])

	if !self.Runnable {
		best := self.Chain.BestSnapshot()

		if best.Height > self.Height {
			self.Quit()
			return
		}

		self.Runnable = self.Height == best.Height + 1

		if self.Runnable {
			self.SetCommittee(int32(best.LastRotation))
		}
	}

	self.newtree <- tree {
		creator: adr,
		fees: block.Fees,
		hash: block.Header.BlockHash(),
		header: &block.Header,
		block: nil,
	}
}

 */

func (self *Syncer) BlockInit(block *btcutil.Block) {
	var adr [20]byte
	copy(adr[:], block.MsgBlock().Transactions[0].SignatureScripts[1])

	Runnable := false

	best := self.Chain.BestSnapshot()

	if !self.Runnable {
		if best.Height >= self.Height {
			self.Quit()
			return
		}

		Runnable = self.Height == best.Height + 1
	}

	// total fees are total coinbase outputs
	fees := int64(0)
	eq := int64(-1)
	for _, txo := range block.MsgBlock().Transactions[0].TxOut {
		if txo.TokenType == 0 {
			if eq < 0 {
				eq = txo.Value.(*token.NumToken).Val
			} else if eq != txo.Value.(*token.NumToken).Val {
				return
			}
			fees += eq
		}
	}

	if len(block.MsgBlock().Transactions[0].TxOut) <= wire.CommitteeSize / 2 {
		return
	}

	if !self.Runnable && Runnable {
		self.Runnable = Runnable
		self.SetCommittee(int32(best.LastRotation))
	}

	self.newtree <- tree {
		creator: adr,
		fees: uint64(fees),
		hash: * block.Hash(),
		header: &block.MsgBlock().Header,
		block: block,
	}
}

func (self *Syncer) makeAbout(better int32) *MsgKnowledge {
	k := []int64{-1024} // indicate we are sending a map
	for _, p := range self.knowledges.Knowledge[better] {
		k = append(k, p)
	}
	t := self.forest[self.Names[better]]
	return &MsgKnowledge {
		M:      t.hash,
		Height: self.Height,
		K:      k,
		Finder: t.creator,
		From:   self.Me,
		//	Signatures      map[int][]byte
	}
}

func (self *Syncer) pull(hash chainhash.Hash, from int32) bool {
	if _, ok := self.pulling[hash]; !ok {
		self.pulling[hash] = struct{}{}
		// pull block
		msg := wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeBlock, hash}}}
		miner.server.CommitteeMsg(from+self.Base, &msg)
		return true
	}
	return false
}

func (self *Syncer) Quit() {
	if self.Runnable {
		log.Info("sync quit")
		self.quit <- true
	}
}

func (self *Syncer) Debug(w http.ResponseWriter, r *http.Request) {
}
