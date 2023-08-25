/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package consensus

import (
	"bytes"
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcd/wire/common"
	"github.com/omegasuite/btcutil"
	"github.com/omegasuite/omega/token"
	"sync"
	"time"
)

type tree struct {
	creator [20]byte
	fees    uint64
	hash    chainhash.Hash
	header  *wire.BlockHeader
	block   *btcutil.Block
}

func (self *Syncer) block(t *tree) *btcutil.Block {
	if r, ok := self.blocks[t.hash]; ok {
		return r
	} else {
		return nil
	}
}

type Syncer struct {
	// one syncer handles one height level consensus
	// if current height is below the best chain, syncer quits
	// if current height is more than the best chain, syncer wait, but accept all incoming messages
	// syncer quits when it finishes one height level and the block is connected to the main chain

	Runnable bool

	Committee int32
	Base      int32

	Members map[[20]byte]int32
	Names   map[int32][20]byte
	ips     map[[20]byte]string

	Me     [20]byte
	Myself int32

	Malice map[[20]byte]struct{}

	// a node may annouce to be a candidate if he believes he is the best choice
	// if he believes another one is the best, send his knowledge about the best to the best

	// a node received the candidacy announcement returns an agree message if he believes
	// the node is better than himself and is known to more than 1/2 nodes (qualified)
	// a node rejects candidacy announcement should send his knowledge of the best in reply

	// a node collected more than 1/2 agrees consents may annouce the fact by broadcasting
	// the agreements it collected.

	asked    [wire.CommitteeSize]bool // those who have asked to be a candidate, and not released
	agrees   map[int32]struct{}       // those who I have agree to be a candidate
	blocks   map[chainhash.Hash]*btcutil.Block
	agreed   int32 // the one who I have agreed. can not back out until released by
	sigGiven int32 // who I have given my signature. can never change once given.

	//	consents map[[20]byte]int32		// those wh
	forest map[[20]byte]*tree                // blocks mined
	knows  map[[20]byte][]*wire.MsgKnowledge // the knowledges we received organized by finders (i.e. fact)
	signed map[[20]byte]struct{}

	forestLock sync.Mutex

	knowledges *Knowledgebase

	commands chan interface{}
	quit     chan struct{}

	Done bool

	Height int32

	//	pending map[string][]Message
	pulling  map[int32]int
	pulltime map[int32]int64

	// debug only
	knowRevd []int32
	candRevd []int32
	consRevd []int32

	// wait for end of task
	//	wg          sync.WaitGroup
	idles     int
	handeling string
	repeats   int
}

func (self *Syncer) CommitteeMsgMG(p [20]byte, m wire.Message) {
	if h, ok := self.Members[p]; ok {
		miner.server.CommitteeMsgMG(p, h+self.Base, m)
	} else {
		log.Infof("Msg not sent because %s is not a memnber", p)
	}
}

func (self *Syncer) CommitteeMsg(p [20]byte, m wire.Message) bool {
	h, ok := self.Members[p]
	return ok && miner.server.CommitteeMsg(p, h+self.Base, m)
}

func (self *Syncer) CommitteeCastMG(msg wire.Message) {
	for i, p := range self.Names {
		if i == self.Myself {
			continue
		}
		self.CommitteeMsgMG(p, msg)
	}
}

func (self *Syncer) findBlock(h *chainhash.Hash) *btcutil.Block {
	for _, f := range self.forest {
		if f.block != nil && f.hash.IsEqual(h) {
			return f.block
		}
	}
	return nil
}

func (self *Syncer) repeater() {
	log.Infof("\nRepeater: %d enter", self.Height)

	defer func() {
		log.Infof("Repeater: exit\n")
	}()

	miner.server.CommitteePolling()

	if !self.Runnable || self.Done {
		return
	}

	self.debugging()

	self.repeats++
	if (self.repeats % 3)  == 0 {
		// reset connections
		miner.server.ResetConnections()
		log.Infof("ResetConnections after repeating %s times", self.repeats)
/*
		if self.sigGiven == -1 {
			// clear data
			self.pulling = make(map[int32]int)
			self.pulltime = make(map[int32]int64)
			self.agrees = make(map[int32]struct{})
			self.signed = make(map[[20]byte]struct{})
			self.Malice = make(map[[20]byte]struct{})
			self.knows = make(map[[20]byte][]*wire.MsgKnowledge)
			self.agreed = -1

			self.handeling = ""

			for i, f := range self.forest {
				if i == self.Me {
					self.newtree <- *f
				} else {
					delete(self.forest, i)
				}
			}

			self.knowRevd = make([]int32, wire.CommitteeSize)
			self.candRevd = make([]int32, wire.CommitteeSize)
			self.consRevd = make([]int32, wire.CommitteeSize)
			for i := 0; i < wire.CommitteeSize; i++ {
				self.knowRevd[i], self.candRevd[i], self.consRevd[i] = -1, -1, -1
			}
			self.knowledges = CreateKnowledge(self)
		}
 */
	}

	// enough sigs to conclude?
	if self.agreed != -1 && len(self.signed) >= wire.CommitteeSigs && !self.Done {
		self.Done = true
		close(self.quit)
		return
	}
/*
	// if peer is disconnected, clear its knowledge falgs
	for m,i := range self.Members {
		if i != self.Myself && !miner.server.Connected(m) {
			if self.sigGiven != i && self.agreed == i {
				self.agreed = -1
			}
			for j := 0; j < wire.CommitteeSize; j++ {
				self.knowledges.Knowledge[i][j] = 0
				self.knowledges.Knowledge[j][i] = 0
				for k := 0; k < wire.CommitteeSize; k++ {
					self.knowledges.Knowledge[j][k] &= ^(0x1 << i)
				}
			}
		}
	}
 */

	for _,kp := range self.knows {
		repeated := make(map[int32]struct{})
		mp := self.Members[kp[0].From]
		for j := len(kp) - 1; j >= 0; j-- {
			p := kp[j]
			if p.From == self.Me {
				continue
			}
			if _, ok := repeated[self.Members[p.From]]; ok {
				continue
			}

			repeated[self.Members[p.From]] = struct{}{}

			// send it
			pp := *p
			//		pp.K = append(pp.K, self.Myself)
			pp.AddK(self.Myself, miner.server.GetPrivKey(self.Me))
			to := pp.From
			pp.From = self.Me

			log.Infof("Repeater: Sending knowledge info about %x to %x", pp.Finder, to)
			if self.CommitteeMsg(to, &pp) {
				q := self.Members[kp[j].From]
				qm := int64((1<<uint(q)) | (1<<uint(self.Myself)))
				if (self.knowledges.Knowledge[mp][self.Myself] & qm) != qm || (self.knowledges.Knowledge[mp][q] & qm) != qm {
					self.knowledges.Knowledge[mp][self.Myself] |= qm
					self.knowledges.Knowledge[mp][q] |= qm
				}
			}
		}
	}

	if tree,ok := self.forest[self.Me]; ok && len(self.commands) < (wire.CommitteeSize - 1) * 10 {
		k := wire.NewMsgKnowledge()
		k.From = self.Me
		k.Height = self.Height
		k.Finder = self.Me
		k.M = tree.hash
		k.AddK(self.Myself, miner.server.GetPrivKey(self.Me))

		self.commands <- k

		for i,p := range self.Names {
			if i == self.Myself {
				continue
			}
			log.Infof("Repeater: Sending my knowledge info to %x", p)
			self.CommitteeMsg(p, k)
		}
	}

	for _, tree := range self.forest {
		if tree.block == nil {
			if _,ok := self.Members[tree.creator]; ok {
				self.pull(tree.hash, self.Members[tree.creator])
			}
		}
	}

	if self.agreed == -1 {
		// check if we should agree with someone else
		best := self.best()

		if best >= 0 && best != self.Myself && self.asked[best] && self.knowledges.Qualified(best) && miner.server.Connected(self.Names[best]) {
			self.agreed = best
		} else {
			self.candidacy()
		}
	}

	if self.agreed == self.Myself && len(self.agrees) < wire.CommitteeSigs - 1 {
		for i,b := range self.asked {
			if !b || int32(i) == self.Myself || !self.better(int32(i), self.Myself) {
				continue
			}
			if self.better(int32(i), self.agreed) {
				self.agreed = int32(i)
			}
		}
		if self.agreed != self.Myself {
			r := self.makeRelease(self.agreed)
			for i,_ := range self.agrees {
				self.CommitteeMsgMG(self.Names[i], r)
			}
			self.agrees = make(map[int32]struct{})
		}
	}

	if self.agreed != self.Myself && self.agreed != -1 {
		// resend an agree message
		fmp := self.agreed
		from := self.Names[fmp]

		d := wire.MsgCandidateResp{Height: self.Height, K: []int64{}, From: self.Me, M: self.forest[from].hash}

		if self.sigGiven == -1 {
			d.Reply = "cnst"
			d.Better = fmp
			d.Sign(miner.server.GetPrivKey(self.Me))

			log.Infof("Repeater: Consent candicacy by %x", from)

			self.CommitteeMsgMG(from, &d)
		}
	}

	self.idles++

	if self.idles > 2 {
		self.idles = 0
		if self.sigGiven != -1 {
			// resend signatures
			privKey := miner.server.GetPrivKey(self.Me)
			if privKey == nil {
				return
			}

			log.Infof("Repeater: resend signature %d", self.sigGiven)

			from := self.Names[self.agreed]
			hash := blockchain.MakeMinerSigHash(self.Height, self.forest[from].hash)

			sig, _ := privKey.Sign(hash)
			s := sig.Serialize()

			sigmsg := wire.MsgSignature {
				For:	   from,
			}
			sigmsg.MsgConsensus = wire.MsgConsensus {
				Height:    self.Height,
				From:      self.Me,
				M:		   self.forest[from].hash,
				Signature: make([]byte, btcec.PubKeyBytesLenCompressed + len(s)),
			}

			copy(sigmsg.Signature[:], privKey.PubKey().SerializeCompressed())
			copy(sigmsg.Signature[btcec.PubKeyBytesLenCompressed:], s)

			self.CommitteeCastMG(&sigmsg)
		} else if self.ckconsensus() {
			return
		} else if self.agreed == self.Myself {
			log.Infof("Repeater: cast my candidacy %d", self.agreed)
			msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)
			msg.Sign(miner.server.GetPrivKey(self.Me))
			self.CommitteeCastMG(msg)
		} else if self.agreed != -1 {
			// resend agreement
			M := self.forest[self.Names[self.agreed]].hash
			d := wire.MsgCandidateResp{Height: self.Height, K: []int64{}, From: self.Me, M: M}

			d.Reply = "cnst"
			d.Better = self.agreed
			d.Sign(miner.server.GetPrivKey(self.Me))

			self.CommitteeMsgMG(self.Names[self.agreed], &d)
		} else if _,ok := self.forest[self.Me]; ok {
			// no agreement has reached, volunteer for it
			log.Infof("Repeater: volunteer for candidacy")
			msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)
			msg.Sign(miner.server.GetPrivKey(self.Me))
			self.CommitteeCastMG(msg)
		} else {
			for k, ok := range self.asked {
				if int32(k) == self.Myself || !ok {
					continue
				}
				n := self.Names[int32(k)]
				if self.forest[n] == nil {
					continue
				}
				if self.forest[n].block != nil {
					continue
				}
				self.pull(self.forest[n].hash, int32(k))
			}
		}
	}
}

func (self *Syncer) Release(msg * wire.MsgRelease) {
	self.asked[self.Members[msg.From]] = false

	if self.agreed == self.Members[msg.From] {
		//		self.knowledges.ProcFlatKnowledge(msg.Better, msg.K)
		self.agreed = -1

		self.candidacy()
		/*
			self.agreed = msg.Better
			d := wire.MsgCandidateResp{Height: msg.Height, K: self.makeAbout(msg.Better).K,
				M:self.makeAbout(msg.Better).M, Better: msg.Better,
				From: self.Me, Reply:"cnst"}
			miner.server.CommitteeMsg(msg.Better, &d)
		*/
	}
}

type debugtype struct {
}

func (self *Syncer) run() {
	miner.wg.Add(1)
	defer miner.wg.Done()

	ticker := time.NewTicker(time.Second * 1)
	begin := time.Now()

loop:
	for {
		self.forestLock.Lock()

		select {
		case <-self.quit:
			self.forestLock.Unlock()
			break loop

		case cmd := <-self.commands:
			switch cmd.(type) {
			case *debugtype:
				self.debugging()

			case *tree:
				tree := cmd.(*tree)
				if self.sigGiven >= 0 {
					self.forestLock.Unlock()
					continue
				}
				if tree.block != nil {
					log.Infof("newtree %s at %d width %d txs", tree.hash.String(), self.Height, len(tree.block.MsgBlock().Transactions))
				} else {
					log.Infof("newtree %s at %d", tree.hash.String(), self.Height)
				}

				if !self.validateMsg(tree.creator, nil, nil) {
					log.Infof("tree creator %x is not a member of committee", tree.creator)
					self.forestLock.Unlock()
					continue
				}

				if tree.block != nil &&
					len(tree.block.MsgBlock().Transactions) > 1 &&
					len(tree.block.MsgBlock().Transactions[1].TxIn) > 1 &&
					tree.block.MsgBlock().Transactions[1].TxIn[0].SignatureIndex == 0xFFFFFFFF {
					log.Errorf("Incorrect tree. I generated dup tree hash at %d", self.Height)
				}

				self.handeling = "New tree"
				c := self.Members[tree.creator]

				if _, ok := self.forest[tree.creator]; !ok || self.forest[tree.creator].block == nil {
					// each creator may submit only one tree
					self.forest[tree.creator] = tree
					self.repeats = 0
				} else if (self.forest[tree.creator].hash != chainhash.Hash{}) && tree.hash != self.forest[tree.creator].hash {
					if self.Me == tree.creator {
						log.Errorf("Incorrect tree. I generated dup tree hash at %d", self.Height)
						self.forestLock.Unlock()
						continue
					}
					self.Malice[tree.creator] = struct{}{}
					delete(self.forest, tree.creator)
					self.knowledges.Malice(c)
				}

				if tree.block != nil {
					if _, ok := self.pulltime[c]; ok {
						delete(self.pulltime, c)
						delete(self.pulling, c)
					}
				}

				if bytes.Compare(tree.creator[:], self.Me[:]) == 0 {
					k := wire.NewMsgKnowledge()
					k.From = self.Me
					k.Height = self.Height
					k.Finder = self.Me
					k.M = tree.hash
					k.AddK(self.Myself, miner.server.GetPrivKey(self.Me))
					self.commands <- k
				}
				self.print()

			case Message:
				m := cmd.(Message)
				self.handeling = m.Command()

				switch m.(type) {
				case *wire.MsgKnowledge: // passing knowledge
					if self.sigGiven >= 0 {
						self.forestLock.Unlock()
						continue
					}

					k := m.(*wire.MsgKnowledge)

					self.knowRevd[self.Members[k.From]] = self.Members[k.From]

					if !self.validateMsg(k.Finder, &k.M, m) {
						log.Infof("MsgKnowledge invalid")
						self.forestLock.Unlock()
						continue
					}

					if _, ok := self.forest[k.Finder]; !ok || self.forest[k.Finder].block == nil {
						self.pull(k.M, self.Members[k.Finder])
					}

					if self.knowledges.ProcKnowledge(k) {
						self.candidacy()

						if self.knows[k.Finder] == nil {
							self.knows[k.Finder] = make([]*wire.MsgKnowledge, 0)
						}
						self.knows[k.Finder] = append(self.knows[k.Finder], k)
						self.repeats = 0
					}

				case *wire.MsgCandidate: // announce candidacy
					k := m.(*wire.MsgCandidate)

					if self.sigGiven >= 0 && self.Names[self.sigGiven] != k.F {
						log.Infof("MsgCandidate declined. sig already given to %d", self.sigGiven)
						self.forestLock.Unlock()
						continue
					}

					self.candRevd[self.Members[k.F]] = self.Members[k.F]

					if !self.validateMsg(k.F, &k.M, m) {
						log.Infof("Invalid MsgCandidate message")
						self.forestLock.Unlock()
						continue
					}

					if _, ok := self.forest[k.F]; !ok || self.forest[k.F].block == nil {
						self.pull(k.M, self.Members[k.F])
					} else {
						self.Candidate(k)
					}

				case *wire.MsgCandidateResp: // response to candidacy announcement
					if self.sigGiven >= 0 {
						self.forestLock.Unlock()
						continue
					}

					k := m.(*wire.MsgCandidateResp)
					if !self.validateMsg(k.From, nil, m) {
						self.forestLock.Unlock()
						continue
					}

					self.candidateResp(k)

				case *wire.MsgRelease: // grant a release from duty
					if self.sigGiven >= 0 {
						self.forestLock.Unlock()
						continue
					}
					k := m.(*wire.MsgRelease)
					if !self.validateMsg(k.From, nil, m) {
						self.forestLock.Unlock()
						continue
					}

					self.Release(k)
					self.repeats = 0

				case *wire.MsgConsensus: // announce consensus reached
					if self.sigGiven >= 0 {
						self.forestLock.Unlock()
						continue
					}
					k := m.(*wire.MsgConsensus)

					if !self.validateMsg(k.From, nil, m) {
						self.forestLock.Unlock()
						continue
					}

					if _, ok := self.forest[k.From]; !ok || self.forest[k.From].block == nil {
						self.pull(k.M, self.Members[k.From])
					}

					self.consRevd[self.Members[k.From]] = self.Members[k.From]
					self.repeats = 0
					if self.Consensus(k) {
						self.forestLock.Unlock()
						break loop
					}

				case *wire.MsgSignature: // received signature
					k := m.(*wire.MsgSignature)
					self.repeats = 0

					if self.Signature(k) {
						if len(self.signed) == wire.CommitteeSize || time.Now().Sub(begin) >= time.Second {
							self.forestLock.Unlock()
							break loop
						} else {
							time.Sleep(500 * time.Millisecond) // wait 500 millisecond to allow all members to sign
						}
					}

				default:
					log.Infof("unable to handle message type %s at %d", m.Command(), m.Block())
				}
			}

		case <-ticker.C:
			for len(ticker.C) > 0 {
				<-ticker.C
			}
			self.repeater()
		}
		self.forestLock.Unlock()
		self.handeling = ""
	}

	ticker.Stop()

	for true {
		select {		// drain all msgs
		case m := <- self.commands:
			switch m.(type) {
			case *wire.MsgSignature:	// take all pending signatures
				self.Signature(m.(*wire.MsgSignature))
			}

		default:	// no more msg pending. pub & quit
			if self.sigGiven != -1 {
				owner := self.Names[self.sigGiven]
				if self.Runnable && self.forest[owner] != nil && self.forest[owner].block != nil &&
					len(self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
					miner.server.NewConsusBlock(self.forest[owner].block)
				}
			}

			log.Infof("sync %d quit", self.Height)

			self.Done = true
			self.Runnable = false

			return
		}
	}
}

func Sender(msg Message) []byte {
	if msg == nil || miner == nil {
		return nil
	}
	switch msg.(type) {
	case *wire.MsgKnowledge:
		return nil
/*
		tmsg := *msg.(*wire.MsgKnowledge)
		tmsg.K = make([]int32, 0)
		tmsg.Signatures = make([][]byte, 0)
		tmsg.From = tmsg.Finder

		for j,i := range msg.(*wire.MsgKnowledge).K {
			sig := msg.(*wire.MsgKnowledge).Signatures[j]

			signer, err := btcutil.VerifySigScript(sig, tmsg.DoubleHashB(), miner.cfg)
			if err != nil {
				log.Infof("MsgKnowledge VerifySigScript fail")
				return nil
			}

			pkh := signer.Hash160()

			tmsg.K = append(tmsg.K, i)
			tmsg.Signatures = append(tmsg.Signatures, sig)
			tmsg.From = *pkh
		}
		return tmsg.From[:]
 */

	case *wire.MsgCandidate, *wire.MsgCandidateResp, *wire.MsgRelease:
		signer, err := btcutil.VerifySigScript(msg.GetSignature(), msg.DoubleHashB(), miner.cfg)
		if err != nil {
			log.Infof("%s VerifySigScript fail", msg.Command())
			return nil
		}
		return (*signer.Hash160())[:]

	case *wire.MsgSignature:
		k,err := btcec.ParsePubKey(msg.(*wire.MsgSignature).Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		if err != nil {
			return nil
		}
		pk, _ := btcutil.NewAddressPubKeyPubKey(*k, miner.cfg)
		pk.SetFormat(btcutil.PKFCompressed)
		return pk.ScriptAddress()

	case *wire.MsgConsensus:
		k,err := btcec.ParsePubKey(msg.(*wire.MsgConsensus).Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		if err != nil {
			return nil
		}
		pk, _ := btcutil.NewAddressPubKeyPubKey(*k, miner.cfg)
		pk.SetFormat(btcutil.PKFCompressed)
		return pk.ScriptAddress()
	}
	return nil
}

func (self *Syncer) Signature(msg * wire.MsgSignature) bool {
	if self.agreed == -1 {
		return false
	}
	if f,ok := self.forest[self.Names[self.agreed]]; !ok || !msg.M.IsEqual(&f.hash) {
		return false
	}

	if _, ok := self.signed[msg.From]; ok {
		return len(self.signed) >= wire.CommitteeSigs
	}

	tree := int32(-1)
	for i,f := range self.forest {
		if msg.M == f.hash && i == msg.For && f.block != nil {
			tree = self.Members[i]
		}
	}
	if tree < 0 || tree != self.agreed {
		log.Infof("signature ignored, it is for %d (%s), not what I agreed %d.", tree, msg.M.String(), self.agreed)
		return false
	}

	owner := self.Names[tree]

	// TODO: detect double signature
	// verify signature
	hash := blockchain.MakeMinerSigHash(self.Height, msg.M)

	k,err := btcec.ParsePubKey(msg.Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
	if err != nil {
		return false
	}

	s, err := btcec.ParseDERSignature(msg.Signature[btcec.PubKeyBytesLenCompressed:], btcec.S256())
	if err != nil {
		return false
	}

	if !s.Verify(hash, k) {
		return false
	}

	if self.sigGiven == -1 {	// len(self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts[1]) <= 20 {
		// remove the sig 1 that contained the miner's name
		self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts =
			self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts[:1]
	}

	if !UpdateLastWritten(self.Height) && self.sigGiven != tree {	// nenver sign if height is not higher than last signed block
		return false
	}

	self.sigGiven = tree

	self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts = append(
		self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts,
		msg.Signature[:])
	self.signed[msg.From] = struct{}{}

	return len(self.signed) >= wire.CommitteeSigs
}

func (self *Syncer) Consensus(msg * wire.MsgConsensus) bool {
	if self.agreed != self.Members[msg.From] {
		return false
	}

	// verify signature
	hash := blockchain.MakeMinerSigHash(self.Height, self.forest[msg.From].hash)

	k,err := btcec.ParsePubKey(msg.Signature[:btcec.PubKeyBytesLenCompressed], btcec.S256())
	if err != nil {
		return false
	}

	s, err := btcec.ParseDERSignature(msg.Signature[btcec.PubKeyBytesLenCompressed:], btcec.S256())
	if err != nil {
		return false
	}

	if !s.Verify(hash, k) {
		return false
	}

	privKey := miner.server.GetPrivKey(self.Me)
	if privKey == nil {
		return false
	}

	sig, _ := privKey.Sign(hash)
	sgs := sig.Serialize()

	sigmsg := wire.MsgSignature {
		For:	   msg.From,
	}
	sigmsg.MsgConsensus = wire.MsgConsensus {
		Height:    self.Height,
		From:      self.Me,
		M:		   msg.M,
		Signature: make([]byte, btcec.PubKeyBytesLenCompressed + len(sgs)),
	}

	copy(sigmsg.Signature[:], privKey.PubKey().SerializeCompressed())
	copy(sigmsg.Signature[btcec.PubKeyBytesLenCompressed:], sgs)

//	log.Infof("Consensus: cast signature")

	self.CommitteeCastMG(&sigmsg)

	if self.sigGiven == -1 {
		if !UpdateLastWritten(self.Height) && self.sigGiven != self.agreed {	// nenver sign if height is not higher than last signed block
			return false
		}
		self.sigGiven = self.agreed
		if self.forest[msg.From].block != nil {
			// remove the sig 1 that contained the miner's name
			self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts =
				self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts[:1]
			// add signatures to block
			self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts = append(
				self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts,
				sigmsg.Signature[:])
			self.signed[self.Me] = struct{}{}
		}
	}

	if _, ok := self.signed[msg.From]; !ok && self.forest[msg.From].block != nil {
		self.signed[msg.From] = struct{}{}
		// add signatures to block
		self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts = append(
			self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts,
			msg.Signature[:])
		self.signed[msg.From] = struct{}{}

		if len(self.forest[msg.From].block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
			return true
//			log.Info("passing NewConsusBlock & quit")
//			miner.server.NewConsusBlock(self.forest[msg.From].block)
		}
	}
	return false
}

func (self *Syncer) reckconsensus() {
	if self.agreed != self.Myself || self.sigGiven != self.Myself || len(self.agrees) + 1 < wire.CommitteeSigs {
		return
	}

	if self.forest[self.Me] == nil || self.forest[self.Me].block == nil {
		return
	}

	if _,ok := self.signed[self.Me]; !ok {
		return
	}

	hash := blockchain.MakeMinerSigHash(self.Height, self.forest[self.Me].hash)

	if privKey := miner.server.GetPrivKey(self.Me); privKey != nil && self.sigGiven == self.Myself {
		sig, _ := privKey.Sign(hash)
		ss := sig.Serialize()
		msg := wire.MsgConsensus{
			Height:    self.Height,
			From:      self.Me,
			M:		   self.forest[self.Me].hash,
			Signature: make([]byte, btcec.PubKeyBytesLenCompressed + len(ss)),
		}

		copy(msg.Signature[:], privKey.PubKey().SerializeCompressed())
		copy(msg.Signature[btcec.PubKeyBytesLenCompressed:], ss)

		//		log.Infof("reckconsensus: cast Consensus")

		self.CommitteeCastMG(&msg)
	}
}

func (self *Syncer) ckconsensus() bool {
	if self.agreed != self.Myself || len(self.agrees) + 1 < wire.CommitteeSigs {
		return false
	}

	if self.forest[self.Me] == nil || self.forest[self.Me].block == nil {
		return false
	}

	hash := blockchain.MakeMinerSigHash(self.Height, self.forest[self.Me].hash)

	if privKey := miner.server.GetPrivKey(self.Me); privKey != nil && self.sigGiven == -1 {
		if !UpdateLastWritten(self.Height) && self.sigGiven != self.Myself {	// nenver sign if height is not higher than last signed block
			return false
		}
		self.sigGiven = self.Myself

		sig, _ := privKey.Sign(hash)
		ss := sig.Serialize()
		msg := wire.MsgConsensus{
			Height:    self.Height,
			From:      self.Me,
			M:		   self.forest[self.Me].hash,
			Signature: make([]byte, btcec.PubKeyBytesLenCompressed + len(ss)),
		}

		copy(msg.Signature[:], privKey.PubKey().SerializeCompressed())
		copy(msg.Signature[btcec.PubKeyBytesLenCompressed:], ss)

		self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts =
			self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts[:1]

		self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts = append(
			self.forest[self.Me].block.MsgBlock().Transactions[0].SignatureScripts,
			msg.Signature[:])
		self.signed[self.Me] = struct{}{}
		self.agrees[self.Myself] = struct{}{}

//		log.Infof("ckconsensus: cast Consensus")

		self.CommitteeCastMG(&msg)

		return true
	}
	return false
}

func (self *Syncer) makeRelease(better int32) *wire.MsgRelease {
	var h chainhash.Hash
	if better != -1 {
		h = self.forest[self.Names[better]].hash //self.makeAbout(better).M,
	}
	d := &wire.MsgRelease{
		Better: better,
		M:      h,
		Height: self.Height,
		From:   self.Me,
	}
	d.Sign(miner.server.GetPrivKey(self.Me))
	return d
}

func (self *Syncer) dupKnowledge(fmp int32) {
	agreed := self.Names[self.agreed]

	ns := make([]*wire.MsgKnowledge, 0)

	for _, ks := range self.knows[agreed] {
		if ks.K[len(ks.K)-1] != fmp {
			m := int64((1 << fmp) | (1 << self.Myself))
			for _, w := range ks.K {
				m = 1 << w
			}

			t := *ks
			t.AddK(self.Myself, miner.server.GetPrivKey(self.Me))

			if ng,_ := self.knowledges.gain(self.agreed, t.K); ng {
				if self.CommitteeMsg(self.Names[fmp], &t) {
					self.knowledges.Knowledge[self.agreed][fmp] |= m
					self.knowledges.Knowledge[self.agreed][self.Myself] |= m
				}
				ns = append(ns, &t)
			}
		}
	}

	if len(ns) > 0 {
		self.knows[agreed] = append(self.knows[agreed], ns...)
	}
}

func (self *Syncer) yield(better int32) bool {
	if self.better(better, self.agreed) {
		self.asked[self.Myself] = false
		rls := self.makeRelease(better)
		for r, _ := range self.agrees {
			if r != self.Myself {
				rls.Sign(miner.server.GetPrivKey(self.Me))
				self.CommitteeMsgMG(self.Names[r], rls)
			}
		}
		self.agrees = make(map[int32]struct{})
		self.agreed = -1
		if self.asked[better] && better != self.Myself {
			// give a consent to Better
			d := wire.MsgCandidateResp{Height: self.Height, K: []int64{}, From: self.Me}
			d.Reply = "cnst"
			d.Better = better
			d.M = self.forest[self.Names[better]].hash
			d.Sign(miner.server.GetPrivKey(self.Me))

//			log.Infof("yield: yield to %x", self.Names[better])

			self.CommitteeMsgMG(self.Names[better], &d)
		}
		self.agreed = better
		return true
	}
	return false
}

func (self *Syncer) candidateResp(msg *wire.MsgCandidateResp) {
	if msg.Reply == "cnst" && self.agreed != -1 {
		if self.agreed != self.Myself {
			// release the node from obligation and notify him about new agreed
//			log.Infof("consent received from %x but I am not taking it", msg.From)
			self.CommitteeMsgMG(msg.From, self.makeRelease(self.agreed))
		} else {
//			log.Infof("consent received from %x", msg.From)
			self.agrees[self.Members[msg.From]] = struct{}{}
			self.ckconsensus()
		}
		self.repeats = 0
	} else if msg.Reply == "cnst" && self.agreed == -1 {
//		log.Infof("consent received from %x but I am not taking it", msg.From)
		self.CommitteeMsgMG(msg.From, self.makeRelease(self.agreed))
		self.repeats = 0
	} else if msg.Reply == "rjct" && self.agreed == self.Myself {
//		log.Infof("rejection received from %x", msg.From)
		self.knowledges.Rejected(self.Members[msg.From])

		switch msg.Better {
		case -1:
			// reject because signed another candidate
			return

		default:
			// reject because there is a better choice
			t,ok := self.forest[self.Names[msg.Better]]
			if !ok || t.block == nil {
				self.pull(msg.M, msg.Better)
//				self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
				return
			}
			// check if Better is indeed better, if yes, release it (in yield)
			if !self.yield(msg.Better) {
				// no. we are better, send knowledge about it
				// peer is misbehaving, because we should agree on who is better
//				self.dupKnowledge(self.Members[msg.From])
				if self.agreed == self.Myself {
					msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)
					msg.Sign(miner.server.GetPrivKey(self.Me))

//					log.Infof("candidateResp: reaffirm candidacy")

					self.CommitteeMsgMG(msg.F, msg) // ask again
				}
			} else {
				self.agreed = -1
			}
		}

/*
		if self.knowledges.ProcFlatKnowledge(msg.Better, msg.K) {
			// gained more knowledge, check if we are better than msg.better, if not
			// release nodes in agrees
			if self.knowledges.Qualified(msg.Better) &&
				self.asked[self.Names[msg.Better]] &&
				self.forest[self.Names[msg.Better]].fees > self.forest[self.Me].fees ||
				(self.forest[self.Names[msg.Better]].fees == self.forest[self.Me].fees && msg.Better > self.Myself) {

				delete(self.asked, self.Me)
				for r, _ := range self.agrees {
					miner.server.CommitteeMsg(r, self.makeRelease(msg.Better))
				}

				self.agreed = msg.Better
				d := wire.MsgCandidateResp{Height: msg.Height,
					K: self.makeAbout(msg.Better).K,
					M: self.makeAbout(msg.Better).M,
					Better: msg.Better,
					From: self.Me, Reply:"cnst"}
				miner.server.CommitteeMsg(msg.Better, &d)

				self.agrees = make(map[int32]struct{})
				return
			}
		}

 */
	}
}

func (self *Syncer) candidacy() {
	if self.agreed == self.Myself || self.agreed != -1 || !self.knowledges.Qualified(self.Myself) {
		return
	}

	better := self.Myself

	for i := 0; i < wire.CommitteeSize; i++ {
		if self.asked[int32(i)] && self.better(int32(i), better) && self.knowledges.Qualified(int32(i)) {
			// there is a better candidate
			// someone else is the best, send him knowledge about him that he does not know
			better = int32(i)
		}
	}

	if better != self.Myself {
		t := self.forest[self.Names[better]]
		if t.block == nil {
			self.pull(t.hash, better)
		}
		return
	}

	// we may announce candidacy only if we have all trees in or time to pull has expired
	ready := true
	for m, t := range self.forest {
		if t.block != nil {
			continue
		}
		if d,ok := self.pulltime[self.Members[m]]; ok {
			if time.Now().Unix() < 30 + d {
				ready = false
			}
		} else {
			ready = false
		}
	}
	if !ready {
		return
	}

	mp := self.Myself
	self.agreed = mp

//	self.consents[self.Me] = 1

//	log.Infof("Announce candicacy by %d at %d", self.Myself, self.Height)
//	self.DebugInfo()

	msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)

	self.asked[self.Myself] = true

	msg.Sign(miner.server.GetPrivKey(self.Me))

//	log.Infof("candidacy: Announce candicacy")

	self.CommitteeCastMG(msg)
}

func (self *Syncer) Candidate(msg *wire.MsgCandidate) {
	// received a request for confirmation of candidacy
	d := wire.MsgCandidateResp{Height: msg.Height, K: []int64{}, From: self.Me, M: msg.M}

	from := msg.F
	fmp,ok := self.Members[from]

	if !self.Runnable || !ok {
		return
	}

	if self.sigGiven != -1 && self.sigGiven != fmp {
		d.Reply = "rjct"
		d.Better = -1
		d.Sign(miner.server.GetPrivKey(self.Me))

//		log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
		return
	}
	if self.sigGiven != -1 {
		return
	}

	self.asked[fmp] = true

	if _,ok := self.forest[from]; !ok || self.forest[from].block == nil {
		self.pull(msg.M, fmp)
		return
	}

	if !self.knowledges.Qualified(fmp) {
		// we might not have enough info. so keep silent.
/*
		d.Reply = "rjct"
		d.Better = -2
		d.Sign(miner.server.GetPrivKey(self.Me))

		log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
 */
		return
	}

	if self.agreed == self.Myself && self.better(fmp, self.agreed) {
		if self.yield(fmp) {
			return
		}
	}

	if self.agreed == -1 || self.agreed == fmp {
//		log.Infof("consent given by %x to %d", self.Me, fmp)
		d.Reply = "cnst"
		d.Better = fmp
		self.agreed = fmp
		d.Sign(miner.server.GetPrivKey(self.Me))

//		log.Infof("Candidate: Consent candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
		self.repeats = 0
		return
	}

	// reject it, tell who we have agreed. check whether fmp is better than agreed, if not give knowledge of agreed,
	if self.better(self.agreed, fmp) {
		self.dupKnowledge(fmp)
	}

	d.Reply = "rjct"
	//		d.K = []int64{-1024}
	//		for _,p := range self.knowledges.Knowledge[self.agreed] {
	//			d.K = append(d.K, p)
	//		}
	d.Better = self.agreed
	d.M = self.forest[self.Names[self.agreed]].hash
	d.Sign(miner.server.GetPrivKey(self.Me))

//	log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

	self.CommitteeMsgMG(self.Names[fmp], &d)
}

func CreateSyncer(h int32) *Syncer {
	p := Syncer{}

	p.commands = make(chan interface{}, 100)
	p.quit = make(chan struct{})
	p.Height = h
//	p.pending = make(map[string][]Message, 0)

	p.pulling = make(map[int32]int)
	p.pulltime = make(map[int32]int64)
	p.agrees = make(map[int32]struct{})
//	p.asked = make(map[int32]struct{})
	p.signed = make(map[[20]byte]struct{})
	p.Members = make(map[[20]byte]int32)
	p.Names = make(map[int32][20]byte)
	p.Malice = make(map[[20]byte]struct {})
	p.knows = make(map[[20]byte][]*wire.MsgKnowledge)
	p.Done = false

	p.agreed = -1
	p.sigGiven = -1
	p.repeats = 0

	p.handeling = ""
//	p.mutex = sync.Mutex{}

//	p.consents = make(map[[20]byte]int32, wire.CommitteeSize)
	p.forest = make(map[[20]byte]*tree, wire.CommitteeSize)

	p.Runnable = false
//	p.Me = miner.name

//	p.SetCommittee()
	p.knowRevd = make([]int32, wire.CommitteeSize)
	p.candRevd = make([]int32, wire.CommitteeSize)
	p.consRevd = make([]int32, wire.CommitteeSize)
	for i := 0; i < wire.CommitteeSize; i++ {
		p.knowRevd[i], p.candRevd[i], p.consRevd[i] = -1, -1, -1
	}

	return &p
}

func (self *Syncer) validateMsg(finder [20]byte, m * chainhash.Hash, msg Message) bool {
	if !self.Runnable || self.Done {
		if !self.Runnable {
			log.Infof("validate failed. I'm not runnable")
		} else {
			log.Infof("validate failed. I'm done at this height")
		}
//		time.Sleep(time.Second)
//		self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
		return false
	}

	if _, ok := self.Malice[finder]; ok {
		log.Infof("validate failed. %x is a malice node", finder)
		return false
	}

	c, ok := self.Members[finder]

	if !ok {
		log.Infof("validate failed. %x is a not a member of committee at height %d", finder, self.Height)
		return false
	}

	switch msg.(type) {
	case *wire.MsgKnowledge:
		tmsg := *msg.(*wire.MsgKnowledge)
		tmsg.K = make([]int32, 0)
		tmsg.Signatures = make([][]byte, 0)
		tmsg.From = tmsg.Finder

		for j,i := range msg.(*wire.MsgKnowledge).K {
			sig := msg.(*wire.MsgKnowledge).Signatures[j]

			signer, err := btcutil.VerifySigScript(sig, tmsg.DoubleHashB(), miner.cfg)
			if err != nil {
				log.Infof("MsgKnowledge VerifySigScript fail")
				return false
			}

			pkh := signer.Hash160()

			tmsg.K = append(tmsg.K, i)
			tmsg.Signatures = append(tmsg.Signatures, sig)
			tmsg.From = self.Names[int32(i)]
			if bytes.Compare(tmsg.From[:], pkh[:]) != 0 {
				log.Infof("MsgKnowledge Verify sender fail")
				return false
			}
		}

	case *wire.MsgCandidate, *wire.MsgCandidateResp, *wire.MsgRelease:
		signer, err := btcutil.VerifySigScript(msg.GetSignature(), msg.DoubleHashB(), miner.cfg)
		if err != nil {
			log.Infof("%s VerifySigScript fail", msg.Command())
			return false
		}
		pkh := signer.Hash160()
		if bytes.Compare(msg.Sender(), pkh[:]) != 0 {
			log.Infof("%s Verify sender fail", msg.Command())
			return false
		}
	}

	if _, ok = self.forest[finder]; m != nil && !ok {
		self.forest[finder] = &tree{
			creator: finder,
			fees:    0,
			hash:    *m,
			header:  nil,
			block:   nil,
		}

//		log.Infof("Pull block %s from %d", m.String(), c)
		self.pull(*m, c)
		return true
	}

	if m != nil && self.forest[finder].hash != *m {
		log.Infof("block is not the same as registered %x", self.forest[finder].hash)

		return false
	}
	return true
}

func (self *Syncer) SetCommittee() {
	self.setCommittee()
}

func (self *Syncer) setCommittee() {
	if self.Runnable || self.Done {
		return
	}

	best := miner.server.BestSnapshot()
	self.Runnable = self.Height == best.Height + 1

	if !self.Runnable {
		log.Infof("self.Height %d != best.Height %d + 1", self.Height, best.Height)
		return
	}

	c := int32(best.LastRotation)

	self.Committee = c
	self.Base = c - wire.CommitteeSize + 1

	in := false

	for i := c - wire.CommitteeSize + 1; i <= c; i++ {
		blk,_ := miner.server.MinerBlockByHeight(i)
		if blk == nil {
			continue
		}

		who := i - (c - wire.CommitteeSize + 1)

		for _,n := range miner.name {
			if bytes.Compare(n[:], blk.MsgBlock().Miner[:]) == 0 {
				inc := false
				for _, ip := range miner.cfg.ExternalIPs {
					if ip == string(blk.MsgBlock().Connection) {
						inc = true
					}
				}
				if !inc {
					continue
				}

				copy(self.Me[:], n[:])
				self.Myself = who
				in = true
			}
		}

		self.Members[blk.MsgBlock().Miner] = who
		self.Names[who] = blk.MsgBlock().Miner
	}

	self.knowledges = CreateKnowledge(self)

	if in {
		log.Infof("Run consensus protocol at %d", self.Height)
		go self.run()
	} else {
		self.Runnable = false
	}
}

func (self *Syncer) UpdateChainHeight(h int32) {
//	if h < self.Height {
//		return
//	}
	if h > self.Height {
		self.Quit()
		return
	}
	
//	self.SetCommittee()
}

func (self *Syncer) BlockInit(block *btcutil.Block) {
	var adr [20]byte

	if self.Done {
		return
	}
	if len(block.MsgBlock().Transactions[0].SignatureScripts) < 2 {
		log.Errorf("block does not contain enough signatures. %d", len(block.MsgBlock().Transactions[0].SignatureScripts))
		return
	}
	if len(block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
		log.Infof("it is a consensus block. Skip it.")
		return
	}
	copy(adr[:], block.MsgBlock().Transactions[0].SignatureScripts[1])

	// total fees are total coinbase outputs
	fees := int64(0)
	eq := int64(-1)
	for _, txo := range block.MsgBlock().Transactions[0].TxOut {
		if txo.IsSeparator() {
			break
		}
		if txo.TokenType == 0 {
			if eq < 0 {
				eq = txo.Value.(*token.NumToken).Val
			} else if eq != txo.Value.(*token.NumToken).Val {
				return
			}
			fees += eq
		} else {
			break
		}
	}

	if len(block.MsgBlock().Transactions[0].TxOut) < wire.CommitteeSigs {
		return
	}

	self.setCommittee()
	
	self.forestLock.Lock()
	if r,ok := self.forest[adr]; !ok || r.block == nil {
		self.commands <- &tree{
			creator: adr,
			fees:    uint64(fees),
			hash:    * block.Hash(),
			header:  &block.MsgBlock().Header,
			block:   block,
		}
	}
	self.forestLock.Unlock()

	if miner.server.BestSnapshot().Hash != block.MsgBlock().Header.PrevBlock {
		miner.server.ChainSync(block.MsgBlock().Header.PrevBlock, adr)
	}
}

func (self *Syncer) pull(hash chainhash.Hash, from int32) {
	self.handeling = "pull"
	if _,ok := self.pulling[from]; !ok || self.pulling[from] == 0 {
		// pull block
		msg := wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, hash}}}
//		log.Infof("Pull request: to %d hash %s", from+self.Base, hash.String())
		if self.CommitteeMsg(self.Names[from], &msg) {
//			log.Infof("Pull request sent to %d", from)
			self.pulling[from] = 5
			self.pulltime[from] = time.Now().Unix()
		} else {
			log.Infof("Fail to Pull !!!!!!!!")
		}
	} else {
		self.pulling[from]--
//		log.Infof("Have pulled for %d at height %d", from, self.Height)
	}
}

func (self *Syncer) Quit() {
	self.Done = true
	select {
	case _,ok := <-self.quit:
		if ok {
			close(self.quit)
		}

	default:
		close(self.quit)
	}
}

func (self *Syncer) print() {
//	return

	log.Infof("Syncer for %d = %x", self.Myself, self.Me)
	log.Infof("Runnable = %d Committee = %d Base = %d", self.Runnable, self.Committee, self.Base)
	log.Infof("agreed = %d sigGiven = %d Height = %d", self.agreed, self.sigGiven, self.Height)
	log.Infof("Done = %d # of agrees = %d: %v", self.Done, len(self.agrees), self.agrees)

	knowRevd := "Knowledge received from: "
	candRevd := "Candidacy anouncement received from: "
	consRevd := "Consensus anouncement received from: "

	for i := 0; i < wire.CommitteeSize; i++ {
		knowRevd += fmt.Sprintf("%d ", self.knowRevd[i])
		candRevd += fmt.Sprintf("%d ", self.candRevd[i])
		consRevd += fmt.Sprintf("%d ", self.consRevd[i])
	}
	log.Infof("%s\n%s\n%s", knowRevd, candRevd, consRevd)

	if self.knowledges != nil {
		log.Infof("knowledges = ")

		self.knowledges.print()
	}
}

func (self *Syncer) DebugInfo() {
	if !self.Done && len(self.commands) < (wire.CommitteeSize - 1) * 10 {
		self.commands <- &debugtype{}
	}
}

func (self *Syncer) debugging() {
	log.Infof("\ndebugging\nI am %x, %d", self.Me, self.Myself)
	self.print()
	log.Infof("Members & Names (%d):", len(self.Members))
	for m,n := range self.Members {
		if self.Names[n] != m {
			log.Infof("Unmatched Members & Names: %x, %d", m, n)
		}
		log.Infof("Members & Names: %d, %x", n, m)
	}
	for m,n := range self.Names {
		if self.Members[n] != m {
			log.Infof("Unmatched Members & Names: %d, %x", m, n)
		}
	}
	log.Infof("Queues: commands = %d, handeling = %s", len(self.commands), self.handeling)

	if len(self.Malice) > 0 {
		log.Infof("Malice miners:")
		for m,_ := range self.Malice {
			log.Infof("%x", m)
		}
	}

	if len(self.agrees) > 0 {
		log.Infof("Who has agreed to this block (%d):", len(self.agrees))
		for m,_ := range self.agrees {
			log.Infof("%x", m)
		}
	}
	log.Infof("Who has asked to agree candicacy:")
	for m,ok := range self.asked {
		if ok {
			log.Infof("%d ", m)
		}
	}
	log.Info("\n")

	if len(self.signed) > 0 {
		log.Infof("Who has signed for this block (%d):", len(self.signed))
		for m,_ := range self.signed {
			log.Infof("%x", m)
		}
	}
/*
	if len(self.pending) > 0 {
		log.Infof("Pending messages:")
		for _,q := range self.pending {
			for _,m := range q {
				log.Infof("%s", m.(wire.Message).Command())
			}
		}
	}
 */

	log.Infof("Forrest (%d):", len(self.forest))
	for w,t := range self.forest {
		log.Infof("Tree of %x:", w)
		log.Infof("creator of %x:", t.creator)
		log.Infof("fees of %d:", t.fees)
		log.Infof("hash of %s:", t.hash.String())
		if t.block == nil {
			log.Infof("Tree is naked")
		}
	}
	log.Infof("\n")
}

func (self *Syncer) better(left, right int32) bool {
	l,ok := self.forest[self.Names[left]]
	if !ok {
		return false
	}
	r,ok := self.forest[self.Names[right]]
	if !ok {
		return true
	}
	return l.fees > r.fees || (l.fees == r.fees && left < right)
}

func (self *Syncer) best() int32 {
	var seld *[20]byte

	for left,l := range self.forest {
		if seld == nil {
			if l.block != nil {
				seld = new([20]byte)
				copy(seld[:], left[:])
			}
		} else {
			if l.block != nil && (l.fees > self.forest[*seld].fees ||
				(l.fees == self.forest[*seld].fees && self.Members[left] < self.Members[*seld])) {
				copy(seld[:], left[:])
			}
		}
	}

	if seld == nil {
		return -1
	}
	return self.Members[*seld]
}