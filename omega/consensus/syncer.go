/* Copyright (C) 2019-2020 omega-chain.com - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
* You should have received a copy of the license with this file.
* If not, please visit: <https://omega-chain.com/license.html>
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
	"net/http"
	"sync"
	"time"
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

	asked    map[int32]struct{}		// those who have asked to be a candidate, and not released
	agrees   map[int32]struct{}		// those who I have agree to be a candidate
	agreed   int32			// the one who I have agreed. can not back out until released by
	sigGiven int32			// who I have given my signature. can never change once given.

//	consents map[[20]byte]int32		// those wh
	forest   map[[20]byte]*tree		// blocks mined
	knows    map[[20]byte][]*wire.MsgKnowledge	// the knowledges we received organized by finders (i.e. fact)
	signed   map[[20]byte]struct{}

	knowledges *Knowledgebase

	newtree chan tree
	quit chan struct{}
	Done bool

	Height int32

	pending map[string][]Message
	pulling map[int32]int

	messages chan Message
	repeating chan struct{}

	mutex sync.Mutex

	// debug only
	knowRevd	[]int32
	candRevd	[]int32
	consRevd	[]int32

	// wait for end of task
//	wg          sync.WaitGroup
	idles		int
}

func (self *Syncer) CommitteeMsgMG(p [20]byte, m wire.Message) {
	if _, ok := self.Members[p]; ok {
		miner.server.CommitteeMsgMG(p, m)
	}
}

func (self *Syncer) CommitteeMsg(p [20]byte, m wire.Message) bool {
	_, ok := self.Members[p]
	return ok && miner.server.CommitteeMsg(p, m)
}

func (self *Syncer) CommitteeCastMG(msg wire.Message) {
	for i, p := range self.Names {
		if i == self.Myself {
			continue
		}
		miner.server.CommitteeMsgMG(p, msg)
	}
}

func (self *Syncer) findBlock(h * chainhash.Hash) * btcutil.Block {
	for _,f := range self.forest {
		if f.block != nil && f.hash.IsEqual(h) {
			return f.block
		}
	}
	return nil
}

func (self *Syncer) repeater() {
	log.Infof("Repeater: %d enter", self.Height)
	defer func() {
		log.Infof("Repeater: exit")
	}()

	miner.server.CommitteePolling()

	// enough sigs to conclude?
	if self.agreed != -1 && len(self.signed) >= wire.CommitteeSigs {
		self.mutex.Lock()
		select {
		case <-self.quit:
		default:
			self.quit <- struct{}{}
		}
		self.mutex.Unlock()
		return
	}

	self.mutex.Lock()
	for _,kp := range self.knows {
		repeated := make(map[int32]struct{})
		for j := len(kp) - 1; j >= 0; j-- {
			p := kp[j]
			if _, ok := repeated[self.Members[p.From]]; ok {
				continue
			}

			log.Infof("Repeater: knowledge to %x", p.From)
			repeated[self.Members[p.From]] = struct{}{}

			// send it
			pp := *p
			//		pp.K = append(pp.K, self.Myself)
			pp.AddK(self.Myself, miner.server.GetPrivKey(self.Me))
			to := pp.From
			pp.From = self.Me

			self.CommitteeMsg(to, &pp)
		}
	}
	if tree,ok := self.forest[self.Me]; ok {
		k := wire.NewMsgKnowledge()
		k.From = self.Me
		k.Height = self.Height
		k.Finder = self.Me
		k.M = tree.hash
		k.AddK(self.Myself, miner.server.GetPrivKey(self.Me))

		self.messages <- k

		for i,p := range self.Names {
			if i == self.Myself {
				continue
			}
			self.CommitteeMsg(p, k)
		}
	}
	self.mutex.Unlock()

	if self.agreed != self.Myself && self.agreed != -1 {
		// resend an agree message
		fmp := self.agreed
		from := self.Names[fmp]

		d := wire.MsgCandidateResp{Height: self.Height, K: []int64{}, From: self.Me, M: self.forest[from].hash}

		if self.sigGiven == -1 {
			d.Reply = "cnst"
			d.Better = fmp
			d.Sign(miner.server.GetPrivKey(self.Me))

			log.Infof("Candidate: Consent candicacy by %x", from)

			self.CommitteeMsgMG(from, &d)
		}
	}

	self.idles++

	if self.idles > 2 {
		// resend candidacy
		if self.agreed == self.Myself {
			log.Infof("Repeater: cast candidacy %d", self.agreed)
			msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)
			msg.Sign(miner.server.GetPrivKey(self.Me))
			self.CommitteeCastMG(msg)
		}

		// resend consensus
		log.Infof("Repeater: reckconsensus")
		self.reckconsensus()

		// resend signatures
		if self.sigGiven != -1 {
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
		}
	}
}

func (self *Syncer) Release(msg * wire.MsgRelease) {
	delete(self.asked, self.Members[msg.From])

	if self.agreed == self.Members[msg.From] {
		//		self.knowledges.ProcFlatKnowledge(msg.Better, msg.K)

		self.agreed = -1
		/*
			self.agreed = msg.Better
			d := wire.MsgCandidateResp{Height: msg.Height, K: self.makeAbout(msg.Better).K,
				M:self.makeAbout(msg.Better).M, Better: msg.Better,
				From: self.Me, Reply:"cnst"}
			miner.server.CommitteeMsg(msg.Better, &d)
		*/
	}
}

func (self *Syncer) run() {
	going := true

	miner.wg.Add(1)
	defer miner.wg.Done()

	ticker := time.NewTicker(time.Second * 4)

	self.repeating = make(chan struct{}, 10)

	for going {
		select {
		case tree := <- self.newtree:
			if self.sigGiven >= 0 {
				continue
			}
			if tree.block != nil {
				log.Infof("newtree %s at %d width %d txs", tree.hash.String(), self.Height, len(tree.block.MsgBlock().Transactions))
			} else {
				log.Infof("newtree %s at %d", tree.hash.String(), self.Height)
			}
			if !self.validateMsg(tree.creator, nil, nil) {
				log.Infof("tree creator %x is not a member of committee", tree.creator)
				continue
			}
			
			if tree.block != nil && 
				len(tree.block.MsgBlock().Transactions) > 1 &&
				len(tree.block.MsgBlock().Transactions[1].TxIn) > 1 &&
				tree.block.MsgBlock().Transactions[1].TxIn[0].SignatureIndex == 0xFFFFFFFF {
				log.Errorf("Incorrect tree. I generated dup tree hash at %d", self.Height)
			}

			if _, ok := self.forest[tree.creator]; !ok || self.forest[tree.creator].block == nil {
				// each creator may submit only one tree
				self.forest[tree.creator] = &tree
			} else if (self.forest[tree.creator].hash != chainhash.Hash{}) && tree.hash != self.forest[tree.creator].hash {
				if self.Me == tree.creator {
					log.Errorf("Incorrect tree. I generated dup tree hash at %d", self.Height)
					break
				}
				self.Malice[tree.creator] = struct {}{}
				delete(self.forest, tree.creator)
				c := self.Members[tree.creator]
				self.knowledges.Malice(c)
			}

			if bytes.Compare(tree.creator[:], self.Me[:]) == 0 {
				k := wire.NewMsgKnowledge()
				k.From = self.Me
				k.Height = self.Height
				k.Finder = self.Me
				k.M = tree.hash
				k.AddK(self.Myself, miner.server.GetPrivKey(self.Me))
				self.messages <- k
			}
			self.print()

		case m := <- self.messages:
			log.Infof("processing %s message at %d", m.Command(), m.Block())
			switch m.(type) {
			case *wire.MsgKnowledge:		// passing knowledge
				if self.sigGiven >= 0 {
					continue
				}

				k := m.(*wire.MsgKnowledge)

				self.knowRevd[self.Members[k.From]] = self.Members[k.From]

				log.Infof("MsgKnowledge: Finder = %x\nFrom = %x\nHeight = %d\nM = %s\nK = [%v]",
					k.Finder, k.From, k.Height, k.M.String(), k.K)
				if !self.validateMsg(k.Finder, &k.M, m) {
					log.Infof("MsgKnowledge invalid")
					continue
				}

				if _, ok := self.forest[k.Finder]; !ok || self.forest[k.Finder].block == nil {
					self.pull(k.M, self.Members[k.Finder])
				}

				if self.knowledges.ProcKnowledge(k) {
					self.candidacy()

					self.mutex.Lock()
					if self.knows[k.Finder] == nil {
						self.knows[k.Finder] = make([]*wire.MsgKnowledge, 0)
					}
					self.knows[k.Finder] = append(self.knows[k.Finder], k)
					self.mutex.Unlock()
				}

			case *wire.MsgKnowledgeDone:
				if self.sigGiven >= 0 {
					continue
				}

				k := m.(*wire.MsgKnowledgeDone)

				if self.knowledges.ProcKnowledgeDone((*wire.MsgKnowledge)(k)) {
					self.candidacy()
				}

			case *wire.MsgCandidate:		// announce candidacy
				k := m.(*wire.MsgCandidate)

				if self.sigGiven >= 0 && self.Names[self.sigGiven] != k.F {
					log.Infof("MsgCandidate declined. sig already given to %d", self.sigGiven)
					continue
				}

				self.candRevd[self.Members[k.F]] = self.Members[k.F]

				log.Infof("MsgCandidate: M = %s\nHeight = %d\nF = %x\nSignature = %x\n",
					k.M.String(), k.Height, k.F, k.Signature)
				if !self.validateMsg(k.F, &k.M, m) {
					log.Infof("Invalid MsgCandidate message")
					continue
				}

				if _, ok := self.forest[k.F]; !ok || self.forest[k.F].block == nil {
					self.pull(k.M, self.Members[k.F])
				}

				self.Candidate(k)

			case *wire.MsgCandidateResp:		// response to candidacy announcement
				if self.sigGiven >= 0 {
					continue
				}

				k := m.(*wire.MsgCandidateResp)
				if !self.validateMsg(k.From, nil, m) {
					continue
				}
				log.Infof("candidateResp: From = %x\nHeight = %d\nM = %s",
					k.From, k.Height, k.M.String())
				self.candidateResp(k)

			case *wire.MsgRelease:			// grant a release from duty
				if self.sigGiven >= 0 {
					continue
				}
				k := m.(*wire.MsgRelease)
				if !self.validateMsg(k.From, nil, m) {
					continue
				}
				log.Infof("MsgRelease: From = %x\nHeight = %d\nM = %s",
					k.From, k.Height, k.M.String())
				self.Release(k)

			case *wire.MsgConsensus:			// announce consensus reached
				if self.sigGiven >= 0 {
					continue
				}
				k := m.(*wire.MsgConsensus)

				if !self.validateMsg(k.From, nil, m) {
					continue
				}

				if _, ok := self.forest[k.From]; !ok || self.forest[k.From].block == nil {
					self.pull(k.M, self.Members[k.From])
				}

				self.consRevd[self.Members[k.From]] = self.Members[k.From]
				self.Consensus(k)
				log.Infof("MsgConsensus: From = %x\nHeight = %d\nM = %s",
					k.From, k.Height, k.M.String())

			case *wire.MsgSignature:		// received signature
				k := m.(*wire.MsgSignature)
				log.Infof("MsgSignature: From = %x\nHeight = %d\nM = %s",
					k.From, k.Height, k.M.String())
				if self.Signature(k) {
					going = false
				}
			}
			for len(self.repeating) > 1 {
				<-self.repeating
			}
//			self.print()

		case <-self.quit:
			going = false

		case <-self.repeating:
			self.repeater()
			for len(self.repeating) > 0 {
				<-self.repeating
			}

		case <-ticker.C:
			self.repeating <- struct{}{}
		}
	}

	ticker.Stop()

	for true {
		select {
		case <-self.newtree:
//		case <- self.messages:
		case m := <- self.messages:
			switch m.(type) {
			case *wire.MsgSignature:
				log.Info("handling MsgSignature on quit")
				self.Signature(m.(*wire.MsgSignature))
			}

		default:
			if self.sigGiven != -1 {
				owner := self.Names[self.sigGiven]
				if self.Runnable && self.forest[owner] != nil && self.forest[owner].block != nil &&
					len(self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
					log.Info("passing NewConsusBlock on quit")
					miner.server.NewConsusBlock(self.forest[owner].block)
				}
			}
			self.Done = true
			self.Runnable = false

			log.Infof("sync %d quit", self.Height)
			return
		}
	}
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
	if tree < 0 || (self.sigGiven != -1 && self.sigGiven != tree) {
		log.Infof("signature ignored, it is for %d (%s), not what I gave %d.", tree, msg.M.String(), self.sigGiven)
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

	self.sigGiven = tree

	self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts = append(
		self.forest[owner].block.MsgBlock().Transactions[0].SignatureScripts,
		msg.Signature[:])
	self.signed[msg.From] = struct{}{}

	return len(self.signed) >= wire.CommitteeSigs
}

func (self *Syncer) Consensus(msg * wire.MsgConsensus) {
	if self.agreed != self.Members[msg.From] {
		return
	}

	// verify signature
	hash := blockchain.MakeMinerSigHash(self.Height, self.forest[msg.From].hash)

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

	privKey := miner.server.GetPrivKey(self.Me)
	if privKey == nil {
		return
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

	log.Infof("Consensus: cast signature")

	self.CommitteeCastMG(&sigmsg)

	if self.sigGiven == -1 {
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
	}
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

		log.Infof("reckconsensus: cast Consensus")

		self.CommitteeCastMG(&msg)
	}
}

func (self *Syncer) ckconsensus() {
	if self.agreed != self.Myself || len(self.agrees) + 1 < wire.CommitteeSigs {
		return
	}

	if self.forest[self.Me] == nil || self.forest[self.Me].block == nil {
		return
	}

	hash := blockchain.MakeMinerSigHash(self.Height, self.forest[self.Me].hash)

	if privKey := miner.server.GetPrivKey(self.Me); privKey != nil && self.sigGiven == -1 {
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

		log.Infof("ckconsensus: cast Consensus")

		self.CommitteeCastMG(&msg)
	}
}

func (self *Syncer) makeRelease(better int32) *wire.MsgRelease {
	d := &wire.MsgRelease{
		Better: better,
		M:      self.forest[self.Names[better]].hash,	//self.makeAbout(better).M,
		Height: self.Height,
		From:   self.Me,
	}
	d.Sign(miner.server.GetPrivKey(self.Me))
	return d
}

func (self *Syncer) dupKnowledge(fmp int32) {
	agreed := self.Names[self.agreed]

	ns := make([]*wire.MsgKnowledge, 0)

	self.mutex.Lock()
	defer self.mutex.Unlock()

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
	self.knows[agreed] = append(self.knows[agreed], ns...)
}

func (self *Syncer) yield(better int32) bool {
	if self.better(better, self.agreed) {
		delete(self.asked, self.Myself)
		rls := self.makeRelease(better)
		for r, _ := range self.agrees {
			rls.Sign(miner.server.GetPrivKey(self.Me))
			self.CommitteeMsgMG(self.Names[r], rls)
		}
		self.agrees = make(map[int32]struct{})
		self.agreed = -1
		if _, ok := self.asked[better]; ok {
			// give a consent to Better
			d := wire.MsgCandidateResp{Height: self.Height, K: []int64{}, From: self.Me}
			d.Reply = "cnst"
			d.Better = better
			d.M = self.forest[self.Names[better]].hash
			self.agreed = better
			d.Sign(miner.server.GetPrivKey(self.Me))

			log.Infof("yield: yield to %x", self.Names[better])

			self.CommitteeMsgMG(self.Names[better], &d)
		}
		return true
	}
	return false
}

func (self *Syncer) candidateResp(msg *wire.MsgCandidateResp) {
	if msg.Reply == "cnst" && self.agreed != -1 {
		if self.agreed != self.Myself {
			// release the node from obligation and notify him about new agreed
			log.Infof("consent received from %x but I am not taking it", msg.From)
			self.CommitteeMsgMG(msg.From, self.makeRelease(self.agreed))
		} else {
			log.Infof("consent received from %x", msg.From)
			self.agrees[self.Members[msg.From]] = struct{}{}
			self.ckconsensus()
		}
	} else if msg.Reply == "rjct" && self.agreed == self.Myself {
		log.Infof("rejection received from %x", msg.From)

		switch msg.Better {
		case -1:
			// reject because not in committee. can't help
			return

		case -2:
			// reject because not Qualified. send knowledge about what I have agreed
			self.dupKnowledge(self.Members[msg.From])
			break

		default:
			t,ok := self.forest[self.Names[msg.Better]]
			if !ok || t.block == nil{
				self.pull(msg.M, msg.Better)
//				self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
				return
			}
			// check if Better is indeed better, if yes, release it (in yield)
			if !self.yield(msg.Better) {
				// no. we are better, send knowledge about it
				self.dupKnowledge(self.Members[msg.From])
				if self.agreed == self.Myself {
					msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)
					msg.Sign(miner.server.GetPrivKey(self.Me))

					log.Infof("candidateResp: reaffirm candidacy")

					self.CommitteeMsgMG(self.Me, msg) // ask again
				}
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
	if (self.agreed != -1 && self.agreed != self.Myself) || !self.knowledges.Qualified(self.Myself) {
		return
	}

	better := self.Myself

	for i := 0; i < wire.CommitteeSize; i++ {
		if _,ok := self.asked[int32(i)]; ok && self.better(int32(i), better) && self.knowledges.Qualified(int32(i)) {
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

	mp := self.Myself
	self.agreed = mp

//	self.consents[self.Me] = 1

	log.Infof("Announce candicacy by %d", self.Myself)
//	self.DebugInfo()

	msg := wire.NewMsgCandidate(self.Height, self.Me, self.forest[self.Me].hash)

	self.asked[self.Myself] = struct{}{}

	msg.Sign(miner.server.GetPrivKey(self.Me))

	log.Infof("candidacy: Announce candicacy")

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

		log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
		return
	}

	self.asked[fmp] = struct{}{}

	if _,ok := self.forest[from]; !ok || self.forest[from].block == nil {
		self.pull(msg.M, fmp)
		return
	}

	if !self.knowledges.Qualified(fmp) {
		d.Reply = "rjct"
		d.Better = -2
		d.Sign(miner.server.GetPrivKey(self.Me))

		log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
		return
	}

	if self.agreed != -1 && self.better(fmp, self.agreed) && self.yield(fmp) {
		return
	}

	if self.agreed == -1 || self.agreed == fmp {
		log.Infof("consent given by %x to %d", self.Me, fmp)
		d.Reply = "cnst"
		d.Better = fmp
		self.agreed = fmp
		d.Sign(miner.server.GetPrivKey(self.Me))

		log.Infof("Candidate: Consent candicacy by %x", self.Names[fmp])

		self.CommitteeMsgMG(self.Names[fmp], &d)
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

	log.Infof("Candidate: Reject candicacy by %x", self.Names[fmp])

	self.CommitteeMsgMG(self.Names[fmp], &d)
}

func CreateSyncer(h int32) *Syncer {
	p := Syncer{}

	p.quit = make(chan struct{})
	p.Height = h
	p.pending = make(map[string][]Message, 0)
	p.newtree = make(chan tree, wire.CommitteeSize * 3)	// will hold trees before runnable
	p.messages = make(chan Message, wire.CommitteeSize * 10)
	p.pulling = make(map[int32]int)
	p.agrees = make(map[int32]struct{})
	p.asked = make(map[int32]struct{})
	p.signed = make(map[[20]byte]struct{})
	p.Members = make(map[[20]byte]int32)
	p.Names = make(map[int32][20]byte)
	p.Malice = make(map[[20]byte]struct {})
	p.knows = make(map[[20]byte][]*wire.MsgKnowledge)

	p.agreed = -1
	p.sigGiven = -1
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
		log.Infof("validate failed. I'm not runnable")
//		time.Sleep(time.Second)
		self.pending[wire.CmdBlock] = append(self.pending[wire.CmdBlock], msg)
		return false
	}

	if _, ok := self.Malice[finder]; ok {
		log.Infof("validate failed. %x is a malice node", finder)
		return false
	}

	c, ok := self.Members[finder]

	if !ok {
		log.Infof("validate failed. %x is a not a member", finder)
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

		log.Infof("Pull block %s from %d", m.String(), c)
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
	self.mutex.Lock()

	if self.Runnable {
		self.mutex.Unlock()
		return
	}

	best := miner.server.BestSnapshot()
	self.Runnable = self.Height == best.Height + 1

	if !self.Runnable {
		self.mutex.Unlock()
		return
	}

	c := int32(best.LastRotation)

	self.Committee = c
	self.Base = c - wire.CommitteeSize + 1

	copy(self.Me[:], miner.name[:])

	in := false

	for i := c - wire.CommitteeSize + 1; i <= c; i++ {
		blk,_ := miner.server.MinerBlockByHeight(i)
		if blk == nil {
			self.mutex.Unlock()
			return
		}

		who := i - (c - wire.CommitteeSize + 1)

		self.Members[blk.MsgBlock().Miner] = who
		self.Names[who] = blk.MsgBlock().Miner

		if bytes.Compare(self.Me[:], blk.MsgBlock().Miner[:]) == 0 {
			self.Myself = who
			in = true
		}
	}

	self.knowledges = CreateKnowledge(self)

	self.mutex.Unlock()

	if in {
		go self.run()
	} else {
		self.Runnable = false
	}

//	miner.updateheight <- self.Height
}

func (self *Syncer) UpdateChainHeight(h int32) {
	if h < self.Height {
		return
	}
	if h > self.Height {
		self.Quit()
		return
	}
	
//	self.SetCommittee()
}

func (self *Syncer) BlockInit(block *btcutil.Block) {
	var adr [20]byte
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
		if txo.TokenType == 0 {
			if eq < 0 {
				eq = txo.Value.(*token.NumToken).Val
			} else if eq != txo.Value.(*token.NumToken).Val {
				return
			}
			fees += eq
		}
	}

	if len(block.MsgBlock().Transactions[0].TxOut) < wire.CommitteeSigs {
		return
	}

	self.SetCommittee()

	log.Infof("syner initialized block %s, sending to newtree", block.Hash().String())

	self.newtree <- tree {
		creator: adr,
		fees: uint64(fees),
		hash: * block.Hash(),
		header: &block.MsgBlock().Header,
		block: block,
	}

	if miner.server.BestSnapshot().Hash != block.MsgBlock().Header.PrevBlock {
		miner.server.ChainSync(block.MsgBlock().Header.PrevBlock, adr)
	}
}

func (self *Syncer) pull(hash chainhash.Hash, from int32) {
	if _,ok := self.pulling[from]; !ok || self.pulling[from] == 0 {
		// pull block
		msg := wire.MsgGetData{InvList: []*wire.InvVect{{common.InvTypeWitnessBlock, hash}}}
		log.Infof("Pull request: to %d hash %s", from+self.Base, hash.String())
		if self.CommitteeMsg(self.Names[from], &msg) {
			log.Infof("Pull request sent to %d", from)
			self.pulling[from] = 5
		} else {
			log.Infof("Fail to Pull !!!!!!!!")
		}
	} else {
		self.pulling[from]--
		log.Infof("Have pulled for %d at height %d", from, self.Height)
	}
}

func (self *Syncer) Quit() {
	log.Info("sync %d quit", self.Height)
	if !self.Runnable {
		return
	}

	for true {
		select {
		case <-self.messages:
		case <-self.newtree:
//		case <-self.quit:
		default:
			self.mutex.Lock()
			close(self.quit)
			self.mutex.Unlock()
			return
		}
	}
}

func (self *Syncer) Debug(w http.ResponseWriter, r *http.Request) {
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
	log.Infof("I am %x, %d", self.Me, self.Myself)
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

	if len(self.signed) > 0 {
		log.Infof("Who has signed for this block (%d):", len(self.signed))
		for m,_ := range self.signed {
			log.Infof("%x", m)
		}
	}

	if len(self.pending) > 0 {
		log.Infof("Pending messages:")
		for _,q := range self.pending {
			for _,m := range q {
				log.Infof("%s", m.(wire.Message).Command())
			}
		}
	}

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
	return l.fees > r.fees || (l.fees == r.fees && left > right)
}

func (self *Syncer) best() int32 {
	var seld *[20]byte
	for left,l := range self.forest {
		if seld == nil {
			seld = new([20]byte)
			copy(seld[:], left[:])
		} else {
			if l.fees > self.forest[*seld].fees ||
				(l.fees == self.forest[*seld].fees && self.Members[left] > self.Members[*seld]) {
				copy(seld[:], left[:])
			}
		}
	}
	if seld == nil {
		return -1
	}
	return self.Members[*seld]
}