/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package consensus

import (
	"fmt"
	"github.com/omegasuite/btcd/wire"
	"net/http"
	//	"github.com/omegasuite/btcd/btcec"
)

type Knowledgebase struct {
	syncer     *Syncer
	Knowledge  [][]int64 // row = knowledge; col = member; bits = know who knows the fact
	rejections int64     // who has rejected out condidacy announcement
	status     uint      // 0 normal, 1 candidate, 2 consensus, 3 released
}

func (k *Knowledgebase) Malice(c int32) {
	k.Knowledge[c] = make([]int64, wire.CommitteeSize)
}

/*
func (k * Knowledgebase) ProcessTree(t int32) {
	m := k.syncer.Myself
	k.Knowledge[t][m] |= (1 << t) | (1 << m)
	k.Knowledge[t][t] |= (1 << t) | (1 << m)

	nmg := wire.NewMsgKnowledge()	// wire.MsgKnowledge{}
	nmg.AddK(m, miner.server.GetPrivKey(k.syncer.Me))
	nmg.From = k.syncer.Me
	nmg.Finder = k.syncer.Names[t]
	nmg.Height = k.syncer.Height
	nmg.M = k.syncer.forest[nmg.Finder].hash

	for p, q := range k.Knowledge[m] {
		if q & (1 << t) != 0 {
			continue
		}
		if miner.server.CommitteeMsg(k.syncer.Names[int32(p)], int32(p), nmg) {
			k.Knowledge[t][p] |= 1 << t
		}
	}
	k.syncer.candidacy()
}
*/

func CreateKnowledge(s *Syncer) *Knowledgebase {
	var k Knowledgebase
	k = Knowledgebase{s, make([][]int64, wire.CommitteeSize), 0, 0}

	for i := range k.Knowledge {
		k.Knowledge[i] = make([]int64, wire.CommitteeSize)
	}
	return &k
}

func (self *Knowledgebase) print() {
	if self.Knowledge != nil {
		for i, k := range self.Knowledge {
			s := fmt.Sprintf("%d: ", i)
			for _, m := range k {
				s += fmt.Sprintf(" 0x%x ", m)
			}
			log.Infof(s)
		}
	}
}

func (self *Knowledgebase) Rejected(who int32) {
	if who < 0 {
		self.rejections = 0
	} else {
		self.rejections |= 1 << who
	}
}

func (self *Knowledgebase) Insufficient() bool {
	m := wire.CommitteeSize
	for t := self.rejections; t != 0; t >>= 1 {
		if t&1 != 0 {
			m--
			if m < wire.CommitteeSigs {
				return true
			}
		}
	}
	return false
}

func (self *Knowledgebase) Debug(w http.ResponseWriter, r *http.Request) {
	for ii, jj := range self.Knowledge {
		fmt.Fprintf(w, "%d => ", ii)
		for pp, qq := range jj {
			fmt.Fprintf(w, " %d=0x%x ", pp, qq)
		}
		fmt.Fprintf(w, "\n")
	}
}

var Mapping16 = []int{0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4}

func (self *Knowledgebase) Qualified(who int32) bool {
	j := who
	qualified := 0
	rej := ^self.rejections
	if who != self.syncer.Myself {
		rej = ^0
	}

	for i := int32(0); i < wire.CommitteeSize; i++ {
		s := 0
		for k := uint(0); k < 64; k += 4 {
			s += Mapping16[(((self.Knowledge[j][i] & rej) >> k) & 0xF)]
		}
		if s >= wire.CommitteeSigs {
			qualified++
		}
	}

	return qualified >= wire.CommitteeSigs
}

func (self *Knowledgebase) ProcKnowledge(msg *wire.MsgKnowledge) bool {
	//	k := msg.K
	finder := msg.Finder
	mp, ok := self.syncer.Members[finder]
	if !ok {
		return false
	}

	from := msg.From
	if _, ok = self.syncer.Members[from]; !ok {
		return false
	}

	me := self.syncer.Myself

	lmg := *msg

	tosend := false

	if len(lmg.K) < 2 || lmg.K[len(lmg.K)-1] != me {
		lmg.AddK(me, miner.server.GetPrivKey(self.syncer.Me))
		lmg.From = self.syncer.Me
		tosend = true
	}

	ng, res := self.gain(mp, lmg.K)

	for i, q := range self.Knowledge[mp] {
		if int32(i) == me {
			continue
		}
		imp := improve(msg.K, int32(i))
		if tosend && len(lmg.K) < 3*wire.CommitteeSize && ((ng&(1<<i)) != 0 || imp || q == 0) { // || (q&res) != res {
			self.sendout(&lmg, mp, me, int32(i))
		}
	}

	// does he have knowledge about me? In case he is late comer
	if _, ok := self.syncer.forest[self.syncer.Names[me]]; ok && mp != me && self.Knowledge[me][mp]&(0x1<<me) == 0 {
		// send knowledge about me
		lmg := self.syncer.NewKnowledgeMsg()
		self.sendout(lmg, me, me, mp)
	}

	return res != 0
}

/*
func (self *Knowledgebase) ProcKnowledgeDone(msg *wire.MsgKnowledge) bool {
	finder := msg.Finder
	mp := self.syncer.Members[finder]
	from := msg.From

	lmg := *msg
	lmg.K = append(lmg.K, self.syncer.Members[from])

	ng, _ := self.gain(mp, lmg.K)

	return ng
}
*/

func improve(k []int32, to int32) bool {
	newknowledge := make([]int64, wire.CommitteeSize)

	c := int64(0)
	for _, viewer := range k {
		c |= 1 << uint(viewer)
		newknowledge[viewer] = c
	}

	c |= 1 << to

	for i := 0; i < wire.CommitteeSize; i++ {
		if newknowledge[i]&c != 0 && newknowledge[i] != c {
			return true
		}
	}

	return false
}

func (self *Knowledgebase) sendout(msg *wire.MsgKnowledge, mp int32, me int32, q int32) {
	//	log.Infof("sendout %v to %d", msg.K, q)
	self.syncer.CommitteeMsgMG(self.syncer.Names[q], msg)
	/*

			log.Infof("Fail to send knowledge to %d. Knowledge %v about %x", q, msg.K, msg.M)
			return false
		}
			qm := int64((1 << uint(q)) | (1 << uint(me)))
			if (self.Knowledge[mp][me]&qm) != qm || (self.Knowledge[mp][q]&qm) != qm {
				self.Knowledge[mp][me] |= qm
				self.Knowledge[mp][q] |= qm
				return true
			}
		return false
	*/
}

func (self *Knowledgebase) gain(mp int32, k []int32) (int64, int64) {
	ng := int64(0)
	c := int64(0) // 1 << mp
	for _, viewer := range k {
		c |= 1 << uint(viewer)
		if self.Knowledge[mp][viewer]&c != c {
			self.Knowledge[mp][viewer] |= c
			ng |= int64(1 << viewer)
		}
	}
	for _, viewer := range k {
		if self.Knowledge[mp][viewer]&c != c {
			ng |= int64(1 << viewer)
		}
	}

	return ng, c
}
