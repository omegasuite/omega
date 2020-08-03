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
	"fmt"
	"github.com/omegasuite/btcd/wire"
	"net/http"
//	"github.com/omegasuite/btcd/btcec"
)

type Knowledgebase struct {
	syncer *Syncer
	Knowledge [][]int64	// row = knowledge; col = member; bits = know who knows the fact
	rejections int64	// who has rejected out condidacy announcement
	status    uint // 0 normal, 1 candidate, 2 consensus, 3 released
}

func (k * Knowledgebase) Malice(c int32) {
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
	self.rejections |= 1 << who
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

	if qualified >= wire.CommitteeSigs {
			return true
		}

	return false
}

func (self *Knowledgebase) ProcFlatKnowledge(mp int32, k []int64) bool {
	if len(k) == 0 {
		return false
	}
	more := false
	var s int
	s = 0
	if k[0] < 0 {
		s = 1
	}
	for i := s; i < len(k); i++ {
		j := i - s
		if self.Knowledge[mp][j] != k[i] {
			self.Knowledge[mp][j] |= k[i]
			more = true
		}
	}
	return more
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
	lmg.AddK(me, miner.server.GetPrivKey(self.syncer.Me))

	ng, res := self.gain(mp, lmg.K)
	lmg.From = self.syncer.Me

	for i, q := range self.Knowledge[mp] {
		if int32(i) != me && (ng || (res &^ q != 0)) {
			self.syncer.CommitteeMsgMG(self.syncer.Names[int32(i)], &lmg)
		}
	}

	// does he have knowledge about me? In case he is late comer

	if _,ok := self.syncer.forest[self.syncer.Names[me]]; ok && mp != me && self.Knowledge[me][mp] & (0x1 << me) == 0 {
		// send knowledge about me
		lmg := wire.NewMsgKnowledge()
		lmg.From = self.syncer.Names[me]
		lmg.Finder = self.syncer.Names[me]
		lmg.M = self.syncer.forest[self.syncer.Names[me]].hash
		lmg.Height = msg.Height
		lmg.AddK(me, miner.server.GetPrivKey(self.syncer.Me))
		ng = ng || self.sendout(lmg, me, me, mp)
	}

	return ng
}

func (self *Knowledgebase) ProcKnowledgeDone(msg *wire.MsgKnowledge) bool {
//	k := msg.K
	finder := msg.Finder
	mp := self.syncer.Members[finder]
	from := msg.From

	lmg := *msg
	lmg.K = append(lmg.K, self.syncer.Members[from])

	ng, _ := self.gain(mp, lmg.K)

	return ng
}

func (self *Knowledgebase) improve(fact int32, k []int64, to int32) bool {
	newknowledge := false

	m := []int64{}
	m = append(m, k...)
	m = append(m, int64(self.syncer.Myself))
	m = append(m, int64(to))

	c := int64(0)
	for i := 1; i < len(k); i++ {
		viewer := k[i - 1]
		for j := 0; j <= i; j++ {
			c |= 1 << uint(k[j])
		}
		if (self.Knowledge[fact][viewer] & c) != c {
			newknowledge = true
		}
	}
	if (self.Knowledge[fact][k[len(k) - 1]] & c) != c {
		newknowledge = true
	}
	if (self.Knowledge[fact][self.syncer.Myself] & c) != c {
		newknowledge = true
	}

	return newknowledge
}

func (self *Knowledgebase) sendout(msg *wire.MsgKnowledge, mp int32, me int32, q int32) bool {
	if !self.syncer.CommitteeMsg(self.syncer.Names[q], msg) {
		log.Infof("Fail to send knowledge to %d. Knowledge %v about %x", q, msg.K, msg.M)
		// fail to send
		return false
	}

	qm := int64((1<<uint(q)) | (1<<uint(me)))
	if (self.Knowledge[mp][me] & qm) != qm || (self.Knowledge[mp][q] & qm) != qm {
		self.Knowledge[mp][me] |= qm
		self.Knowledge[mp][q] |= qm
		return true
	}
	return false
}

func (self *Knowledgebase) gain(mp int32, k []int32) (bool, int64) {
	newknowledge := false
	c := int64(0)
	for i := 0; i < len(k); i++ {
		viewer := k[i]
		c |= 1 << uint(k[i])
		if self.Knowledge[mp][viewer] & c != c {
			self.Knowledge[mp][viewer] |= c
			newknowledge = true
		}
	}

	return newknowledge, c
}
