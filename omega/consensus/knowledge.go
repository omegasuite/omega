package consensus

import (
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"net/http"
//	"github.com/btcsuite/btcd/btcec"
)

type Knowledgebase struct {
	syncer *Syncer
	Knowledge [][]int64	// row = knowledge; col = member; bits = know who knows the fact
	status    uint // 0 normal, 1 candidate, 2 consensus, 3 released
}

func (k * Knowledgebase) Malice(c int32) {
	k.Knowledge[c] = make([]int64, wire.CommitteeSize)
}

func (k * Knowledgebase) ProcessTree(t int32) {
	m := k.syncer.Myself
	k.Knowledge[t][m] |= (1 << t) | (1 << m)
	k.Knowledge[t][t] |= (1 << t) | (1 << m)

	nmg := wire.MsgKnowledge{}
	nmg.K = []int64{int64(t), int64(m)}
	nmg.From = k.syncer.Me
	nmg.Finder = k.syncer.Names[t]
	nmg.Height = k.syncer.Height
	nmg.M = k.syncer.forest[nmg.Finder].hash

	for p, q := range k.Knowledge[m] {
		if q & (1 << t) != 0 {
			continue
		}
		if miner.server.CommitteeMsg(int32(p) + k.syncer.Base, &nmg) {
			k.Knowledge[t][p] |= 1 << t
		}
	}
	k.syncer.candidacy()
}

func CreateKnowledge(s *Syncer) *Knowledgebase {
	var k Knowledgebase
	k = Knowledgebase{s, make([][]int64, wire.CommitteeSize), 0}

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
//	for j := int(self.cfg.CommitteeSize) - 1; j >= 0; j-- {
		j := who
		qualified := 0
//		leading := false
		for i := int32(0); i < wire.CommitteeSize; i++ {
			s := 0
			for k := uint(0); k < 64; k += 4 {
				s += Mapping16[((self.Knowledge[j][i] >> k) & 0xF)]
			}
			if s > int(wire.CommitteeSize/2) {
				qualified++
//				if i == j {
//					leading = true
//				}
			}
		}
		if qualified > int(wire.CommitteeSize/2) {
			return true
//			return j == self.committee.P(self.cfg.GetSelf())-1 && leading
		}
//	}
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
	k := msg.K
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

	if k[0] < 0 {
		return self.ProcFlatKnowledge(mp, k[1:])
	}

/*
	tmsg := *msg
	tmsg.K = make([]int64, 0)

	for _,i := range msg.K {
		signature, err := btcec.ParseSignature(msg.Signatures[i], btcec.S256())
		tmsg.K = append(tmsg.K, i)
		tmsg.From = self.committee.AddrStr[int32(i)]
		p := self.committee.Addresses[int32(i)]
		if err != nil || !signature.Verify(tmsg.DoubleHashB(), p.PubKey()) {
			return -1
		}
	}
*/
	k = append(k, int64(me))
	res := false
	if self.gain(mp, k, nil) {
		nmg := *msg
		nmg.K = k
		nmg.From = self.syncer.Me

		miner.server.CommitteeCastMG(me, &nmg, self.syncer.Height)
		self.syncer.candidacy()

//		miner.server.CommitteeCast(me, &nmg)

//		sig, _ := self.Cfg.PrivKey.Sign(nmg.DoubleHashB())
//		nmg.Signatures[me] = sig.Serialize()
/*
		for _, p := range self.syncer.Members {
			if p == me {
				continue
			}
			go self.sendout(&nmg, mp, me, p)
		}
*/
		res = true
	}

	// does he have knowledge about me? In case he is late comer
	if _,ok := self.syncer.forest[self.syncer.Names[me]]; ok && self.Knowledge[me][mp] & (0x1 << me) == 0 {
		// send knowledge about me
		lmg := wire.MsgKnowledge{
			From: self.syncer.Names[me],
			Finder: self.syncer.Names[me],
			M: self.syncer.forest[self.syncer.Names[me]].hash,
			K: []int64{int64(me), int64(me)},
			Height: msg.Height,
		}
		self.sendout(&lmg, me, me, mp)
	}
	return res
}

func (self *Knowledgebase) sendout(msg *wire.MsgKnowledge, mp int32, me int32, q int32) {
	if !miner.server.CommitteeMsg(q + self.syncer.Base, msg) {
		log.Infof("Fail to send knowledge to %d. Knowledge %v about %x", q, msg.K, msg.M)
		// fail to send
		return
	}

	qm := int64((1<<uint(q)) | (1<<uint(me)))
	if (self.Knowledge[mp][me] & qm) != qm || (self.Knowledge[mp][q] & qm) != qm {
		self.Knowledge[mp][me] |= qm
		self.Knowledge[mp][q] |= qm
		self.syncer.candidacy()
	}
}

func (self *Knowledgebase) gain(mp int32, k []int64, extra [][2]uint) bool {
	newknowledge := false

	for i := 0; i < len(k); i++ {
		viewer := k[i]
		c := int64(0)
		for j := 0; j <= i; j++ {
			c |= 1 << uint(k[j])
		}
		if (self.Knowledge[mp][viewer] & c) != c {
			newknowledge = true
			self.Knowledge[mp][viewer] |= c
		}
		if i > 0 && self.Knowledge[mp][k[i-1]]&(1<<uint(viewer)) == 0 {
			newknowledge = true
			self.Knowledge[mp][k[i-1]] |= (1 << uint(viewer))
		}
	}

	log.Infof("gain = %d", newknowledge)

	return newknowledge
}
