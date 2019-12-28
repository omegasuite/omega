package consensus

import (
	"fmt"
	"net/http"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/btcec"
)

type Knowledgebase struct {
	Cfg		  *Config
	committee *Committee
	myself    uint
	Knowledge [][]int64
	status    uint // 0 normal, 1 candidate, 2 consensus, 3 released
}

func (self *Knowledgebase) SetCommittee(c *Committee) {
	self.committee = c
	self.myself = uint(c.P(self.Cfg.Myself))
}

func CreateKnowledge(cfg *Config, c *Committee) *Knowledgebase {
	var k Knowledgebase
	if c == nil {
		k = Knowledgebase{cfg, nil, 0,
		make([][]int64, cfg.CommitteeSize), 0}
	} else {
		k = Knowledgebase{cfg, c,
		uint(c.P(cfg.Myself)), make([][]int64, cfg.CommitteeSize), 0}
	}
	for i := range k.Knowledge {
		k.Knowledge[i] = make([]int64, cfg.CommitteeSize)
	}
	return &k
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

func (self *Knowledgebase) InitKnowledge() {
	if self.committee.In(self.Cfg.Myself) {
		self.myself = uint(self.committee.P(self.Cfg.Myself))
	}
	self.status = 0
	self.Knowledge = make([][]int64, self.committee.CommitteeSize)
	for i := range self.Knowledge {
		self.Knowledge[i] = make([]int64, self.committee.CommitteeSize)
	}
}

var Mapping16 = []int{0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4}

func (self *Knowledgebase) Qualified() bool {
//	for j := int(self.cfg.CommitteeSize) - 1; j >= 0; j-- {
		j := int(self.myself)
		qualified := 0
		leading := false
		for i := 0; i < int(self.committee.CommitteeSize); i++ {
			s := 0
			for k := uint(0); k < 64; k += 4 {
				s += Mapping16[((self.Knowledge[j][i] >> k) & 0xF)]
			}
			if s > int(self.committee.CommitteeSize/2) {
				qualified++
				if i == j {
					leading = true
				}
			}
		}
		if qualified > int(self.committee.CommitteeSize/2) {
			return leading
//			return j == self.committee.P(self.cfg.GetSelf())-1 && leading
		}
//	}
	return false
}

func (self *Knowledgebase) ProcKnowledge(sc *Syncer, msg *MsgKnowledge) int64 {
	if !self.committee.In(self.Cfg.Myself) {
		return -1
	}
	blk := msg.Height

	k := msg.K
	finder := msg.Finder
	from := msg.From
	if !self.committee.In(from) {
		return -1
	}
	mp := self.committee.P(finder)
	if !self.committee.In(from) {
		return -1
	}
	fm := self.committee.P(from)
	me := self.committee.P(self.Cfg.Myself)

	if mp<0 || fm<0 || me<0 {
		return -1
	}
	tmsg := *msg
	tmsg.K = make([]int, 0)
	for _,i := range msg.K {
		signature, err := btcec.ParseSignature(msg.Signatures[i], btcec.S256())
		tmsg.K = append(tmsg.K, i)
		tmsg.From = self.committee.AddrStr[int32(i)]
		p := self.committee.Addresses[int32(i)]
		if err != nil || !signature.Verify(tmsg.DoubleHashB(), p.PubKey()) {
			return -1
		}
	}
	k = append(k, me)
	if self.gain(uint(mp), k, make([][2]uint, 0)) {
		nmg := *msg
		nmg.K = k
		nmg.From = self.Cfg.Myself

		sig, _ := self.Cfg.PrivKey.Sign(nmg.DoubleHashB())
		nmg.Signatures[me] = sig.Serialize()

		for ii, p := range self.committee.Pool {
			if ii - self.committee.Start == int32(me) || ii - self.committee.Start == int32(fm) {
				continue
			}
			q := ii		// (self.committee.P(j) - 1)
			go self.sendout(sc, p, &nmg, mp, blk, me, q)
		}

		return int64(blk)
	}
	return -1
}

func (self *Knowledgebase) sendout(sc *Syncer, client * peer.Peer, msg *MsgKnowledge, mp int, blk int32, me int, q int32) {
	done := make(chan struct{})
	client.QueueMessage(msg, done)
	_ = <-done

	qm := int64((1<<uint(q)) | (1<<uint(me)))
	if (self.Knowledge[mp][me] & qm) != qm || (self.Knowledge[mp][q] & qm) != qm {
		self.Knowledge[mp][me] |= qm
		self.Knowledge[mp][q] |= qm
		sc.candidacy(int64(blk))
	}
}
func (self *Knowledgebase) gain(mp uint, k []int, extra [][2]uint) bool {
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

	return newknowledge
}
