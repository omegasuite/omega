package consensus

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcutil"
)

type Committee struct {
	CommitteeSize int32
	Pool		  map[int32]*peer.Peer
	Addresses	  map[int32]btcutil.AddressPubKey
	AddrStr		  map[int32][20]byte
	Start		  int32
	Iamin		  bool
	Myself		  [20]byte
}

var WaitCommittee = make(chan bool, 50)

func NewCommittee(size int32, me [20]byte) * Committee {
	c := Committee{CommitteeSize:size, Iamin:false, Pool:make(map[int32]*peer.Peer),
			Addresses:make(map[int32]btcutil.AddressPubKey), Myself:me, AddrStr:make(map[int32][20]byte)}
	return &c
}

func (sp *Committee) PubKey(adr *[20]byte) * btcutil.AddressPubKey {
	for i, j := range sp.AddrStr {
		if j == *adr {
			a := sp.Addresses[i]
			return &a
		}
	}
	return nil
}

func (sp *Committee) JoinCommittee(p *peer.Peer, addr *btcutil.AddressPubKey, i int32) {
	sp.Pool[i] = p
	sp.Addresses[i] = *addr
	sp.AddrStr[i] = *addr.AddressPubKeyHash().Hash160()
	if sp.Iamin && sp.AddrStr[i] == sp.Myself {
		sp.Iamin = true
	}
}

func (self *Committee) Debug(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "CommitteeSize = %d\n", self.CommitteeSize)
	for _, a := range self.Pool {
		fmt.Fprintf(w, "%s ", a)
	}
	fmt.Fprintf(w, "\n")
}

func (self *Committee) P(x [20]byte) int {
	for i := int32(0); i < self.CommitteeSize; i++ {
		if x == self.AddrStr[i + self.Start] {
			return int(i)
		}
	}
	return -1
}

var WaitCommitteeCnt = int32(0)

func (self *Committee) Rotate() {
	self.Start++
	for i := range self.Addresses {
		if i < self.Start {
			if self.Iamin {
				v, ok := self.AddrStr[i]
				if ok && v == self.Myself {
					self.Iamin = false
				}
			}
			delete(self.Addresses, i)
			delete(self.Pool, i)
			delete(self.AddrStr, i)
		}
	}
	v, ok := self.AddrStr[self.Start + self.CommitteeSize - 1]
	if ok && v == self.Myself {
		self.Iamin = true
	}
	atomic.AddInt32(&WaitCommitteeCnt, 1)
	WaitCommittee <- true
}

func (self *Committee) In(n [20]byte) bool {
	for i := range self.AddrStr {
		if self.AddrStr[i] == n {
			return true
		}
	}
	return false
}
