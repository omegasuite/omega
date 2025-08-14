// Copyright (C) 2019-2021 Omegasuite developer
// Use of this code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"btcd/blockchain"
	"btcd/connmgr"
	"bytes"
	"github.com/omegasuite/btcd/btcec"
	"math/rand"
	"net"
	"omega/minerchain"
	"time"

	"btcd/wire"
	"btcutil"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
)

const advanceCommitteeConnection = wire.CommitteeSize // # of miner blocks we should prepare for connection
const maxFailedAttempts = 25

// This must be a go routine
func (p *peerState) CommitteeOut(s *committeeState) {
	var msg msgnb
	var ok bool

	next := true

	for {
		if next {
			if msg, ok = <-s.queue; !ok {
				return
			}
		}
		next = true

		sent := false
		for _, sp := range s.peers {
			if !sent && sp.Connected() {
				//				btcdLog.Infof("Send %s msg to %s", msg.msg.Command(), s.address)
				sp.QueueMessageWithEncoding(msg.msg, msg.done, wire.SignatureEncoding)
				sent = true
				s.msgsent++
				break
			}
		}
		if !sent {
			// get a new connections and send it
			s.peers = s.peers[:0]
			p.ForAllPeers(func(sp *serverPeer) {
				if sp.Connected() &&
					(bytes.Compare(sp.Peer.Miner[:], s.member[:]) == 0 ||
						((sp.persistent || !sp.Inbound()) && sp.Peer.Addr() == s.address)) {
					if s.minerHeight > sp.Peer.Committee {
						sp.Peer.Committee = s.minerHeight
					} else {
						s.minerHeight = sp.Peer.Committee
					}
					copy(sp.Peer.Miner[:], s.member[:])

					in := false
					for _, t := range s.peers {
						in = in || (sp.ID() == t.ID())
					}
					if !in {
						s.peers = append(s.peers, sp)
					}
				}
			})
			if len(s.peers) > 0 {
				next = false
			} else {
				tcp, err := net.ResolveTCPAddr("", s.address)
				if err != nil {
					btcdLog.Infof("CommitteeOut: can not resolve %s", s.address)
					if msg.done != nil {
						msg.done <- false
					}
					continue
				}

				btcdLog.Infof("CommitteeOut: make a connection for %s to %s.", msg.msg.Command(), tcp.String())

				s.retry++
				connected := make(chan bool)

				if !s.connecting {
					s.connecting = true
					go p.connManager.Connect(&connmgr.ConnReq{
						Addr:      tcp,
						Permanent: false,
						Committee: s.minerHeight,
						Miner:     s.member,
						Initcallback: func(sp connmgr.ServerPeer) {
							s.connecting = false
							s.peers = append(s.peers, sp.(*serverPeer))
							copy(sp.(*serverPeer).Miner[:], s.member[:])
							close(connected)
						},
					})

					select {
					case <-connected:
						btcdLog.Infof("CommitteeOut: connection established.")
						s.retry = 0
						next = false

					case <-time.After(time.Second * time.Duration(4*(s.retry+1))):
						s.connecting = false
						switch msg.msg.(type) {
						case wire.OmegaMessage:
							msg.msg.(wire.OmegaMessage).SetSeq(rand.Int31())
						}
						protocols[0].Server.Broadcast(msg.msg, nil)
						if msg.done != nil {
							msg.done <- true
						}
					}
				} else {
					time.Sleep(2 * time.Second)
					s.connecting = false
					next = false
				}
			}
		}
	}
}

func (s *server) phaseoutCommittee(r int32) {
	s.peerState.cmutex.Lock()
	for i, p := range s.peerState.committee {
		if p.minerHeight != 0 && p.minerHeight < r {
			delete(s.peerState.committee, i)

			s.peerState.qmutex.Lock()
			p.closed = true
			close(p.queue)
			s.peerState.qmutex.Unlock()
		}
	}
	s.peerState.cmutex.Unlock()
}

func (s *server) MyPlaceInCommittee(r int32) int32 {
	if s.signAddress == nil {
		return 0
	}

	minerTop := s.chain.Miners.BestSnapshot().Height

	for i := r - wire.CommitteeSize + 1; i < r+advanceCommitteeConnection; i++ {
		// scan wire.CommitteeSize records before and after r to determine
		// if we are in the committee
		if i < 0 || i >= minerTop {
			continue
		}

		mb, _ := s.chain.Miners.BlockByHeight(i)
		miner := mb.MsgBlock().Miner
		for _, sa := range s.signAddress {
			if bytes.Compare(miner[:], sa.ScriptAddress()) == 0 {
				in := false
				for _, ip := range s.chainParams.ExternalIPs {
					if ip == string(mb.MsgBlock().Connection) {
						in = true
					}
				}
				if in {
					return i
				}
			}
		}
	}
	return 0
}

func (s *server) BestSnapshot() *blockchain.BestState {
	return s.chain.BestSnapshot()
}

func (s *server) MinerBlockByHeight(n int32) (*wire.MinerBlock, error) {
	return s.chain.Miners.BlockByHeight(n)
}

func (s *server) makeConnection(conn []byte, miner [20]byte, j int32) { //}, me int32) {
	found := false

	s.peerState.cmutex.Lock()
	m, ok := s.peerState.committee[miner]
	if ok {
		np := make([]*serverPeer, 0, len(m.peers))
		for _, r := range m.peers {
			// do they exist?
			exist := false

			s.peerState.forAllPeers(func(sp *serverPeer) {
				if sp.ID() == r.ID() && sp.Connected() {
					exist = true
				}
			})

			if exist {
				np = append(np, r)
			}
		}
		m.peers = np
		if len(m.peers) > 0 {
			s.peerState.cmutex.Unlock()
			return
		}
		if m.minerHeight < j {
			m.minerHeight = j
		}
	} else {
		mb, _ := s.chain.Miners.BlockByHeight(j)
		if bytes.Compare(miner[:], mb.MsgBlock().Miner[:]) != 0 {
			btcdLog.Infof("Error: inconsistent miner %x & height %d in makeConnection", miner, j)
		}

		m = s.peerState.NewCommitteeState(miner, j, string(mb.MsgBlock().Connection))
		s.peerState.committee[miner] = m
	}

	s.peerState.forAllPeers(func(ob *serverPeer) {
		if !found && bytes.Compare(ob.Peer.Miner[:], miner[:]) == 0 && ob.Connected() {
			m.peers = append(m.peers, ob)
			ob.Peer.Committee = j
			found = true
		}
	})
	s.peerState.cmutex.Unlock()

	if found {
		return
	}

	if len(conn) > 0 && len(conn) < 128 {
		// we use 1024-bit RSA pub key, so treat what is less
		// that that as an IP address
		tcp, err := net.ResolveTCPAddr("", string(conn))
		if err != nil {
			return
		}

		isin := false

		addr := tcp.String()
		//		s.peerState.committee[miner].address = addr

		s.peerState.ForAllPeers(func(ob *serverPeer) {
			if !isin && (ob.Addr() == addr || ob.Peer.LocalAddr().String() == addr) && ob.Connected() {
				m.peers = append(m.peers, ob)
				ob.Peer.Committee = j
				copy(ob.Peer.Miner[:], miner[:])

				isin = true
			}
		})

		if isin || len(s.peerState.persistentPeers) > 0 {
			// if we have persistent peers, don't make any connection
			return
		}

		//		if !isin && !m.connecting && len(s.peerState.persistentPeers) == 0 {
		//		if !isin {
		btcdLog.Debugf("makeConnection: new %s", addr)

		if m.connecting {
			return
		}

		m.connecting = true

		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      tcp,
			Permanent: false,
			Committee: j,
			Miner:     miner,
			Initcallback: func(sp connmgr.ServerPeer) {
				m.peers = append(m.peers, sp.(*serverPeer))
				copy(sp.(*serverPeer).Miner[:], m.member[:])
				m.connecting = false
			},
		})
		time.AfterFunc(12*time.Second, func() {
			m.connecting = false
		})
	}
}

var prevMe int32

func (s *server) handleCommitteRotation(r int32) {
	b := s.chain
	best := b.BestSnapshot()

	if uint32(r) < best.LastRotation {
		// if we have more advanced block, ignore this one
		return
	}

	for j := best.LastRotation; j < uint32(r); j++ {
		if mb, _ := b.Miners.BlockByHeight(int32(j)); mb != nil {
			if na, _ := s.addrManager.DeserializeNetAddress(string(mb.MsgBlock().Connection)); na != nil {
				s.addrManager.PhaseoutCommittee(na)
			}
		}
	}

	s.phaseoutCommittee(r - 2*wire.CommitteeSize)

	me := s.MyPlaceInCommittee(r)
	if me == 0 {
		if prevMe != 0 {
			// clean connections
			s.syncManager.ResetConnections(true)
		}
		prevMe = 0
		return
	}

	prevMe = me

	minerTop := s.chain.Miners.BestSnapshot().Height

	// block me is myself, check CommitteeSize miners before and advanceCommitteeConnection
	// miners afetr me to connect to them
	bot := me - wire.CommitteeSize + 1
	if r > me {
		bot = r - wire.CommitteeSize + 1
	}

	for j := bot; j < me+advanceCommitteeConnection; j++ {
		if me == j || j < 0 || j >= minerTop {
			continue
		}

		mb, _ := b.Miners.BlockByHeight(j)
		if mb == nil {
			break
		}

		rc := false
		conn := mb.MsgBlock().Connection
		for _, c := range s.chainParams.ExternalIPs {
			if string(conn) == c {
				rc = true
			}
		}
		if rc {
			continue
		}

		s.peerState.cmutex.Lock()
		_, ok := s.peerState.committee[mb.MsgBlock().Miner]
		s.peerState.cmutex.Unlock()
		if ok {
			continue
		}
		mtch := false
		for _, sa := range s.signAddress {
			if bytes.Compare(mb.MsgBlock().Miner[:], sa.ScriptAddress()) == 0 {
				mtch = true
			}
		}
		if mtch {
			continue
		}

		if _, err := s.chain.CheckCollateral(mb, nil, blockchain.BFNone); !b.IsSVP && err != nil {
			continue
		}

		s.peerState.cmutex.Lock()
		s.peerState.committee[mb.MsgBlock().Miner] =
			s.peerState.NewCommitteeState(mb.MsgBlock().Miner, j, string(mb.MsgBlock().Connection))
		p := s.peerState.peerByName(mb.MsgBlock().Miner[:])

		if p != nil {
			s.peerState.committee[mb.MsgBlock().Miner].peers = append(s.peerState.committee[mb.MsgBlock().Miner].peers, p)
			p.Peer.Committee = j
			s.peerState.cmutex.Unlock()
			continue
		}
		s.peerState.cmutex.Unlock()

		// establish connection
		// check its connection info.
		// if it is an IP address, connect directly,
		// otherwise, broadcast q request for connection msg.
		s.makeConnection(conn, mb.MsgBlock().Miner, j)
	}
}

func (s *server) AddKnownCommittee(id int32, member [20]byte) bool {
	s.peerState.cmutex.Lock()

	m, ok := s.peerState.committee[member]
	s.peerState.cmutex.Unlock()

	if !ok {
		return true
	}

	for _, t := range m.peers {
		if id == t.ID() {
			return true
		}
	}

	added := false

	s.peerState.ForAllPeers(func(sp *serverPeer) {
		if added {
			return
		}
		if sp.Connected() && sp.Peer.ID() == id {
			if m.minerHeight > sp.Peer.Committee {
				sp.Peer.Committee = m.minerHeight
			}
			copy(sp.Peer.Miner[:], member[:])

			m.peers = append(m.peers, sp)
			added = true
		}
	})

	return added
}

func (s *server) CommitteeMsgMG(p [20]byte, h int32, m wire.Message) bool {
	s.peerState.print()

	s.peerState.cmutex.Lock()
	sp, ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok && !sp.closed && len(sp.queue) < 50 {
		sp.queue <- msgnb{m, nil}
		return true
	} else if !ok || sp == nil {
		mb, _ := s.chain.Miners.BlockByHeight(h)
		if mb != nil {
			go s.makeConnection(mb.MsgBlock().Connection, p, h)
		}
	}
	return false
}

func (s *server) ChainSync(h chainhash.Hash, p [20]byte) {
	mlocator, err := s.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
	if err != nil {
		return
	}
	locator, err := s.chain.LatestBlockLocator()
	if err != nil {
		return
	}

	s.peerState.cmutex.Lock()
	sp, ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _, r := range sp.peers {
			if r.Connected() {
				r.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
				return
			}
		}
	}
}

func (s *server) Connected(p [20]byte) bool {
	s.peerState.cmutex.Lock()
	sp, ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _, r := range sp.peers {
			if r.Connected() {
				return true
			}
		}
	}

	return false
}

func (s *server) CommitteeMsg(p [20]byte, h int32, m wire.Message) bool {
	done := make(chan bool)

	s.peerState.cmutex.Lock()
	sp, ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok && !sp.closed && len(sp.queue) < 50 {
		sp.queue <- msgnb{m, done}
	} else if !ok || sp == nil {
		mb, _ := s.chain.Miners.BlockByHeight(h)
		if mb != nil {
			go s.makeConnection(mb.MsgBlock().Connection, p, h)
		}
	}
	return <-done
}

func (s *server) CommitteePolling() {
	if s.signAddress == nil {
		return
	}

	consensusLog.Infof("Connected Peers: %d\nInbound: %s\nOutbound: %d\nPersistent: %d",
		len(s.peerState.inboundPeers)+len(s.peerState.outboundPeers)+len(s.peerState.persistentPeers),
		len(s.peerState.inboundPeers), len(s.peerState.outboundPeers), len(s.peerState.persistentPeers))

	s.peerState.cmutex.Lock()
	for c, p := range s.peerState.committee {
		consensusLog.Infof("Committee member %x has %d connections. Address: %s. %d queued messages", c, len(p.peers), p.address, len(p.queue))
		for _, q := range p.peers {
			consensusLog.Infof("member connections: %d %s %v (local  addr = %s miner=%x)", q.ID(), q.Addr(), q.Connected(), q.LocalAddr().String(), q.Miner)
		}
		consensusLog.Infof("msg sent = %d is connecting: %v retried: %d", p.msgsent, p.connecting, p.retry)
	}
	s.peerState.cmutex.Unlock()
	return
}

func (s *server) SubscribeChain(fn func(*blockchain.Notification)) {
	s.chain.Subscribe(fn)
	s.chain.Miners.Subscribe(fn)
}

func (s *server) NewConsusBlock(m *btcutil.Block) {
	if m == nil {
		s.chain.SendNotification(blockchain.NTBlockConnected, m)
	}
	if m != nil {
		m.ClearSize()
	}
	if isMainchain, orphan, err, _, _ := s.chain.ProcessBlock(m, blockchain.BFNone); err == nil && !orphan && isMainchain {
		consensusLog.Debugf("consensus reached! sigs = %d", len(m.MsgBlock().Transactions[0].SignatureScripts))
	} else {
		s.chain.SendNotification(blockchain.NTBlockRejected, m)
		if err != nil {
			consensusLog.Infof("consensus failed to process ProcessBlock!!! %s", err.Error())
		}
		s.chain.SendNotification(blockchain.NTBlockConnected, (*btcutil.Block)(nil))
	}
}

func (s *server) GetPrivKey(who [20]byte) *btcec.PrivateKey {
	for i, k := range s.signAddress {
		if bytes.Compare(who[:], k.ScriptAddress()) == 0 {
			return protocols[0].cfg.privateKeys[i]
		}
	}
	return nil
}

func (s *peerState) peerByName(name []byte) *serverPeer {
	var p *serverPeer
	s.forAllPeers(func(q *serverPeer) {
		if (p == nil || !p.Connected()) && bytes.Compare(name, q.Miner[:]) == 0 {
			p = q
		}
	})
	return p
}

func (s *peerState) print() {
	return
	/*
		consensusLog.Infof("print Lock")
		s.cmutex.Lock()
		consensusLog.Infof("\npeerState.committee %d:", len(s.committee))
		for i,t := range s.committee {
			srvrLog.Infof("%d => miner = %x conn %s Connected = %d", i, t.Miner, t.String(), t.Connected())
		}
		s.cmutex.Unlock()
		consensusLog.Infof("print Unlock")
	*/

	//	srvrLog.Infof("")
	/*
		srvrLog.Infof("peerState.inboundPeers %d:", len(s.inboundPeers))
		for i,t := range s.inboundPeers {
			srvrLog.Infof("id %d => conn: %s Connected = %d", i, t.String(), t.Connected())
		}

		srvrLog.Infof("peerState.outboundPeers %d:", len(s.outboundPeers))
		for i,t := range s.outboundPeers {
			srvrLog.Infof("id %d => conn: %s Connected = %d", i, t.String(), t.Connected())
		}

	*/
}
