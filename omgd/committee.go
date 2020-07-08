// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2018 The Decred develserver.dbopers
// Use of this sogetminerblockurce code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/connmgr"
	"github.com/omegasuite/omega/minerchain"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/peer"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
)

const advanceCommitteeConnection = wire.CommitteeSize	// # of miner blocks we should prepare for connection

type retryQ struct {
	sp * serverPeer
	start int
	end	  int
	size  int
	items []wire.Message
}

var retry = make(map[uint64]*retryQ)
var retryMutex sync.Mutex

// this must be a go routing starting at the same time as consensus
func (s* server) trying() {
	for true {
		time.Sleep(time.Second * 2)
		if len(retry) != 0 {
			height := s.chain.BestSnapshot().Height
			retryMutex.Lock()
			for h,q := range retry {
				if int32(h) <= height {
					delete(retry, h)
				} else {
					m := q.items[q.start]
					q.start = (q.start + 1) % q.size

					done := make(chan bool)
					q.sp.QueueMessageWithEncoding(m, done, wire.SignatureEncoding)
					r := <- done

					if !r {
						q.items[q.end] = m
						q.end = (q.end + 1) % q.size
					} else if q.start == q.end {
						delete(retry, h)
					}
				}
			}
			retryMutex.Unlock()
		}
	}
}

func senNewMsg(sp * serverPeer, msg wire.Message, h int32) {
	done := make(chan bool)
	sp.QueueMessageWithEncoding(msg, done, wire.SignatureEncoding)
	r := <- done
	if !r {
		retryMutex.Lock()
		m := (uint64(sp.ID()) << 32) | uint64(h)
		if _, ok := retry[m]; !ok {
			retry[m] = &retryQ{
				sp: sp, start: 0, end: 0, size: 10,
				items: make([]wire.Message, 10),
			}
		}
		q := retry[m]
		if (q.end + 1) % q.size == q.start { // grow queue size by double it
			bdl := make([]wire.Message, 2 * q.size)
			if q.end > q.start {
				copy(bdl[q.start:], q.items[q.start:q.end])
			} else {
				copy(bdl[q.start:], q.items[q.start:])
				if q.end > 0 {
					copy(bdl[q.size:], q.items[:q.end])
				}
				q.end += q.size
			}
			q.items = bdl
			q.size *= 2
		}
		q.items[q.end] = msg
		q.end = (q.end + 1) % q.size
		retryMutex.Unlock()
	}
}

func (ps *peerState) forAllCommittee(closure func(name [20]byte, sp *committeeState)) {
//	btcdLog.Infof("cmutex.Lock @ forAllCommittee")
	ps.cmutex.Lock()
	for i, e := range ps.committee {
		closure(i, e)
	}
//	btcdLog.Infof("cmutex.Unlock")
	ps.cmutex.Unlock()
}

func (sp *serverPeer) OnAckInvitation(_ *peer.Peer, msg *wire.MsgAckInvitation) {
	sp.server.peerState.print()

	if (sp.server.chain.BestSnapshot().LastRotation > uint32(msg.Invitation.Height)+wire.CommitteeSize) ||
		(sp.server.chain.BestSnapshot().LastRotation+advanceCommitteeConnection < uint32(msg.Invitation.Height)) {
		// expired or too early for me
		return
	}

	k, err := btcec.ParsePubKey(msg.Invitation.Pubkey[:], btcec.S256())
	if err != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (1) %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	mb, err := sp.server.chain.Miners.BlockByHeight(msg.Invitation.Height)
	if err != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (2) %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}
	if sp.server.chain.CheckCollateral(mb, blockchain.BFNone) != nil {
		return
	}

	// check signature
	pk, _ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
	pk.SetFormat(btcutil.PKFUncompressed)
	pkh1 := pk.AddressPubKeyHash().ScriptAddress()
	pk.SetFormat(btcutil.PKFCompressed)
	pkh2 := pk.AddressPubKeyHash().ScriptAddress()
//	pkhc := pk.AddressPubKeyHash().Hash160()

	if bytes.Compare(pkh1[:], mb.MsgBlock().Miner[:]) != 0 &&
		bytes.Compare(pkh2[:], mb.MsgBlock().Miner[:]) != 0 {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (3) %s miner = %x pkh1 = %x pkh2 = %x at %d", sp.Addr(),
			mb.MsgBlock().Miner, pkh1, pkh2, msg.Invitation.Height)
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	s, err := btcec.ParseSignature(msg.Sig, btcec.S256())
	if err != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (4) %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	var w bytes.Buffer
	if msg.Invitation.Serialize(&w) != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (5) %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	hash := chainhash.DoubleHashB(w.Bytes())
	if !s.Verify(hash, pk.PubKey()) {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv (6) %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	// have we already connected to it?
/*
	refused := false
	sp.server.peerState.forAllPeers(func(ob * serverPeer) {
		if sp != ob && bytes.Compare(ob.Peer.Miner[:], mb.MsgBlock().Miner[:]) == 0 {
			// refuse by disconnect
			refused = true
		}
	})
	if refused {
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
		return
	}
 */

	sp.server.peerState.cmutex.Lock()
	if sp.server.peerState.committee[mb.MsgBlock().Miner] == nil {
		sp.server.peerState.committee[mb.MsgBlock().Miner] = &committeeState{ peers: make([]*serverPeer, 0) }
	}
	m := sp.server.peerState.committee[mb.MsgBlock().Miner]
	sp.server.peerState.cmutex.Unlock()

	m.peers = append(m.peers, sp)
	if m.bestBlock < sp.LastBlock() {
		m.bestBlock = sp.LastBlock()
		if m.lastBlockSent < m.bestBlock {
			m.lastBlockSent = m.bestBlock
		}
	}
	if m.bestMinerBlock < sp.LastMinerBlock() {
		m.bestMinerBlock = sp.LastMinerBlock()
		if m.lastMinerBlockSent < m.bestMinerBlock {
			m.lastMinerBlockSent = m.bestMinerBlock
		}
	}

	consensusLog.Infof("AckInv. %d = %x", msg.Invitation.Height, mb.MsgBlock().Miner)

	sp.Peer.Committee = msg.Invitation.Height
	copy(sp.Peer.Miner[:], mb.MsgBlock().Miner[:])
}

func (s *server) SendInvAck(peer [20]byte, sp *serverPeer) {
	if s.signAddress == nil {
		return
	}

	// send an acknowledgement so the peer knows we are too
	me := s.MyPlaceInCommittee(int32(s.chain.BestSnapshot().LastRotation))
	if me == 0 {	// should never happen
		return
	}

	srvrLog.Infof("SendInvAck to %x", peer)
	pinv, adr := s.makeInvitation(me, s.signAddress.ScriptAddress())

	var w bytes.Buffer

	if pinv != nil && adr != nil {
		pinv.Serialize(&w)
		hash := chainhash.DoubleHashH(w.Bytes())

		if sig, err := s.privKeys.Sign(hash[:]); err == nil {
			ackmsg := wire.MsgAckInvitation{ }
			ackmsg.Sig = sig.Serialize()
			ackmsg.Invitation = *pinv

			sp.Peer.QueueMessage(&ackmsg, nil)
		}
	}
}

func (sp *serverPeer) OnInvitation(_ *peer.Peer, msg *wire.MsgInvitation) {
	sp.server.peerState.print()

	// 1. check if the message has expired or too far out, if yes, do nothing
	if sp.server.chain.BestSnapshot().LastRotation > msg.Expire || msg.Expire - sp.server.chain.BestSnapshot().LastRotation > 5 * wire.CommitteeSize {
		return
	}

	srvrLog.Infof("OnInvitation of %s", sp.Peer.String())

	// 2. check if we are invited, if yes take it by connecting to the peer
	// decode the message
	// try to decode the message with my RSA priv key
	if sp.server.rsaPrivateKey != nil {
		m, err := rsa.DecryptOAEP(sha256.New(), nil, sp.server.rsaPrivateKey, msg.Msg, []byte("invitation"))
		if err == nil {
			// this mesage is for me
			inv := wire.Invitation{}
			inv.Deserialize(bytes.NewReader(m))

			if (sp.server.chain.BestSnapshot().LastRotation > uint32(inv.Height)+wire.CommitteeSize) ||
				(sp.server.chain.BestSnapshot().LastRotation+advanceCommitteeConnection < uint32(inv.Height)) {
				// expired or too early for me
				return
			}

			k, err := btcec.ParsePubKey(inv.Pubkey[:], btcec.S256())
			if err != nil {
				return
			}

			mb, err := sp.server.chain.Miners.BlockByHeight(inv.Height)
			if err != nil {
				return
			}

			// check signature
			pk, _ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
			pkh := pk.AddressPubKeyHash().Hash160()

			if bytes.Compare(pkh[:], mb.MsgBlock().Miner[:]) != 0 {
				return
			}

			s, err := btcec.ParseSignature(msg.Sig, btcec.S256())
			if err != nil {
				return
			}

			var w bytes.Buffer
			if inv.Serialize(&w) != nil {
				return
			}

			hash := chainhash.DoubleHashB(w.Bytes())
			if !s.Verify(hash, pk.PubKey()) {
				return
			}

			// now it is confirmed that the it is a member of (prospective) committee
			tcp, err := net.ResolveTCPAddr("", string(inv.IP))
			if err != nil {
				// not a valid address. should have validated before
				return
			}

			isin := false

			sp.server.peerState.cmutex.Lock()
			if _, ok := sp.server.peerState.committee[mb.MsgBlock().Miner]; !ok {
				sp.server.peerState.committee[mb.MsgBlock().Miner] = newCommitteeState()
			}
			m := sp.server.peerState.committee[mb.MsgBlock().Miner]
			sp.server.peerState.cmutex.Unlock()

			for _, p := range m.peers {
				if p.Connected() {
					sp.server.SendInvAck(mb.MsgBlock().Miner, p)
					return
				}
			}

			sp.server.peerState.forAllPeers(func(ob *serverPeer) {
				if !isin && ob.Addr() == tcp.String() {
					m.peers = append(m.peers, ob)

					ob.Peer.Committee = inv.Height
					copy(ob.Peer.Miner[:], mb.MsgBlock().Miner[:])

					sp.server.SendInvAck(mb.MsgBlock().Miner, ob)

					isin = true
				}
			})

			if !isin {
				var callback = func (q connmgr.ServerPeer) {
					p := q.(*serverPeer)
					m.peers = append(m.peers, p)

					p.Peer.Committee = inv.Height
					copy(p.Peer.Miner[:], mb.MsgBlock().Miner[:])

					sp.server.SendInvAck(mb.MsgBlock().Miner, p)
				}

//				go sp.server.makeConnection(tcp.String(), miner, )

				go sp.server.connManager.Connect(&connmgr.ConnReq{
					Addr:      tcp,
					Permanent: false,
					Committee: inv.Height,
					Miner: mb.MsgBlock().Miner,
					Initcallback: callback,
				})
			}
			return
		}
	}

	// 3. if not, check if the message is in inventory, if yes, ignore it
	mh := msg.Hash()
	mt := time.Now().Unix()
	if _, ok := sp.server.Broadcasted[mh]; ok {
		sp.server.Broadcasted[mh] = mt + 300
		return
	}

	// 4. otherwise, broadcast it
	// remove expired inventory
	for i, t := range sp.server.Broadcasted {
		if time.Now().Unix() > t {
			delete(sp.server.Broadcasted, i)
		}
	}

	// inventory expires 5 minutes
	sp.server.Broadcasted[mh] = time.Now().Unix() + 300

	sp.server.BroadcastMessage(msg, sp)
//	sp.server.broadcast <- broadcastMsg{msg, []*serverPeer{sp} }
}

func (s *server) phaseoutCommittee(r int32) {
	b := s.chain

	keep := make(map[[20]byte]struct{})
	for j := r; j < r + advanceCommitteeConnection + wire.CommitteeSize; j++ {
		mb, _ := b.Miners.BlockByHeight(j)
		if mb != nil {
			keep[mb.MsgBlock().Miner] = struct{}{}
		} else {
			break
		}
	}

	s.peerState.cmutex.Lock()
	for i, _ := range s.peerState.committee {
		if _, ok := keep[i]; !ok {
			for _, sp := range s.peerState.committee[i].peers {
				sp.Committee = -1
				sp.Peer.Committee = -1
			}
			delete(s.peerState.committee, i)
		}
	}
	s.peerState.cmutex.Unlock()
}

func (s *server) MyPlaceInCommittee(r int32) int32 {
	if s.signAddress == nil {
		return 0
	}

	minerTop := s.chain.Miners.BestSnapshot().Height

	for i := r - wire.CommitteeSize + 1; i < r + advanceCommitteeConnection; i++ {
		// scan wire.CommitteeSize records before and after r to determine
		// if we are in the committee
		if i < 0 || i >= minerTop {
			continue
		}

		mb, _ := s.chain.Miners.BlockByHeight(i)
		miner := mb.MsgBlock().Miner
		if bytes.Compare(miner[:], s.signAddress.ScriptAddress()) == 0 {
			return i
		}
	}
	return 0
}

func (s * server) makeInvitation(me int32, miner []byte) (* wire.Invitation, * btcutil.Address) {
	if s.signAddress == nil {
		return nil, nil
	}

	inv := wire.Invitation{
		Height: me,
	}

	if bytes.Compare(miner, s.signAddress.ScriptAddress()) != 0 {
		return nil, nil
	}

	pk := s.privKeys.PubKey()

	copy(inv.Pubkey[:], pk.SerializeCompressed())
//	copy(inv.Pubkey[:], s.privKeys.PubKey().SerializeUncompressed())
	inv.IP = []byte(cfg.ExternalIPs[0])
	return &inv, &s.signAddress
}

func (s * server) makeInvitationMsg(me int32, miner []byte, conn []byte) * wire.MsgInvitation {
	s.peerState.print()

	inv,_ := s.makeInvitation(me, miner)
	if inv == nil {
		return nil
	}

	m := wire.MsgInvitation{
		Expire: uint32(me) + wire.CommitteeSize + uint32(randomUint16Number(10)),
	}

	copy(m.To[:], miner)
	var w bytes.Buffer

	if inv != nil {
		inv.Serialize(&w)
		hash := chainhash.DoubleHashH(w.Bytes())

		if sig, err := s.privKeys.Sign(hash[:]); err == nil {
			m.Sig = sig.Serialize()
		}
	}
	if m.Sig == nil {
		return nil
	}

	var pubkey rsa.PublicKey
	var err error
	type RSA struct {
		N []byte         `json:"n"`
		E int            `json:"e"`
	}
	var r RSA

	if json.Unmarshal(conn, &r) == nil {
		pubkey.N = big.NewInt(0).SetBytes(r.N)
		pubkey.E = r.E
	} else {
		return nil
	}

	m.Msg, err = rsa.EncryptOAEP(sha256.New(), nil, &pubkey, w.Bytes(), []byte("invitation"))
	if err != nil {
		return nil
	}
	return &m
}

func (s *server) BestSnapshot() * blockchain.BestState {
	return s.chain.BestSnapshot()
}

func (s *server) MinerBlockByHeight(n int32) (* wire.MinerBlock,error) {
	return s.chain.Miners.BlockByHeight(n)
}

func (s *server) makeConnection(conn []byte, miner [20]byte, j, me int32) {
	if _, ok := s.peerState.committee[miner]; ok {
		np := make([]*serverPeer, 0, len(s.peerState.committee[miner].peers))
		for _,r := range s.peerState.committee[miner].peers {
			// do they exist?
			exist := false

//			btcdLog.Infof("cmutex.Unlock")
			s.peerState.cmutex.Unlock()
			s.peerState.forAllPeers(func (sp * serverPeer) {
				if sp.ID() == r.ID() {
					exist = true
				}
			})
//			btcdLog.Infof("cmutex.Lock")
			s.peerState.cmutex.Lock()

			if exist {
				np = append(np, r)
			}
		}
		s.peerState.committee[miner].peers = np
		if len(s.peerState.committee[miner].peers) > 0 {
			return
		}
	} else {
		s.peerState.committee[miner] = newCommitteeState()
	}
	m := s.peerState.committee[miner]

	found := false
//	btcdLog.Infof("cmutex.Unlock")
	s.peerState.cmutex.Unlock()
	s.peerState.forAllPeers(func(ob *serverPeer) {
		if bytes.Compare(ob.Peer.Miner[:], miner[:]) == 0 {
			m.peers = append(m.peers, ob)
			ob.Peer.Committee = j
			found = true
			return
		}
	})
//	btcdLog.Infof("cmutex.Lock")
	s.peerState.cmutex.Lock()

	if found {
		return
	}

	if len(conn) > 0 && len(conn) < 128 {
		// we use 1024-bit RSA pub key, so treat what is less
		// that that as an IP address
		tcp, err := net.ResolveTCPAddr("", string(conn))
		if err != nil {
			// not a valid address. should have validated before
			return
		}

		isin := false
//		btcdLog.Infof("cmutex.Unlock")
		s.peerState.cmutex.Unlock()
		s.peerState.forAllOutboundPeers(func (ob *serverPeer) {
			if !isin && ob.Addr() == tcp.String() {
				m.peers = append(m.peers, ob)

				ob.Peer.Committee = j
				copy(ob.Peer.Miner[:], miner[:])

				isin = true
				s.SendInvAck(miner, ob)
			}
		})
//		btcdLog.Infof("cmutex.Lock")
		s.peerState.cmutex.Lock()

		if !isin {
			addr := tcp.String()
/*
			for _,adr := range cfg.ConnectPeers {
				if adr == addr {
					// leave it for connmgr
					return
				}
			}
 */

			btcdLog.Infof("makeConnection: new %s", addr)

//		if !isin || !s.peerState.committee[j].Peer.Connected() {
			go s.connManager.Connect(&connmgr.ConnReq{
				Addr:      tcp,
				Permanent: false,
				Committee: j,
				Miner: miner,
				Initcallback: func(sp connmgr.ServerPeer) { s.SendInvAck(miner, sp.(*serverPeer)) },
			})
		}
	} else if len(cfg.ExternalIPs) == 0 {
		return
	} else if m := s.makeInvitationMsg(me, miner[:], conn); m != nil {
		s.BroadcastMessage(m)
//		s.broadcast <- broadcastMsg { message: m}
	}
}

func (s *server) handleCommitteRotation(state *peerState, r int32) {
//	consensusLog.Infof("handleCommitteRotation at %d", r)
//	s.peerState.print()

	b := s.chain

	if uint32(r) < b.BestSnapshot().LastRotation {
		// if we have more advanced block, ignore this one
		return
	}

	s.phaseoutCommittee(r)
	me := s.MyPlaceInCommittee(r)
	if me == 0 {
		return
	}

	minerTop := s.chain.Miners.BestSnapshot().Height

	// block me is myself, check CommitteeSize miners before and advanceCommitteeConnection
	// miners afetr me to connect to them
	bot := me - wire.CommitteeSize + 1
	if r > me {
		bot = r - wire.CommitteeSize + 1
	}

	s.peerState.cmutex.Lock()
	for j := bot; j < me + advanceCommitteeConnection; j++ {
		if me == j || j < 0 || j >= minerTop {
			continue
		}

		mb,_ := b.Miners.BlockByHeight(j)
		if mb == nil {
			break
		}

		if s.chain.CheckCollateral(mb, blockchain.BFNone) != nil {
			continue
		}

		if _, ok := state.committee[mb.MsgBlock().Miner]; !ok {
			state.committee[mb.MsgBlock().Miner] = newCommitteeState()
		}

		s.peerState.cmutex.Unlock()
		p := s.peerState.peerByName(mb.MsgBlock().Miner[:])
		s.peerState.cmutex.Lock()

		if p != nil {
			hasp := false
			for _,q := range state.committee[mb.MsgBlock().Miner].peers {
				if q == p {
					hasp = true
				}
			}
			if !hasp {
				state.committee[mb.MsgBlock().Miner].peers = append(state.committee[mb.MsgBlock().Miner].peers, p)
			}
			p.Peer.Committee = j
			s.SendInvAck(mb.MsgBlock().Miner, p)
			continue
		}

		// establish connection
		// check its connection info.
		// if it is an IP address, connect directly,
		// otherwise, broadcast q request for connection msg.
		conn := mb.MsgBlock().Connection
		s.makeConnection(conn, mb.MsgBlock().Miner, j, me)
	}

	s.peerState.cmutex.Unlock()
}

func (s *server) CommitteeMsgMG(p [20]byte, m wire.Message, h int32) {
	s.peerState.print()

	s.peerState.cmutex.Lock()
	sp,ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _,r := range sp.peers {
			if r.Connected() {
				srvrLog.Infof("sending it to %s (remote = %s)", r.Peer.LocalAddr().String(), r.Peer.Addr())
				senNewMsg(r, m, h)
				return
			}
		}
		consensusLog.Infof("Failed to find a useful connection")
	} else {
		consensusLog.Infof("Failed to find a useful connection")
	}
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
	sp,ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _,r := range sp.peers {
			if r.Connected() {
				r.PushGetBlocksMsg(locator, mlocator, &zeroHash, &zeroHash)
				return
			}
		}
	}
}

func (s *server) CommitteeMsg(p [20]byte, m wire.Message) bool {
	done := make(chan bool)

	s.peerState.cmutex.Lock()
	sp,ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _,r := range sp.peers {
			if r.Connected() {
				srvrLog.Infof("sending it to %s (remote = %s)", r.Peer.LocalAddr().String(), r.Peer.Addr())
				r.QueueMessageWithEncoding(m, done, wire.SignatureEncoding)
				return <-done
			}
		}
	} else {
		best := s.chain.BestSnapshot()
		my := s.MyPlaceInCommittee(int32(best.LastRotation))
		for i := 0; i < wire.CommitteeSize; i++ {
			blk, _ := s.chain.Miners.BlockByHeight(int32(best.LastRotation) - int32(i))
			if blk == nil || bytes.Compare(blk.MsgBlock().Miner[:], p[:]) != 0{
				continue
			}
			s.peerState.cmutex.Lock()
			s.makeConnection(blk.MsgBlock().Connection, p, blk.Height(), my)
			s.peerState.cmutex.Unlock()
			return false
		}
	}

	return false
}

func (s *server) CommitteePolling() {
	if s.signAddress == nil {
		return
	}

	best := s.chain.BestSnapshot()
	ht := best.Height
	mht := s.chain.Miners.BestSnapshot().Height

	consensusLog.Infof("%v", newLogClosure(func() string {
		return spew.Sdump(s.peerState)
	}))

	syncid := s.syncManager.SyncPeerID()
	s.peerState.forAllPeers(func (ob *serverPeer) {
		if ob.ID() == syncid {
			consensusLog.Infof("My sync peer is: %s", ob.Addr())
		}
	})

	my := s.MyPlaceInCommittee(int32(best.LastRotation))
	var name [20]byte
	copy(name[:], s.signAddress.ScriptAddress())

	consensusLog.Infof("My heights %d %d rotation at %d", ht, mht, best.LastRotation)

	total := 100

	// those we want to have connections
	cmt := make(map[[20]byte]*wire.MinerBlock)
	for i := 0; i < wire.CommitteeSize; i++ {
		blk,_ := s.chain.Miners.BlockByHeight(int32(best.LastRotation) - int32(i))
		if blk != nil {
			cmt[blk.MsgBlock().Miner] = blk
		}
	}

	s.peerState.cmutex.Lock()
	for pname,sp := range s.peerState.committee {
		consensusLog.Infof("Peer %x", pname)
		if _, ok := cmt[pname]; !ok || name == pname {
			continue
		}

		consensusLog.Infof("\tis in committee at %d", cmt[pname].Height())
		delete(cmt, pname)

		for _,r := range sp.peers {
			if r.LastBlock() > sp.bestBlock {
				sp.bestBlock = r.LastBlock()
				if sp.lastBlockSent < sp.bestBlock {
					sp.lastBlockSent = sp.bestBlock
				}
			}
			if r.LastMinerBlock() > sp.bestMinerBlock {
				sp.bestMinerBlock = r.LastMinerBlock()
				if sp.lastMinerBlockSent < sp.bestMinerBlock {
					sp.lastMinerBlockSent = sp.bestMinerBlock
				}
			}
		}
		for _,r := range sp.peers {
			r.UpdateLastBlockHeight(sp.bestBlock)
			r.UpdateLastMinerBlockHeight(sp.bestMinerBlock)
		}

		idmap := make(map[int32]struct{})
		addrmap := make(map[string]int32)

		peers := make([]*serverPeer, 0, len(sp.peers))

		for i,r := range sp.peers {
			if _,ok := idmap[r.ID()]; ok {
				continue
			}
			idmap[r.ID()] = struct{}{}

			if _,ok := addrmap[r.Addr()]; ok {
				if r.Connected() && !r.persistent {
					r.Disconnect("duplicated connection")
				}
				continue
			}

			peers = append(peers, r)

			if !r.Connected() {
				continue
			}

			addrmap[r.Addr()] = int32(i)
//			r.UpdateLastBlockHeight(sp.bestBlock)
//			r.UpdateLastMinerBlockHeight(sp.bestMinerBlock)
		}

		sp.peers = peers

		for _, r := range sp.peers {
			if r.connReq != nil && !r.Connected() {
				s.makeConnection([]byte(r.connReq.Addr.String()), r.connReq.Miner,
					r.connReq.Committee, my)
				total += 100
				break
			}
		}
	}

	for peer,blk := range cmt {
		if name != peer {
			consensusLog.Infof("Peer %x has no good connection", peer)
			s.makeConnection(blk.MsgBlock().Connection, peer, blk.Height(), my)
			total += 100
		}
	}
	s.peerState.cmutex.Unlock()

	// start sync if there is no sync peer
	s.syncManager.StartSync()

	time.Sleep(time.Second * time.Duration(total / 100))
}

func (s *server) SubscribeChain(fn func (*blockchain.Notification)) {
	s.chain.Subscribe(fn)
	s.chain.Miners.Subscribe(fn)
}

func (s *server) NewConsusBlock(m * btcutil.Block) {
//	consensusLog.Infof("NewConsusBlock at %d", m.Height())
//	s.peerState.print()

	if isMainchain, orphan, err, _ := s.chain.ProcessBlock(m, blockchain.BFNone); err == nil && !orphan && isMainchain {
		consensusLog.Infof("consensus reached! sigs = %d", len(m.MsgBlock().Transactions[0].SignatureScripts))
	} else if err != nil {
		consensusLog.Infof("consensus faield to process ProcessBlock!!! %s", err.Error())
	}
}

func (s *server) CommitteeCast(msg wire.Message) {
	if s.signAddress == nil {
		return
	}
	var name [20]byte
	copy(name[:], s.signAddress.ScriptAddress())

	s.peerState.forAllCommittee(func(nm [20]byte, sp *committeeState) {
		if nm == name {
			return
		}
		for _,peer := range sp.peers {
			if peer.Connected() {
				srvrLog.Infof("casting %s message to %s (remote = %s)", msg.Command(), peer.Peer.LocalAddr().String(), peer.Peer.Addr())
				peer.QueueMessageWithEncoding(msg, nil, wire.SignatureEncoding)
				return
			}
		}
		for _,peer := range sp.peers {
			if !peer.Peer.Inbound() && peer.connReq != nil {
				peer.connReq.Initcallback = func(sp connmgr.ServerPeer) {
					srvrLog.Infof("casting %s message to %s (remote = %s)", msg.Command(), peer.Peer.LocalAddr().String(), peer.Peer.Addr())
					peer.QueueMessageWithEncoding(msg, nil, wire.SignatureEncoding)
				}
			}
		}
	})
}

func (s *server) CommitteeCastMG(sender [20]byte, msg wire.Message, h int32) {
	peers := make([]*serverPeer, 0, wire.CommitteeSize)
	s.peerState.forAllCommittee(func(sd [20]byte, sp *committeeState) {
		for _, r := range sp.peers {
			if r.Connected() {
				peers = append(peers, r)
				return
			}
		}
	})

	for _, r := range peers {
		senNewMsg(r, msg, h)
	}
}

func (s *server) GetPrivKey(who [20]byte) * btcec.PrivateKey {
	return cfg.privateKeys
}

func (s *peerState) peerByName(name []byte) * serverPeer {
	var p * serverPeer
	s.forAllPeers(func (q * serverPeer) {
		if bytes.Compare(name, q.Miner[:]) == 0{
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