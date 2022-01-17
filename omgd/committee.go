// Copyright (C) 2019-2021 Omegasuite developer
// Use of this code is governed by an ISC
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
	"github.com/omegasuite/omega/consensus"
	"github.com/omegasuite/omega/minerchain"
	"math/big"
	"net"
	"time"

	"github.com/omegasuite/btcd/chaincfg/chainhash"
//	"github.com/omegasuite/btcd/peer"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
)

const advanceCommitteeConnection = wire.CommitteeSize	// # of miner blocks we should prepare for connection
const maxFailedAttempts = 25

// This must be a go routine
func (p * peerState) CommitteeOut(s * committeeState) {
	var msg wire.Message
	var ok bool
	var connecting bool

	retryCount := time.Duration(1)

	for {
		if msg, ok = <-s.queue; !ok {
			return
		}

		done := make(chan bool)
		sent := false
		for _,sp := range s.peers {
			if !sent && sp.Connected() {
				btcdLog.Infof("CommitteeOut: %s msg to %s", msg.Command(), sp.Addr())
				sp.QueueMessageWithEncoding(msg, done, wire.SignatureEncoding)
				sent, connecting, retryCount = true, false, 1
			}
		}
		if !sent {
			// get a new connections and send it
			s.peers = s.peers[:0]
			p.ForAllPeers(func(sp *serverPeer) {
				if sp.Connected() &&
					(sp.Peer.Miner == s.member ||
					((sp.persistent || !sp.Inbound()) && sp.Peer.Addr() == s.address)) {
					if s.minerHeight > sp.Peer.Committee {
						sp.Peer.Committee = s.minerHeight
					} else {
						s.minerHeight = sp.Peer.Committee
					}
					copy(sp.Peer.Miner[:], s.member[:])
					s.peers = append(s.peers, sp)
				}
			})
			if len(s.peers) > 0 {
				btcdLog.Infof("CommitteeOut: %s msg to %s", msg.Command(), s.peers[0].Addr())
				s.peers[0].QueueMessageWithEncoding(msg, done, wire.SignatureEncoding)
				sent, connecting, retryCount = true, false, 1
			} else if connecting || retryCount > maxFailedAttempts {
				continue
			} else {	// if len(s.address) > 0
				tcp, err := net.ResolveTCPAddr("", s.address)
				if err != nil {
					btcdLog.Infof("CommitteeOut: can not resolve %s", s.address)
					continue
				}

				btcdLog.Infof("CommitteeOut: make a connection for %s to %s.", msg.Command(), tcp.String())

				connecting = true

				go p.connManager.Connect(&connmgr.ConnReq{
					Addr:      tcp,
					Permanent: false,
					Committee: s.minerHeight,
					Miner: s.member,
					Initcallback: func(sp connmgr.ServerPeer) {
						s.peers = append(s.peers, sp.(*serverPeer))
					},
				})

				time.AfterFunc(retryCount * connectionRetryInterval, func () {
					connecting = false
				})

				retryCount++

				continue
			}
		}
		r := <- done
		m, ok := msg.(*wire.MsgKnowledge)
		if ok && r {
			reply := wire.MsgKnowledgeDone(*m)
			reply.From = s.member
			consensus.HandleMessage(&reply)
		}
	}
}
/*
func (sp *serverPeer) OnAckInvitation(_ *peer.Peer, msg *wire.MsgAckInvitation) {
	sp.server.peerState.print()

	if (sp.server.chain.BestSnapshot().LastRotation > uint32(msg.Invitation.Height)+wire.CommitteeSize) ||
		(sp.server.chain.BestSnapshot().LastRotation+advanceCommitteeConnection < uint32(msg.Invitation.Height)) {
		// expired or too early for me
		return
	}

	k, err := btcec.ParsePubKey(msg.Invitation.Pubkey[:], btcec.S256())
	if err != nil {
		consensusLog.Infof("refuses AckInv (1) %s", sp.Addr())
		return
	}

	mb, err := sp.server.chain.Miners.BlockByHeight(msg.Invitation.Height)
	if err != nil {
		consensusLog.Infof("refuses AckInv (2) %s", sp.Addr())
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

	if bytes.Compare(pkh1[:], mb.MsgBlock().Miner[:]) != 0 &&
		bytes.Compare(pkh2[:], mb.MsgBlock().Miner[:]) != 0 {
		consensusLog.Infof("refuses AckInv (3) %s miner = %x pkh1 = %x pkh2 = %x at %d", sp.Addr(),
			mb.MsgBlock().Miner, pkh1, pkh2, msg.Invitation.Height)
		return
	}

	if bytes.Compare(mb.MsgBlock().Miner[:], sp.server.signAddress.ScriptAddress()) == 0 {
		return
	}

	s, err := btcec.ParseSignature(msg.Sig, btcec.S256())
	if err != nil {
		consensusLog.Infof("refuses AckInv (4) %s", sp.Addr())
		return
	}

	var w bytes.Buffer
	if msg.Invitation.Serialize(&w) != nil {
		consensusLog.Infof("refuses AckInv (5) %s", sp.Addr())
		return
	}

	hash := chainhash.DoubleHashB(w.Bytes())
	if !s.Verify(hash, pk.PubKey()) {
		consensusLog.Infof("refuses AckInv (6) %s", sp.Addr())
		return
	}

	sp.server.peerState.cmutex.Lock()
	if sp.server.peerState.committee[mb.MsgBlock().Miner] == nil {
		sp.server.peerState.committee[mb.MsgBlock().Miner] =
			sp.server.peerState.NewCommitteeState(mb.MsgBlock().Miner, mb.Height(), string(mb.MsgBlock().Connection))
	}
	m := sp.server.peerState.committee[mb.MsgBlock().Miner]
	sp.server.peerState.cmutex.Unlock()

	m.peers = append(m.peers, sp)

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

			if bytes.Compare(mb.MsgBlock().Miner[:], sp.server.signAddress.ScriptAddress()) == 0 {
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
			added := false

			sp.server.peerState.cmutex.Lock()
			if _, ok := sp.server.peerState.committee[mb.MsgBlock().Miner]; !ok {
				sp.server.peerState.committee[mb.MsgBlock().Miner] =
					sp.server.peerState.NewCommitteeState(mb.MsgBlock().Miner, mb.Height(), string(mb.MsgBlock().Connection))
			}
			m := sp.server.peerState.committee[mb.MsgBlock().Miner]
			sp.server.peerState.cmutex.Unlock()

			for _, p := range m.peers {
				if p.Connected() {
					sp.server.SendInvAck(mb.MsgBlock().Miner, p)
					return
				}
			}

			addr := tcp.String()

			sp.server.peerState.ForAllPeers(func(ob *serverPeer) {
				if !isin && (ob.Addr() == addr || ob.Peer.LocalAddr().String() == addr) && ob.Connected() {
					for i, b := range m.peers {
						if !b.Connected() {
							m.peers = append(m.peers[:i], m.peers[i+1:]...)
						} else if b.ID() == ob.ID() {
							added = true
						}
					}
					if !added {
						m.peers = append(m.peers, ob)
					}

					ob.Peer.Committee = inv.Height
					copy(ob.Peer.Miner[:], mb.MsgBlock().Miner[:])

					sp.server.SendInvAck(mb.MsgBlock().Miner, ob)

					isin = true
				}
			})

			if !isin && !added {
				var callback = func (q connmgr.ServerPeer) {
					p := q.(*serverPeer)
					m.peers = append(m.peers, p)

					p.Peer.Committee = inv.Height
					copy(p.Peer.Miner[:], mb.MsgBlock().Miner[:])

					sp.server.SendInvAck(mb.MsgBlock().Miner, p)
				}

				priority,_ := sp.server.addrManager.AddLocalAddress(wire.NewNetAddressIPPort(tcp.IP, uint16(tcp.Port), 0), addrmgr.CommitteePrio)
				if priority == addrmgr.ManualPrio {
					btcdLog.Infof("This is a perm conn")
				}

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
}
 */

func (s *server) phaseoutCommittee(r int32) {
	s.peerState.cmutex.Lock()
	for i, p := range s.peerState.committee {
		if p.minerHeight != 0 && p.minerHeight < r {
			delete(s.peerState.committee, i)
			close(p.queue)
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
		for _,sa := range s.signAddress {
			if bytes.Compare(miner[:], sa.ScriptAddress()) == 0 {
				return i
			}
		}
	}
	return 0
}

func (s * server) makeInvitation(me int32, miner []byte) (* wire.Invitation, * btcutil.Address) {
	if s.signAddress == nil {
		return nil, nil
	}
	if len(cfg.ExternalIPs) == 0 {
		return nil, nil
	}

	inv := wire.Invitation{
		Height: me,
	}

	for j,sa := range s.signAddress {

		if bytes.Compare(miner, sa.ScriptAddress()) != 0 {
			continue
		}

		pk := s.privKeys[j].PubKey()

		copy(inv.Pubkey[:], pk.SerializeCompressed())
		//	copy(inv.Pubkey[:], s.privKeys.PubKey().SerializeUncompressed())
		inv.IP = []byte(cfg.ExternalIPs[0])
		return &inv, &s.signAddress[j]
	}
	return nil, nil
}

func (s * server) makeInvitationMsg(me int32, miner []byte, conn []byte) * wire.MsgInvitation {
	s.peerState.print()

	inv,sa := s.makeInvitation(me, miner)
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

		for i, key := range s.privKeys {
			if sa == &s.signAddress[i] {
				if sig, err := key.Sign(hash[:]); err == nil {
					m.Sig = sig.Serialize()
				}
			}
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

func (s *server) makeConnection(conn []byte, miner [20]byte, j int32) { //}, me int32) {
	found := false

	s.peerState.cmutex.Lock()
	m, ok := s.peerState.committee[miner]
	if ok {
		np := make([]*serverPeer, 0, len(m.peers))
		for _,r := range m.peers {
			// do they exist?
			exist := false

			s.peerState.forAllPeers(func (sp * serverPeer) {
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

		m = s.peerState.NewCommitteeState(miner,j, string(mb.MsgBlock().Connection))
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

		if !isin {
			btcdLog.Debugf("makeConnection: new %s", addr)

			go s.connManager.Connect(&connmgr.ConnReq{
				Addr:      tcp,
				Permanent: false,
				Committee: j,
				Miner: miner,
				Initcallback: func(sp connmgr.ServerPeer) {
					m.peers = append(m.peers, sp.(*serverPeer))
				},
			})
		}
	}
}

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

	s.phaseoutCommittee(r - 2 * wire.CommitteeSize)

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

	for j := bot; j < me + advanceCommitteeConnection; j++ {
		if me == j || j < 0 || j >= minerTop {
			continue
		}

		mb,_ := b.Miners.BlockByHeight(j)
		if mb == nil {
			break
		}

		s.peerState.cmutex.Lock()
		_, ok := s.peerState.committee[mb.MsgBlock().Miner]
		s.peerState.cmutex.Unlock()
		if ok {
			continue
		}
		mtch := false
		for _,sa := range s.signAddress {
			if bytes.Compare(mb.MsgBlock().Miner[:], sa.ScriptAddress()) == 0 {
				mtch = true
			}
		}
		if mtch {
			continue
		}

		if _,err := s.chain.CheckCollateral(mb, nil, blockchain.BFNone); err != nil {
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
		conn := mb.MsgBlock().Connection

		s.makeConnection(conn, mb.MsgBlock().Miner, j)
	}
}

func (s *server) CommitteeMsgMG(p [20]byte, h int32, m wire.Message) {
	s.peerState.print()

	s.peerState.cmutex.Lock()
	sp,ok := s.peerState.committee[p]
	if ok {
		sp.queue <- m
	}
	s.peerState.cmutex.Unlock()

	if !ok {
		mb,_ := s.chain.Miners.BlockByHeight(h)
		if p != mb.MsgBlock().Miner {
			btcdLog.Infof("CommitteeMsgMG passed inconsistent peer & height")
			return
		}
		btcdLog.Infof("CommitteeMsgMG makeConnection to %s %d", mb.MsgBlock().Connection, mb.Height())

		s.makeConnection(mb.MsgBlock().Connection, p, mb.Height())
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

func (s *server) Connected(p [20]byte) bool {
	s.peerState.cmutex.Lock()
	sp,ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _,r := range sp.peers {
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
	sp,ok := s.peerState.committee[p]
	s.peerState.cmutex.Unlock()

	if ok {
		for _,r := range sp.peers {
			if r.Connected() {
				btcdLog.Infof("sending %s to %s (remote = %s)", m.Command(), r.Peer.LocalAddr().String(), r.Peer.Addr())
				r.QueueMessageWithEncoding(m, done, wire.SignatureEncoding)
				return <-done
			}
		}
		btcdLog.Infof("No Connected peer in %x (%d) for sending %s", p, len(sp.peers), m.Command())

		if len(sp.address) > 0 {
			btcdLog.Infof("%x is at %d. makeConnection", p, h)
			s.makeConnection([]byte(sp.address), p, h)
		}
	} else {
		btcdLog.Infof("%x not in committee yet, add it", p)

		blk, _ := s.chain.Miners.BlockByHeight(h)

		if p != blk.MsgBlock().Miner {
			btcdLog.Infof("CommitteeMsg passed inconsistent peer & height")
			return false
		}

		btcdLog.Infof("%x is at %d. makeConnection", p, h)
		s.makeConnection(blk.MsgBlock().Connection, p, blk.Height())
	}

	return false
}

func (s *server) CommitteePolling() {
	if s.signAddress == nil {
		return
	}

	consensusLog.Infof("Connected Peers: %d\nInbound: %s\nOutbound: %d\nPersistent: %d",
		len(s.peerState.inboundPeers) + len(s.peerState.outboundPeers) + len(s.peerState.persistentPeers),
		len(s.peerState.inboundPeers), len(s.peerState.outboundPeers), len(s.peerState.persistentPeers))

	s.peerState.cmutex.Lock()
	for c, p := range s.peerState.committee {
		consensusLog.Infof("Committee member %x has %d connections. Address: %s. %d queued messages", c, len(p.peers), p.address, len(p.queue))
		for _, q := range p.peers {
			consensusLog.Infof("member connections: %d %s %v (local  addr = %s)", q.ID(), q.Addr(), q.Connected(), q.LocalAddr().String())
		}
	}
	s.peerState.cmutex.Unlock()
	return
}

func (s *server) SubscribeChain(fn func (*blockchain.Notification)) {
	s.chain.Subscribe(fn)
	s.chain.Miners.Subscribe(fn)
}

func (s *server) NewConsusBlock(m * btcutil.Block) {
	m.ClearSize()
	if isMainchain, orphan, err, _, _ := s.chain.ProcessBlock(m, blockchain.BFNone); err == nil && !orphan && isMainchain {
		consensusLog.Debugf("consensus reached! sigs = %d", len(m.MsgBlock().Transactions[0].SignatureScripts))
	} else {
		s.chain.SendNotification(blockchain.NTBlockRejected, m)
		if err != nil {
			consensusLog.Infof("consensus faield to process ProcessBlock!!! %s", err.Error())
		}
	}
}

func (s *server) GetPrivKey(who [20]byte) * btcec.PrivateKey {
	for i,k := range s.signAddress {
		if bytes.Compare(who[:], k.ScriptAddress()) == 0 {
			return cfg.privateKeys[i]
		}
	}
	return nil
}

func (s *peerState) peerByName(name []byte) * serverPeer {
	var p * serverPeer
	s.forAllPeers(func (q * serverPeer) {
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