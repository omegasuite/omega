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
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire/common"
	"github.com/btcsuite/omega/minerchain"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
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
//					q.sp.QueueMessageWithEncoding(m, done, wire.SignatureEncoding)
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
	ps.cmutex.Lock()
	for i, e := range ps.committee {
		closure(i, e)
	}
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
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	mb, err := sp.server.chain.Miners.BlockByHeight(msg.Invitation.Height)
	if err != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	// check signature
	var miner [20]byte
	copy(miner[:], mb.MsgBlock().Miner)
	pk, _ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
	pkh := pk.AddressPubKeyHash().Hash160()

	if bytes.Compare(pkh[:], miner[:]) != 0 {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	s, err := btcec.ParseSignature(msg.Sig, btcec.S256())
	if err != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	var w bytes.Buffer
	if msg.Invitation.Serialize(&w) != nil {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	hash := chainhash.DoubleHashB(w.Bytes())
	if !s.Verify(hash, pk.PubKey()) {
		// refuse by disconnect
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	// have we already connected to it?
	refused := false
	sp.server.peerState.forAllPeers(func(ob * serverPeer) {
		if sp != ob && bytes.Compare(ob.Peer.Miner[:], miner[:]) == 0 {
			// refuse by disconnect
			refused = true
		}
	})
	if refused {
		consensusLog.Infof("refuses AckInv. disconnect from %s", sp.Addr())
//		sp.server.handleDonePeerMsg(sp.server.peerState, sp)
		return
	}

	sp.server.peerState.cmutex.Lock()
	if sp.server.peerState.committee[miner] == nil {
		sp.server.peerState.committee[miner] = &committeeState{ peers: make([]*serverPeer, 0) }
	}
	m := sp.server.peerState.committee[miner]
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

	sp.Peer.Committee = msg.Invitation.Height
	copy(sp.Peer.Miner[:], miner[:])
}

func (s *server) SendInvAck(peer [20]byte, sp *serverPeer) {
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

	// 1. check if the message has expired, if yes, do nothing
	if sp.server.chain.BestSnapshot().LastRotation > msg.Expire {
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
			var miner [20]byte
			copy(miner[:], mb.MsgBlock().Miner)

			pk, _ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
			pkh := pk.AddressPubKeyHash().Hash160()

			if bytes.Compare(pkh[:], miner[:]) != 0 {
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
			if _, ok := sp.server.peerState.committee[miner]; !ok {
				sp.server.peerState.committee[miner] = newCommitteeState()
			}
			m := sp.server.peerState.committee[miner]
			sp.server.peerState.cmutex.Unlock()

			for _, p := range m.peers {
				if p.Connected() {
					sp.server.SendInvAck(miner, p)
					return
				}
			}

			sp.server.peerState.forAllPeers(func(ob *serverPeer) {
				if !isin && ob.Addr() == tcp.String() {
					m.peers = append(m.peers, ob)

					ob.Peer.Committee = inv.Height
					copy(ob.Peer.Miner[:], miner[:])

					sp.server.SendInvAck(miner, ob)

					isin = true
				}
			})

			if !isin {
				var callback = func (q connmgr.ServerPeer) {
					p := q.(*serverPeer)
					m.peers = append(m.peers, p)

					p.Peer.Committee = inv.Height
					copy(p.Peer.Miner[:], miner[:])

					sp.server.SendInvAck(miner, p)
				}

				go sp.server.connManager.Connect(&connmgr.ConnReq{
					Addr:      tcp,
					Permanent: false,
					Committee: inv.Height,
					Miner: miner,
					Initcallback: callback,
				})
			}
			return
		}
	}

	// 3. if not, check if the message is in inventory, if yes, ignore it
	mh := msg.Hash()
	if _, ok := sp.server.syncManager.Broadcasted[mh]; ok {
		sp.server.syncManager.Broadcasted[mh] = time.Now().Unix() + 300
		return
	}

	// 4. otherwise, broadcast it
	// remove expired inventory
	for i, t := range sp.server.syncManager.Broadcasted {
		if time.Now().Unix() > t {
			delete(sp.server.syncManager.Broadcasted, i)
		}
	}

	// inventory expires 5 minutes
	sp.server.syncManager.Broadcasted[mh] = time.Now().Unix() + 300
	sp.server.broadcast <- broadcastMsg{msg, []*serverPeer{sp} }
}

func (s *server) phaseoutCommittee(r int32) {
	b := s.chain

	keep := make(map[[20]byte]struct{})
	for j := r; j < r + advanceCommitteeConnection + wire.CommitteeSize; j++ {
		mb, _ := b.Miners.BlockByHeight(j)
		if mb != nil {
			var name [20]byte
			copy(name[:], mb.MsgBlock().Miner)
			keep[name] = struct{}{}
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
	inv := wire.Invitation{
		Height: me,
	}

	if bytes.Compare(miner, s.signAddress.ScriptAddress()) != 0 {
		return nil, nil
	}

	copy(inv.Pubkey[:], s.privKeys.PubKey().SerializeCompressed())
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

func (s *server) uniConn() {
	return
	// close connection to keep one for each committee member. conflict resolution:
	// the one with higher miner block height get to be server
/*
	best := int32(s.chain.BestSnapshot().LastRotation)
	adrmap := make(map[string]int32)
	if len(s.peerState.committee) > wire.CommitteeSize {
		for i, p := range s.peerState.committee {
			if j, ok := adrmap[p.Addr()]; !ok {
				adrmap[p.Addr()] = i
			} else {
				if j <= best-wire.CommitteeSize || j > best {
					delete(s.peerState.committee, j)
				} else {
					delete(s.peerState.committee, i)
				}
			}
		}
	}

	s.peerState.forAllPeers(func (p * serverPeer) {
		if p.Committee <= 0 {
			return
		}
		s.peerState.forAllPeers(func (q * serverPeer) {
			if q.Committee <= 0 {
				return
			}
			if p.Peer.ID() == q.Peer.ID() || bytes.Compare(p.Peer.Miner[:], q.Peer.Miner[:]) != 0 {
				return
			}
			if !p.Connected() || !q.Connected() {
				if q.Connected() {
					s.handleDonePeerMsg(s.peerState, p)
					return
				} else if p.Connected() {
					s.handleDonePeerMsg(s.peerState, q)
					return
				}
			}

			if p.Peer.LastBlock() > q.Peer.LastBlock() {
				s.handleDonePeerMsg(s.peerState, q)
			} else {
				s.handleDonePeerMsg(s.peerState, p)
			}
		})
	})
 */
}

func (s *server) makeConnection(conn []byte, miner [20]byte, j, me int32) {
	if _, ok := s.peerState.committee[miner]; ok {
		np := make([]*serverPeer, 0, len(s.peerState.committee[miner].peers))
		for _,r := range s.peerState.committee[miner].peers {
			// do they exist?
			exist := false
			s.peerState.forAllPeers(func (sp * serverPeer) {
				if sp == r {
					exist = true
				}
			})
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
	s.peerState.forAllPeers(func(ob *serverPeer) {
		if bytes.Compare(ob.Peer.Miner[:], miner[:]) == 0 {
			m.peers = append(m.peers, ob)
			ob.Peer.Committee = j
			found = true
			return
		}
	})

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
		s.peerState.forAllOutboundPeers(func (ob *serverPeer) {
			if !isin && ob.Addr() == tcp.String() {
				m.peers = append(m.peers, ob)

				ob.Peer.Committee = j
				copy(ob.Peer.Miner[:], miner[:])

				isin = true
				s.SendInvAck(miner, ob)
			}
		})

		if !isin {
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
		s.broadcast <- broadcastMsg { message: m}
	}
}

func (s *server) handleCommitteRotation(state *peerState, r int32) {
	consensusLog.Infof("handleCommitteRotation at %d", r)
	s.peerState.print()

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
		var miner [20]byte
		copy(miner[:], mb.MsgBlock().Miner)

		if _, ok := state.committee[miner]; !ok {
			state.committee[miner] = newCommitteeState()
		}

		p := s.peerState.peerByName(miner[:])
		if p != nil {
			state.committee[miner].peers = append(state.committee[miner].peers, p)
			p.Peer.Committee = j
			s.SendInvAck(miner, p)
			continue
		}

		// establish connection
		// check its connection info.
		// if it is an IP address, connect directly,
		// otherwise, broadcast q request for connection msg.
		conn := mb.MsgBlock().Connection
		s.makeConnection(conn, miner, j, me)
	}
	s.peerState.cmutex.Unlock()
}

func (s *server) AnnounceNewBlock(m * btcutil.Block) {
	consensusLog.Infof("AnnounceNewBlock %d %s", m.Height(), m.Hash().String())
	s.peerState.print()

/*
	h := consensus.MsgMerkleBlock{
		Fees: 0,
		Header: m.MsgBlock().Header,
		Height: m.Height(),
	}
	copy(h.From[:], m.MsgBlock().Transactions[0].SignatureScripts[1])
	for _, txo := range m.MsgBlock().Transactions[0].TxOut {
		_,v := txo.Value.Value()
		h.Fees += uint64(v)
	}
 */
	msg := wire.NewMsgInv()
	msg.AddInvVect(&wire.InvVect{
		Type: common.InvTypeWitnessBlock,
		Hash: *m.Hash(),
	})

	var name [20]byte
	copy(name[:], s.signAddress.ScriptAddress())

	s.CommitteeCastMG(name, msg, m.Height())

//	s.committeecast <- broadcastMsg { message: msg }
}

func (s *server) CommitteeMsgMG(p [20]byte, m wire.Message, h int32) {
	s.peerState.print()

	s.peerState.cmutex.Lock()
	if sp,ok := s.peerState.committee[p]; ok {
		s.peerState.cmutex.Unlock()

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
		s.peerState.cmutex.Unlock()
	}
}

func (s *server) CommitteeMsg(p [20]byte, m wire.Message) bool {
	done := make(chan bool)

	s.peerState.cmutex.Lock()
	if sp,ok := s.peerState.committee[p]; ok {
		for _,r := range sp.peers {
			if r.Connected() {
				srvrLog.Infof("sending it to %s (remote = %s)", r.Peer.LocalAddr().String(), r.Peer.Addr())
				r.QueueMessageWithEncoding(m, done, wire.SignatureEncoding)
				s.peerState.cmutex.Unlock()

				return <-done
			}
		}
	}
	s.peerState.cmutex.Unlock()

	return false
}

func (s *server) CommitteePolling() {
	best := s.chain.BestSnapshot()
	ht := best.Height
	mht := s.chain.Miners.BestSnapshot().Height

	my := s.MyPlaceInCommittee(int32(best.LastRotation))
	var name [20]byte
	copy(name[:], s.signAddress.ScriptAddress())

	consensusLog.Infof("\n\nMy heights %d %d rotation at %d", ht, mht, best.LastRotation)

	total := 0

	// those we want to have connections
	cmt := make(map[[20]byte]*wire.MinerBlock)
	for i := 0; i < wire.CommitteeSize; i++ {
		blk,_ := s.chain.Miners.BlockByHeight(int32(best.LastRotation) - int32(i))
		if blk != nil {
			var nname [20]byte
			copy(nname[:], blk.MsgBlock().Miner)
			cmt[nname] = blk
		}
	}

/*
	// take out those we already connected, what's left is those we need to connect
	s.peerState.forAllPeers(func(sp * serverPeer) {
		if _, ok := cmt[sp.Peer.Miner]; ok && sp.Connected() {
			delete(cmt, sp.Peer.Miner)
		}
	})

	// initiate connection by the new one. note, if we are not in committee, them my will be 0
	my := s.MyPlaceInCommittee(int32(best.LastRotation))
	for name, blk := range cmt {
		if my > blk.Height() {
			s.makeConnection(blk.MsgBlock().Connection, name, blk.Height(), my)
		}
	}

 */

	s.peerState.cmutex.Lock()
	for pname,sp := range s.peerState.committee {
		consensusLog.Infof("Peer %x", pname)
		if _, ok := cmt[pname]; !ok {
			continue
		}

		consensusLog.Infof("\tis in committee at %d", cmt[pname].Height())
		delete(cmt, pname)

		for _,r := range sp.peers {
			if !r.Connected() {
				continue
			}
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
		heightSent := sp.lastBlockSent
		minerHeightSent := sp.lastMinerBlockSent

		if heightSent == ht && minerHeightSent == mht {
			consensusLog.Infof("Peer %x is in perfect sync", pname)
			sp.lastBlockSent = (sp.bestBlock + sp.lastBlockSent) / 2
			sp.lastMinerBlockSent = (sp.bestMinerBlock + sp.lastMinerBlockSent) / 2
			continue
		}

		consensusLog.Infof("Peer %x \n\theights %d %d", pname, heightSent, minerHeightSent)

		heightSent--
		minerHeightSent--

		if heightSent < 0 {
			heightSent = 0
		}
		if minerHeightSent < 0 {
			minerHeightSent = 0
		}

		sent := false

		for _,r := range sp.peers {
			if !r.Connected() {
				continue
			}
			if r.LastBlock() == ht && r.LastMinerBlock() == mht {
				continue
			}

			sent = true

			// sending the requesting peer new inventory
			inv := wire.NewMsgInv()
			for i, n := heightSent, 0; i < ht; n++ {
				i++
				if n > wire.MaxInvPerMsg {
					r.QueueMessageWithEncoding(inv, nil, wire.SignatureEncoding)
					inv = wire.NewMsgInv()
					n = 0
				}
				h, _ := s.chain.BlockHashByHeight(i)
				inv.AddInvVect(&wire.InvVect{common.InvTypeWitnessBlock, *h})
				total++
			}

			d := len(inv.InvList)

			// sending the requesting peer new inventory
			for i, n := minerHeightSent, 0; i < mht; n++ {
				i++
				if n > wire.MaxInvPerMsg {
					r.QueueMessage(inv, nil)
					inv = wire.NewMsgInv()
					n = 0
				}
				h, _ := s.chain.Miners.(*minerchain.MinerChain).BlockHashByHeight(i)
				inv.AddInvVect(&wire.InvVect{common.InvTypeMinerBlock, *h})
				total++
			}

//			sp.lastBlockSent = ht
//			sp.lastMinerBlockSent = mht

			if len(inv.InvList) > 0 {
				done := make(chan bool)
				consensusLog.Infof("Sending %d tx and %d miner inventory to %x at %s with waiting", d, len(inv.InvList)-d, pname, r.Addr())
				r.QueueMessage(inv, done)
				<-done
				consensusLog.Infof("Inventory sent!")
			}

			sp.lastBlockSent = ht
			sp.lastMinerBlockSent = mht

			break
		}

		if !sent {
			consensusLog.Infof("Peer has %d connections, none good", len(sp.peers))
			for _, r := range sp.peers {
				if r.connReq != nil {
					s.makeConnection([]byte(r.connReq.Addr.String()), r.connReq.Miner,
						r.connReq.Committee, my)
					total += 100
/*
					consensusLog.Infof("Reconnect with ", r.connReq.String())
					s.connManager.Connect(r.connReq)
 */
					break
				}
			}
		}

/*
		if !sp.Peer.Connected() {
			if sp.connReq != nil {
				s.connManager.Connect(sp.connReq)
			}
			consensusLog.Infof("Peer %s is not connected", sp.Addr())
			continue
		}
 */
	}

	for peer,blk := range cmt {
		if name != peer {
			consensusLog.Infof("Peer %x has no good connection", peer)
			s.makeConnection(blk.MsgBlock().Connection, peer, blk.Height(), my)
			total += 100
		}
	}
	s.peerState.cmutex.Unlock()

	bmht := mht
	bht := ht

	//	if randomUint16Number(10) > 7 {
		consensusLog.Infof("list of all peers")
		s.peerState.forAllPeers(func(sp * serverPeer){
			var hash chainhash.Hash
			if sp.LastAnnouncedBlock() != nil {
				hash = *sp.LastAnnouncedBlock()
			}
			cnd := "disconnected -- "
			if sp.Connected() {
				cnd = "connected -- "
				inv := wire.NewMsgInv()

				if sp.LastMinerBlock() > mht {
					consensusLog.Infof("Request miner blocks upto %d from %s", sp.LastMinerBlock(), sp.Addr())
					locator, err := s.chain.Miners.(*minerchain.MinerChain).LatestBlockLocator()
					if err == nil {
						sp.PushGetMinerBlocksMsg(locator, &zeroHash)
						total += 300
					}
					mht = sp.LastMinerBlock()
				} else if sp.LastMinerBlock() < bmht {
					consensusLog.Infof("Send miner 5 most recent blocks to %s", sp.Addr())
					for i, n := bmht-5, 0; i < bmht; n++ {
						i++
						h, _ := s.chain.Miners.(*minerchain.MinerChain).BlockHashByHeight(i)
						if h != nil {
							inv.AddInvVect(&wire.InvVect{common.InvTypeMinerBlock, *h})
						}
						total++
					}
				}

				d := len(inv.InvList)

				if sp.LastBlock() > ht {
					consensusLog.Infof("Request tx blocks upto %d from %s", sp.LastBlock(), sp.Addr())
					locator, err := s.chain.LatestBlockLocator()
					if err == nil {
						sp.PushGetBlocksMsg(locator, &zeroHash)
						total += 300
					}
					ht = sp.LastBlock()
				} else if sp.LastBlock() < bht {
					consensusLog.Infof("Send tx 5 most recent blocks to %s", sp.Addr())
					for i, n := bht-5, 0; i < bht; n++ {
						i++
						h, _ := s.chain.BlockHashByHeight(i)
						if h != nil {
							inv.AddInvVect(&wire.InvVect{common.InvTypeWitnessBlock, *h})
						}
						total++
					}
				}

				// sending the requesting peer new inventory

				if len(inv.InvList) > 0 {
					done2 := make(chan bool)
					consensusLog.Infof("Sending %d tx and %d miner inventory to %s with waiting", d, len(inv.InvList)-d, sp.Addr())
					sp.QueueMessage(inv, done2)
					<-done2
					consensusLog.Infof("Inventory sent!")
				}
			}

			consensusLog.Infof("%s %s %d last blocks %d %d last hash %s\n\t\tcommittee %d %x", cnd,
				sp.Addr(), sp.ID(), sp.LastBlock(), sp.LastMinerBlock(), hash.String(),
				sp.Peer.Committee, sp.Peer.Miner)
		})
//	}
	time.Sleep(time.Second * time.Duration(total / 100))
}

func (s *server) SubscribeChain(fn func (*blockchain.Notification)) {
	s.chain.Subscribe(fn)
	s.chain.Miners.Subscribe(fn)
}

func (s *server) NewConsusBlock(m * btcutil.Block) {
	consensusLog.Infof("NewConsusBlock at %d", m.Height())
	s.peerState.print()

	if _, _, err := s.chain.ProcessBlock(m, blockchain.BFNone); err == nil {
		srvrLog.Infof("consensus reached! sigs = %d", len(m.MsgBlock().Transactions[0].SignatureScripts))
//		msg := wire.NewMsgInv()
//		msg.AddInvVect(&wire.InvVect{
//			Type: common.InvTypeWitnessBlock,
//			Hash: *m.Hash(),
//		})

//		s.broadcast <- broadcastMsg { message: msg }
	} else {
		srvrLog.Infof("consensus faield to pass ProcessBlock!!! %s", err.Error())
	}
}

/*
func (s *server) handleCommitteecastMsg(state *peerState, bmsg *broadcastMsg) {
	srvrLog.Infof("handleCommitteecastMsg %s message", bmsg.message.Command())

	s.peerState.print()

	state.forAllCommittee(func(sp *serverPeer) {
		for _, ep := range bmsg.excludePeers {
			if sp == ep {
				return
			}
		}
		srvrLog.Infof("casting %s message to %s (remote = %s)", bmsg.message.Command(), sp.Peer.LocalAddr().String(), sp.Peer.Addr())
		sp.QueueMessageWithEncoding(bmsg.message, nil, wire.SignatureEncoding)
	})
}
 */

func (s *server) CommitteeCast(msg wire.Message) {
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
				s.connManager.Connect(peer.connReq)
			}
		}
	})
}

func (s *server) CommitteeCastMG(sender [20]byte, msg wire.Message, h int32) {
	s.peerState.forAllCommittee(func(sd [20]byte, sp *committeeState) {
		for _, r := range sp.peers {
			if r.Connected() {
				senNewMsg(r, msg, h)
				return
			}
		}
	})
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