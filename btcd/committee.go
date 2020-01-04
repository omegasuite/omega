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
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/omega/consensus"
	"math/big"
	"net"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const advanceCommitteeConnection = wire.CommitteeSize	// # of miner blocks we should prepare for connection

func (ps *peerState) reconnect(i int32, e * serverPeer, closure func(sp *serverPeer)) {
	if e.connReq != nil {
		// reconnect
		if closure != nil {
			e.connReq.Initcallback = func() { closure(ps.committee[i]) }
		}
		e.server.connManager.Connect(e.connReq)
	} else {
		if tcp, err := net.ResolveTCPAddr("", e.Peer.Addr()); err == nil {
			req := connmgr.ConnReq{
				Addr:         tcp,
				Committee:    i,
				Permanent:    false,
			}
			if closure != nil {
				req.Initcallback = func() { closure(ps.committee[i]) }
			}
			e.server.connManager.Connect(&req)
		}
	}
}

func (ps *peerState) forAllCommittee(closure func(sp *serverPeer)) {
	for i, e := range ps.committee {
		if i < int32(e.server.chain.BestSnapshot().LastRotation) - wire.CommitteeSize {
			delete(ps.committee, i)
			continue
		}
		if i > int32(e.server.chain.BestSnapshot().LastRotation) {
			continue
		}
		if !e.Peer.Connected() {
			ps.reconnect(i, e, closure)
		} else {
			closure(e)
		}
	}
}

func (sp *serverPeer) OnAckInvitation(_ *peer.Peer, msg *wire.MsgAckInvitation) {
	if (sp.server.chain.BestSnapshot().LastRotation > uint32(msg.Invitation.Height)+wire.CommitteeSize) ||
		(sp.server.chain.BestSnapshot().LastRotation+advanceCommitteeConnection < uint32(msg.Invitation.Height)) {
		// expired or too early for me
		return
	}

	k, err := btcec.ParsePubKey(msg.Invitation.Pubkey[:], btcec.S256())
	if err != nil {
		return
	}

	mb, err := sp.server.chain.Miners.BlockByHeight(msg.Invitation.Height)
	if err != nil {
		return
	}

	// check signature
	miner := mb.MsgBlock().Miner
	pk, _ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
	pkh := pk.AddressPubKeyHash().Hash160()

	if bytes.Compare(pkh[:], miner) != 0 {
		return
	}

	s, err := btcec.ParseSignature(msg.Sig, btcec.S256())
	if err != nil {
		return
	}

	var w bytes.Buffer
	if msg.Invitation.Serialize(&w) != nil {
		return
	}

	hash := chainhash.DoubleHashB(w.Bytes())
	if !s.Verify(hash, pk.PubKey()) {
		return
	}

	sp.server.peerState.committee[msg.Invitation.Height] = sp

	sp.Peer.Committee = msg.Invitation.Height
	copy(sp.Peer.Miner[:], miner)
}

func (s *server) sendInvAck(peer int32) {
	// send an acknowledgement so the peer knows we are too
	me := s.MyPlaceInCommittee(int32(s.chain.BestSnapshot().LastRotation))
	if me == 0 {	// should never happen
		return
	}

	my,_ := s.chain.Miners.BlockByHeight(me)
	pinv, adr := s.makeInvitation(me, my.MsgBlock().Miner)

	ackmsg := wire.MsgAckInvitation{}

	var w bytes.Buffer

	if pinv != nil && adr != nil {
		pinv.Serialize(&w)
		hash := chainhash.DoubleHashH(w.Bytes())

		if sig, err := s.privKeys[*adr].Sign(hash[:]); err == nil {
			ackmsg.Sig = sig.Serialize()
			ackmsg.Invitation = *pinv
			s.peerState.committee[peer].Peer.QueueMessage(&ackmsg, nil)
		}
	}
}

func (sp *serverPeer) OnInvitation(_ *peer.Peer, msg *wire.MsgInvitation) {
	// 1. check if the message has expired, if yes, do nothing
	if sp.server.chain.BestSnapshot().LastRotation > msg.Expire {
		return
	}

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
				(sp.server.chain.BestSnapshot().LastRotation + advanceCommitteeConnection < uint32(inv.Height)) {
				// expired or too early for me
				return
			}

			k,err := btcec.ParsePubKey(inv.Pubkey[:], btcec.S256())
			if err != nil {
				return
			}

			mb, err := sp.server.chain.Miners.BlockByHeight(inv.Height)
			if err != nil {
				return
			}

			// check signature
			miner := mb.MsgBlock().Miner
			pk,_ := btcutil.NewAddressPubKeyPubKey(*k, sp.server.chainParams)
			pkh := pk.AddressPubKeyHash().Hash160()

			if bytes.Compare(pkh[:], miner) != 0 {
				return
			}

			s,err := btcec.ParseSignature(msg.Sig, btcec.S256())
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
			if _, ok := sp.server.peerState.committee[inv.Height]; !ok {
				sp.server.peerState.forAllPeers(func(ob *serverPeer) {
					if !isin && ob.connReq.Addr.String() == tcp.String() {
						sp.server.peerState.committee[inv.Height] = ob

						ob.Peer.Committee = inv.Height
						copy(ob.Peer.Miner[:], miner)

						isin = true
					}
				})
			}

			var callback = func () {
				sp.server.sendInvAck(inv.Height)
			}

			if !isin || !sp.server.peerState.committee[inv.Height].Peer.Connected() {
				go sp.server.connManager.Connect(&connmgr.ConnReq{
					Addr:      tcp,
					Permanent: false,
					Committee: inv.Height,
					Initcallback: callback,
				})
			} else {
				callback()
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

func (state *peerState) phaseoutCommittee(r int32) {
	for i, _ := range state.committee {
		if i < r - wire.CommitteeSize {
			delete(state.committee, i)
		}
	}
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
		found := false
		for addr, _ := range s.privKeys {
			if bytes.Compare(miner[:], addr.ScriptAddress()) == 0 {
				found = true
				break
			}
		}
		if found {
			return i
		}
	}
	return 0
}

func (s * server) makeInvitation(me int32, miner []byte) (* wire.Invitation, * btcutil.Address) {
	inv := wire.Invitation{
		Height: me,
	}

	for adr, key := range s.privKeys {
		if bytes.Compare(miner, adr.ScriptAddress()) != 0 {
			continue
		}

		copy(inv.Pubkey[:], key.PubKey().SerializeCompressed())
		inv.IP = []byte(cfg.ExternalIPs[0])
		return &inv, &adr
	}
	return nil, nil
}

func (s * server) makeInvitationMsg(me int32, miner []byte, conn []byte) * wire.MsgInvitation {
	inv,adr := s.makeInvitation(me, miner)

	m := wire.MsgInvitation{
		Expire: uint32(me) + wire.CommitteeSize + uint32(randomUint16Number(10)),
	}

	copy(m.To[:], miner)
	var w bytes.Buffer

	if inv != nil {
		inv.Serialize(&w)
		hash := chainhash.DoubleHashH(w.Bytes())

		if sig, err := s.privKeys[*adr].Sign(hash[:]); err == nil {
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

func (s *server) handleCommitteRotation(state *peerState, r int32) {
	b := s.chain

	if uint32(r) < b.BestSnapshot().LastRotation {
		// if we have more advanced block, ignore this one
		return
	}

	state.phaseoutCommittee(r)
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

		var callback = func () {
			s.sendInvAck(j)
		}

		if k, ok := state.committee[j]; ok {
			if !k.Peer.Connected() {
				state.reconnect(j, k, func(ps *serverPeer) {
					callback()
				})
			}
			continue
		}

		mb,_ := b.Miners.BlockByHeight(j)
		if mb == nil {
			break
		}
		miner := mb.MsgBlock().Miner
		// establish connection
		// check its connection info.
		// if it is an IP address, connect directly,
		// otherwise, broadcast q request for connection msg.
		conn := mb.MsgBlock().Connection
		if len(conn) < 128 {
			// we use 1024-bit RSA pub key, so treat what is less
			// that that as an IP address
			tcp, err := net.ResolveTCPAddr("", string(conn))
			if err != nil {
				// not a valid address. should have validated before
				continue
			}

			isin := false
			state.forAllPeers(func (ob *serverPeer) {
				if !isin && ob.connReq.Addr.String() == tcp.String() {
					state.committee[j] = ob

					ob.Peer.Committee = j
					copy(ob.Peer.Miner[:], miner)

					isin = true
					if state.committee[j].Peer.Connected() {
						callback()
					}
				}
			})

			if !isin || !state.committee[j].Peer.Connected() {
				go s.connManager.Connect(&connmgr.ConnReq{
					Addr:      tcp,
					Permanent: false,
					Committee: j,
					Initcallback: callback,
				})
			}
		} else if len(cfg.ExternalIPs) == 0 {
			continue
		} else if m := s.makeInvitationMsg(me, miner, conn); m != nil {
			s.broadcast <- broadcastMsg { message: m}
		}
	}
}

func (s *server) AnnounceNewBlock(m * btcutil.Block) {
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
	s.committeecast <- broadcastMsg { message: &h}
}

func (s *server) CommitteeMsg(p int32, m wire.Message) bool {
	if sp,ok := s.peerState.committee[p]; ok {
		done := make(chan struct{})
		sp.QueueMessage(m, nil)
		<- done
		return true
	}
	return false
}

func (s *server) NewConsusBlock(m * wire.MsgBlock) {
	s.broadcast <- broadcastMsg { message: m}
}

func (s *server) handleCommitteecastMsg(state *peerState, bmsg *broadcastMsg) {
	state.forAllCommittee(func(sp *serverPeer) {
		for _, ep := range bmsg.excludePeers {
			if sp == ep {
				return
			}
		}

		sp.QueueMessage(bmsg.message, nil)
	})
}

func (s *server) CommitteeCast(sender int32, msg wire.Message) {
	sdr := s.peerState.committee[sender]
	s.peerState.forAllCommittee(func(sp *serverPeer) {
		if sdr == sp {
				return
			}

		sp.QueueMessage(msg, nil)
	})
}

func (s *server) GetPrivKey(who [20]byte) * btcec.PrivateKey {
	for adr, pvk := range cfg.privateKeys {
		if bytes.Compare(who[:], adr.ScriptAddress()) == 0 {
			return pvk
		}
	}
	return nil
}