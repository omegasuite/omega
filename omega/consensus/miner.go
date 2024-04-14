/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package consensus

import (
	"bytes"
	"time"

	//	"bufio"
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	//	"io"
	"os"

	//	"net/http"
	"sync"
	//	"time"
)

const (
	maxTxPerBlock = 50000
)

type Message interface {
	wire.Message
	Block() int32
	Sign(key *btcec.PrivateKey)
	DoubleHashB() []byte
	GetSignature() []byte
	Sender() [20]byte
	BlockHash() chainhash.Hash
	Sequence() int32
}

var Debug int // hash of last block

type PeerNotifier interface {
	MyPlaceInCommittee(r int32) int32
	CommitteeMsg([20]byte, int32, wire.Message) bool
	Connected(p [20]byte) bool
	CommitteeMsgMG([20]byte, int32, wire.Message)
	NewConsusBlock(block *btcutil.Block)
	GetPrivKey([20]byte) *btcec.PrivateKey
	BestSnapshot() *blockchain.BestState
	MinerBlockByHeight(int32) (*wire.MinerBlock, error)
	SubscribeChain(func(*blockchain.Notification))
	CommitteePolling()
	ChainSync(chainhash.Hash, [20]byte)
	ResetConnections()
	GetTxBlock(h int32) *btcutil.Block
	Broadcast(wire.Message, *string)
	AddKnownCommittee(int32, [20]byte) bool
}

type ReqQueue interface {
	QueueMessage(msg wire.Message, doneChan chan<- bool)
	QueueMessageWithEncoding(msg wire.Message, doneChan chan<- bool, encoding wire.MessageEncoding)
	Addr() string
	ID() int32
	NA() *wire.NetAddress
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server       PeerNotifier
	updateheight chan int32
	name         [][20]byte

	lastSignedBlock int32
	lwbFile         *os.File

	cfg      *chaincfg.Params
	pulling  map[chainhash.Hash]int64
	allblks  map[chainhash.Hash]*btcutil.Block
	knownsrc map[chainhash.Hash]ReqQueue

	// wait for end of task
	wg        sync.WaitGroup
	shutdown  bool
	castedMsg map[chainhash.Hash]int64 // time a message is broadcated, to prevent re-casting
}

type newblock struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

var newblockch chan newblock

// var newheadch chan newhead

func ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) {
	if miner == nil || miner.shutdown || newblockch == nil {
		return
	}

	flags |= blockchain.BFNoConnect
	log.Infof("Consensus.ProcessBlock for block %s at %d, flags=%x", block.Hash().String(), block.Height(), flags)

	if block.Height() < 0 {
		block.SetHeight(int32(block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index))
		log.Infof("Force height to %d", block.Height())
	}

	block.ClearSize()
	newblockch <- newblock{block, flags}
}

func ServeBlock(h *chainhash.Hash) *btcutil.Block {
	if miner == nil || miner.shutdown {
		return nil
	}
	for _, s := range miner.Sync {
		b := s.findBlock(h)
		if b != nil {
			return b
		}
	}
	return nil
}

var miner *Miner

var Quit chan struct{}
var POWStopper chan struct{}
var errMootBlock error
var errInvalidBlock error
var connNotice chan interface{}
var Leader chan int32

func (m *Miner) notice(notification *blockchain.Notification) {
	if connNotice != nil && !miner.shutdown {
		switch notification.Type {
		case blockchain.NTBlockConnected:
			connNotice <- notification.Data
		}
	}
}

func handleConnNotice(c interface{}) {
	switch c.(type) {
	case *wire.MinerBlock:
		b := c.(*wire.MinerBlock)

		h := b.Height()

		log.Infof("new miner block at %d connected", h)

		miner.syncMutex.Lock()
		for _, s := range miner.Sync {
			if s.Base > h-wire.CommitteeSize && s.Base <= h && !s.Runnable {
				s.SetCommittee()
			}
		}
		miner.syncMutex.Unlock()

	case *btcutil.Block:
		b := c.(*btcutil.Block)

		h := b.Height()

		UpdateChainHeight(h)

		log.Infof("new tx block at %d connected", h)
		var sny *Syncer

		miner.syncMutex.Lock()
		next := int32(0x7FFFFFFF)
		for n, s := range miner.Sync {
			if n > h && n < next {
				next = n
			} else if n <= h {
				delete(miner.Sync, n)
				s.Quit()
			}
		}
		if next != 0x7FFFFFFF && !miner.Sync[next].Runnable {
			sny = miner.Sync[next]
		}
		miner.syncMutex.Unlock()

		if sny != nil {
			log.Infof("SetCommittee for next syner %d", sny.Height)
			sny.SetCommittee()
		} else {
			log.Infof("No pending syners")
		}
	}
}

func UpdateLastWritten(last int32) bool {
	if last > miner.lastSignedBlock {
		miner.lastSignedBlock = last
		return true
	}

	return false
}

func SetupRelay(s PeerNotifier) {
	miner = &Miner{}
	miner.server = s
	miner.cfg = nil
	miner.castedMsg = make(map[chainhash.Hash]int64)
	miner.pulling = make(map[chainhash.Hash]int64)
	miner.allblks = make(map[chainhash.Hash]*btcutil.Block)
	miner.knownsrc = make(map[chainhash.Hash]ReqQueue)
	newblockch = make(chan newblock, 2*wire.CommitteeSize)

	polling := true

	for polling {
		select {
		case blk := <-newblockch:
			miner.allblks[*blk.block.Hash()] = blk.block

		case <-Quit:
			return
		}
	}
}

func Consensus(s PeerNotifier, dataDir string, addr []btcutil.Address, cfg *chaincfg.Params) {
	miner = &Miner{}
	miner.server = s
	miner.cfg = cfg
	miner.updateheight = make(chan int32, 200)
	miner.lastSignedBlock = 0
	miner.castedMsg = make(map[chainhash.Hash]int64)
	miner.pulling = make(map[chainhash.Hash]int64)
	miner.allblks = make(map[chainhash.Hash]*btcutil.Block)
	miner.knownsrc = make(map[chainhash.Hash]ReqQueue)

	s.SubscribeChain(miner.notice)

	connNotice = make(chan interface{}, 10)

	miner.Sync = make(map[int32]*Syncer, 0)
	miner.syncMutex = sync.Mutex{}

	miner.name = make([][20]byte, len(addr))
	for i, name := range addr {
		copy(miner.name[i][:], name.ScriptAddress())
	}

	newblockch = make(chan newblock, 2*wire.CommitteeSize)

	errMootBlock = fmt.Errorf("Moot block.")
	errInvalidBlock = fmt.Errorf("Invalid block")
	Quit = make(chan struct{})

	log.Info("Consensus running")
	miner.wg.Add(1)

	//	ticker := time.NewTicker(time.Second * 10)
	defer miner.wg.Done()

	polling := true
out:
	for polling {
		select {
		case height := <-miner.updateheight:
			log.Infof("Consensus <-miner.updateheight %d", height)
			miner.syncMutex.Lock()
			cleaner(height)
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}
			miner.syncMutex.Unlock()

		case c := <-connNotice:
			handleConnNotice(c)

		case blk := <-newblockch:
			top := miner.server.BestSnapshot().Height
			bh := blk.block.Height()

			if bh <= top {
				continue
			}

			if len(blk.block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
				continue
			}

			miner.syncMutex.Lock()
			snr, ok := miner.Sync[bh]
			if !ok {
				log.Infof(" CreateSyncer at %d", bh)
				miner.Sync[bh] = CreateSyncer(bh)
				snr = miner.Sync[bh]
			}
			log.Infof(" BlockInit at %d for block %s", bh, blk.block.Hash().String())
			miner.syncMutex.Unlock()

			if POWStopper != nil {
				if len(POWStopper) < wire.CommitteeSize {
					POWStopper <- struct{}{}
				} else {
					log.Infof("len(POWStopper) = %d", len(POWStopper))
				}
			}
			snr.BlockInit(blk.block)

		case <-Quit:
			polling = false
			break out
		}
	}
	log.Info("Consensus quitting")

	miner.syncMutex.Lock()
	for i, t := range miner.Sync {
		log.Infof("Sync %d to Quit", i)
		delete(miner.Sync, i)
		t.Quit()
	}
	miner.syncMutex.Unlock()

	for true {
		select {
		case <-miner.updateheight:
		case <-newblockch:
		case <-connNotice:

		default:
			log.Info("consensus quits")
			return
		}
	}
}

func HandleMessage(p ReqQueue, m Message) (bool, *chainhash.Hash) {
	if miner == nil || miner.shutdown {
		return false, nil
	}

	// the messages here are consensus messages. specifically, it does not include block msg.
	h := m.Block()
	bh := miner.server.BestSnapshot().Height

	if m.Sequence() > 0 {
		log.Infof("Seq = %d", m.Sequence())
	}

	if h <= bh {
		return true, nil
	}

	switch m.(type) {
	case *wire.MsgPull:
		miner.syncMutex.Lock()
		mm, _ := miner.allblks[m.BlockHash()]
		if mm != nil {
			log.Infof("Supply data for pulling of %s to %s", m.BlockHash().String(), p.Addr())
			//			d := make(chan bool)
			p.QueueMessageWithEncoding(mm.MsgBlock(), nil, wire.SignatureEncoding|wire.FullEncoding)
		} else if src, ok := miner.knownsrc[m.BlockHash()]; ok {
			log.Infof("Forward pulling request")
			pull(m.BlockHash(), m.Block(), src)
		} else {
			log.Infof("Unable to handle pulling request")
		}
		miner.syncMutex.Unlock()
		return true, nil

	default:
		miner.syncMutex.Lock()
		miner.knownsrc[m.BlockHash()] = p
		miner.syncMutex.Unlock()
	}

	ps := p.Addr()

	if miner.cfg == nil { // relay mode
		if m.Sequence() > 0 {
			miner.server.Broadcast(m, &ps)
		}
		return false, nil
	}

	miner.syncMutex.Lock()

	// check if we have got this msg before
	var w bytes.Buffer
	var hs chainhash.Hash
	w.Write([]byte(m.Command()))
	m.OmcEncode(&w, 0, wire.FullEncoding)
	copy(hs[:], chainhash.HashB(w.Bytes()))
	if _, ok := miner.castedMsg[hs]; ok {
		miner.syncMutex.Unlock()
		return true, nil
	}
	now := time.Now().Unix()
	for h, t := range miner.castedMsg {
		if now-t > 5 {
			delete(miner.castedMsg, h)
		}
	}

	miner.castedMsg[hs] = now

	s, ok := miner.Sync[h]

	if !ok {
		miner.Sync[h] = CreateSyncer(h)
		s = miner.Sync[h]
	} else if s.Done {
		miner.syncMutex.Unlock()
		log.Infof("syncer has finished with %h. Ignore this message", h)
		return false, nil
	}
	miner.syncMutex.Unlock()

	// add source IP to known committee
	s.forestLock.Lock()
	ip, ok := s.ips[m.Sender()]
	s.forestLock.Unlock()

	if m.Sequence() == 0 && ok { // not through broadcast, thus the source IP belongs to the true committee member
		if p.NA().IP.Equal(ip) {
			miner.server.AddKnownCommittee(p.ID(), m.Sender())
		}
	}

	s.SetCommittee()

	if s.Myself < 0 {
		if m.Sequence() > 0 {
			miner.server.Broadcast(m, &ps)
		}
		return false, nil
	}

	if len(s.commands) > (wire.CommitteeSize-1)*10 {
		<-s.commands
		<-s.commands
		log.Infof("Runnable syner %d has too many (%d) messages queued. Discard oldest one.", s.Height, len(s.commands))
		s.DebugInfo()
	}
	s.commands <- m

	if !s.Runnable {
		log.Infof("syncer is not ready for height %d, message will be queued. Current que len = %d", h, len(s.commands))
		miner.server.Broadcast(m, &ps)
		return false, nil
	}

	miner.syncMutex.Lock()
	//	s.forestLock.Lock()
	if _, ok := s.blocks[m.BlockHash()]; !ok {
		if mm, ok := miner.allblks[m.BlockHash()]; ok {
			s.blocks[m.BlockHash()] = mm
		} else {
			pull(m.BlockHash(), s.Height, p)
		}
	}
	//	s.forestLock.Unlock()
	miner.syncMutex.Unlock()

	return false, nil // hash
}

func VerifySig(m Message) bool {
	if miner.cfg == nil {
		return true
	}

	var err error
	switch m.(type) {
	case *wire.MsgPull:
		return true

	case *wire.MsgKnowledge:
		tmsg := *m.(*wire.MsgKnowledge)
		tmsg.K = make([]int32, 0)
		tmsg.Signatures = make([][]byte, 0)
		copy(tmsg.From[:], tmsg.Finder[:])

		for j, i := range m.(*wire.MsgKnowledge).K {
			sig := m.(*wire.MsgKnowledge).Signatures[j]

			tmsg.K = append(tmsg.K, i)

			signer, err := btcutil.VerifySigScript(sig, tmsg.DoubleHashB(), miner.cfg)
			if err != nil {
				log.Infof("VerifySig VerifySigScript fail. msg = %x\n", m)
				return false
			}

			pkh := signer.Hash160()
			copy(tmsg.From[:], pkh[:])
			tmsg.Signatures = append(tmsg.Signatures, sig)
		}

	case *wire.MsgConsensus, *wire.MsgSignature:
		hash := blockchain.MakeMinerSigHash(m.Block(), m.BlockHash())
		k, err := btcec.ParsePubKey(m.GetSignature()[:btcec.PubKeyBytesLenCompressed], btcec.S256())
		if err != nil {
			return false
		}
		s, err := btcec.ParseDERSignature(m.GetSignature()[btcec.PubKeyBytesLenCompressed:], btcec.S256())

		if !s.Verify(hash, k) {
			return false
		}

	default:
		_, err = btcutil.VerifySigScript(m.GetSignature(), m.DoubleHashB(), miner.cfg)
	}

	if err != nil {
		log.Infof("VerifySigScript fail. %v", m)
		return false
	}
	return true
}

func pull(hash chainhash.Hash, h int32, p ReqQueue) {
	t := time.Now().Unix()

	if p == nil {
		if src, ok := miner.knownsrc[hash]; ok {
			p = src
		} else {
			log.Infof("Unable to pull %s because don't know its source", hash.String())
			return
		}
	}

	if _, ok := miner.pulling[hash]; !ok || miner.pulling[hash]+5 < t {
		// pull block
		msg := wire.MsgPull{}
		msg.Height = h
		msg.M = hash
		p.QueueMessage(&msg, nil)

		log.Infof("pull %s at %d from %s", hash.String(), h, p.Addr())

		miner.pulling[hash] = t
	}
}

func UpdateChainHeight(latestHeight int32) {
	if miner.shutdown {
		return
	}
	if miner != nil && miner.updateheight != nil {
		miner.updateheight <- latestHeight
	}
}

func cleaner(top int32) {
	if miner.shutdown {
		return
	}
	for i, t := range miner.Sync {
		if i < top {
			delete(miner.Sync, i)
			t.Quit()
		}
	}
	for i, b := range miner.allblks {
		if b.Height() < top {
			delete(miner.allblks, i)
		}
	}
}

func Shutdown() {
	miner.shutdown = true

	log.Infof("Syners:")
	for h, s := range miner.Sync {
		log.Infof("%d Runnable = %v", h, s.Runnable)
		s.Quit()
	}

	//	DebugInfo()

	select {
	case <-Quit:
	default:
		close(Quit)
	}
	miner.wg.Wait()

	if POWStopper != nil {
		close(POWStopper)
	}

	log.Infof("Consensus Shutdown completed")
}

var seq int32

func (self *Miner) Broadcast(msg wire.OmegaMessage, ps *string) {
	seq++
	msg.SetSeq(seq)
	self.server.Broadcast(msg, ps)
}

func VerifyMsg(msg wire.OmegaMessage, pubkey *btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

/*
func DebugInfo() {
	top := int32(0)
	if miner == nil {
		return
	}
	miner.syncMutex.Lock()
	for h, _ := range miner.Sync {
		if h > top {
			top = h
		}
	}
	log.Infof("\nMiner has %d Syncers\n\nThe top syncer is %d:", len(miner.Sync), top)
	for h, s := range miner.Sync {
		if h < top-2 {
			delete(miner.Sync, h)
			log.Infof("\nStopping %d", h)
			s.Quit()
		}
	}
	log.Infof("\nDone examing syner heights")
	if s, ok := miner.Sync[top]; ok {
		s.DebugInfo()
	}
	miner.syncMutex.Unlock()
}
*/
