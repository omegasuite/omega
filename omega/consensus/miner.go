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
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"net/http"
	"sync"
//	"time"
)

const (
	maxTxPerBlock = 50000
)

type Message interface {
	Block() int32
	Sign(key *btcec.PrivateKey)
	DoubleHashB() []byte
	GetSignature() []byte
	Sender() []byte
	Command() string
}

var Debug        int // hash of last block

type PeerNotifier interface {
	MyPlaceInCommittee(r int32) int32
	CommitteeMsg([20]byte, int32, wire.Message) bool
	CommitteeMsgMG([20]byte, int32, wire.Message)
	NewConsusBlock(block *btcutil.Block)
	GetPrivKey([20]byte) *btcec.PrivateKey
	BestSnapshot() *blockchain.BestState
	MinerBlockByHeight(int32) (*wire.MinerBlock, error)
	SubscribeChain(func(*blockchain.Notification))
	CommitteePolling()
	ChainSync(chainhash.Hash, [20]byte)
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server		 PeerNotifier
	updateheight chan int32
	name [20]byte

	cfg *chaincfg.Params

	// wait for end of task
	wg          sync.WaitGroup
	shutdown bool
}

type newblock struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

var newblockch chan newblock
// var newheadch chan newhead

func ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) {
	if miner.shutdown {
		return
	}

	flags |= blockchain.BFNoConnect
	log.Infof("Consensus.ProcessBlock for block %s at %d, flags=%x",
		block.Hash().String(), block.Height(), flags)

	log.Infof("newblockch.len = %d", len(newblockch))

	newblockch <- newblock { block, flags }

	log.Infof("newblockch.len queued")
}

func ServeBlock(h * chainhash.Hash) *btcutil.Block {
	if miner.shutdown {
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

var miner * Miner

var Quit chan struct{}
var POWStopper chan struct{}
var errMootBlock error
var errInvalidBlock error

func (m *Miner) notice (notification *blockchain.Notification) {
	switch notification.Type {
	case blockchain.NTBlockConnected:
		switch notification.Data.(type) {
		case *wire.MinerBlock:
			b := notification.Data.(*wire.MinerBlock)
			h := b.Height()

			log.Infof("new miner block at %d connected", h)

			miner.syncMutex.Lock()
			for _,s := range miner.Sync {
				if s.Base > h - wire.CommitteeSize && s.Base <= h && !s.Runnable {
					s.SetCommittee()
				}
			}
			miner.syncMutex.Unlock()

		case *btcutil.Block:
			b := notification.Data.(*btcutil.Block)
			h := b.Height()

			log.Infof("new tx block at %d connected", h)
			var sny * Syncer

			miner.syncMutex.Lock()
			next := int32(0x7FFFFFFF)
			for n,s := range miner.Sync {
				if n > h && n < next {
					next = n
				} else if n <= h {
					delete(miner.Sync, n)
					go s.Quit()
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
}

func CommitteePolling() {
	miner.server.CommitteePolling()
	DebugInfo()
}

func Consensus(s PeerNotifier, addr btcutil.Address, cfg *chaincfg.Params) {
	miner = &Miner{}
	miner.server = s
	miner.cfg = cfg
	miner.updateheight = make(chan int32)

	s.SubscribeChain(miner.notice)

	miner.Sync = make(map[int32]*Syncer, 0)
	miner.syncMutex = sync.Mutex{}

	var name [20]byte
	copy(name[:], addr.ScriptAddress())
	miner.name = name

	newblockch = make(chan newblock, 2 * wire.CommitteeSize)
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
/*
		case <-ticker.C:
			best := miner.server.BestSnapshot()
			log.Infof("Best tx chain height: %d Last rotation: %d", best.Height, best.LastRotation)

			top := int32(-1)
			var tr *Syncer

			miner.syncMutex.Lock()
			for h, s := range miner.Sync {
				if h > top {
					top = h
				}
				if s.Runnable {
					if tr == nil || s.Height > tr.Height {
						tr = s
					}
				}
			}
			miner.syncMutex.Unlock()
 */

		case height := <-miner.updateheight:
			log.Infof("updateheight %d", height)
			cleaner(height)
			miner.syncMutex.Lock()
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}
			miner.syncMutex.Unlock()
			log.Infof("updateheight done")

		case blk := <-newblockch:
			top := miner.server.BestSnapshot().Height
			bh := blk.block.Height()
			log.Infof("miner received newblock %s at %d vs. %d",
				blk.block.Hash().String(), top, bh)

			if bh <= top {
				log.Infof("newblock ignored")
				continue
			}

			if len(blk.block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSigs {
				// should never gets here
				log.Infof("Block is a consensus. Accept it and close processing for height %d.", bh)
				continue
			}

			miner.syncMutex.Lock()
			if _, ok := miner.Sync[bh]; !ok {
				log.Infof(" CreateSyncer at %d", bh)
				miner.Sync[bh] = CreateSyncer(bh)
			}
			log.Infof(" BlockInit at %d for block %s", bh, blk.block.Hash().String())
			snr := miner.Sync[bh]
			miner.syncMutex.Unlock()

			if POWStopper != nil {
				if len(POWStopper) < wire.CommitteeSize {
					POWStopper <- struct{}{}
				} else {
					log.Infof("len(POWStopper) = %d", len(POWStopper))
				}
			}
			snr.BlockInit(blk.block)
			log.Infof("newblock initialized")

		case <- Quit:
			log.Info("consensus received Quit")
			polling = false
//			ticker.Stop()
//			DebugInfo()
			break out
		}
	}

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

		default:
			log.Info("consensus quits")
			return
		}
	}
}

func HandleMessage(m Message) (bool, * chainhash.Hash) {
	if miner == nil || miner.shutdown {
		return false, nil
	}

	// the messages here are consensus messages. specifically, it does not include block msg.
	h := m.Block()
	bh := miner.server.BestSnapshot().Height

	if h <= bh {
		return true, nil
	}

	miner.syncMutex.Lock()
	s, ok := miner.Sync[h]

	if !ok {
		miner.Sync[h] = CreateSyncer(h)
		s = miner.Sync[h]
	} else if miner.Sync[h].Done {
		miner.syncMutex.Unlock()
		log.Infof("syncer has finished with %h. Ignore this message", h)
		return false, nil
	}
	miner.syncMutex.Unlock()
	
//	log.Infof("miner dispatching Message for height %d", m.Block())

	s.SetCommittee()

	var hash * chainhash.Hash

	if !s.Runnable {
		log.Infof("syncer is not ready for height %d, message will be queued. Current que len = %d", h, len(s.messages))

		switch m.(type) {
		case *wire.MsgKnowledge:
			hash = &m.(*wire.MsgKnowledge).M

		case *wire.MsgCandidate:
			hash = &m.(*wire.MsgCandidate).M

		case *wire.MsgCandidateResp:
			hash = &m.(*wire.MsgCandidateResp).M

		case *wire.MsgRelease:
			hash = &m.(*wire.MsgRelease).M

		case *wire.MsgConsensus:
			hash = &m.(*wire.MsgConsensus).M

		case *wire.MsgSignature:
			hash = &m.(*wire.MsgSignature).M
		}

		if len(s.messages) > 1 {
			hash = nil
		}

		if len(s.messages) > (wire.CommitteeSize - 1) * 10 {
			log.Infof("too many messages are queued. Discard.")
			return false, nil
		}
	}

	if len(s.messages) > (wire.CommitteeSize - 1) * 10 {
		log.Infof("Runnable syner has too many (%d) messages queued.", len(s.messages))
		s.DebugInfo()
	}

	s.messages <- m

	return false, hash
}

func UpdateChainHeight(latestHeight int32) {
	if miner.shutdown {
		return
	}
	if miner != nil {
		miner.updateheight <- latestHeight
	}
}

func cleaner(top int32) {
	if miner.shutdown {
		return
	}
	miner.syncMutex.Lock()
	for i, t := range miner.Sync {
		if i < top {
			delete(miner.Sync, i)
			go t.Quit()
		}
	}
	miner.syncMutex.Unlock()
}

func Shutdown() {
	miner.shutdown = true

	log.Infof("Syners:")
	for h,s := range miner.Sync {
		log.Infof("%d Runnable = %v", h, s.Runnable)
	}

	DebugInfo()

	select {
	case <-Quit:
	default:
		close(Quit)
	}
	miner.wg.Wait()
	log.Infof("Consensus Shutdown completed")
}

func VerifyMsg(msg wire.OmegaMessage, pubkey * btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

func (self *Miner) Debug(w http.ResponseWriter, r *http.Request) {
}

func DebugInfo() {
	top := int32(0)
	miner.syncMutex.Lock()
	for h,_ := range miner.Sync {
		if h > top {
			top = h
		}
	}
	log.Infof("\nI am %x. Miner has %d Syncers\n\nThe top syncer is %d:", miner.name, len(miner.Sync), top)
	for h,s := range miner.Sync {
		if h < top - 2 {
			delete(miner.Sync, h)
			log.Infof("\nStopping %d", h)
			go s.Quit()
		}
	}
	log.Infof("\nDone examing syner heights")
	if s,ok := miner.Sync[top]; ok {
		if len(s.repeating) == 0 && s.Runnable {
			log.Infof("\nSendng repeating to %d", top)
			s.repeating <- struct{}{}
		}
		s.DebugInfo()
	}
	miner.syncMutex.Unlock()
}