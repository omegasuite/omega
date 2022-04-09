/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package consensus

import (
	"bufio"
	"fmt"
	"github.com/omegasuite/btcd/blockchain"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcd/chaincfg/chainhash"
	"github.com/omegasuite/btcd/wire"
	"github.com/omegasuite/btcutil"
	"io"
	"os"

	//	"net/http"
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
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server		 PeerNotifier
	updateheight chan int32
	name [][20]byte

	lastSignedBlock int32
	lwbFile * os.File

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
	if miner == nil || miner.shutdown {
		return
	}

	flags |= blockchain.BFNoConnect
	log.Infof("Consensus.ProcessBlock for block %s at %d, flags=%x", block.Hash().String(), block.Height(), flags)

	if block.Height() < 0 {
		block.SetHeight(int32(block.MsgBlock().Transactions[0].TxIn[0].PreviousOutPoint.Index))
		log.Infof("Force height to %d", block.Height())
	}

	block.ClearSize()
	if newblockch != nil {
		newblockch <- newblock{block, flags}
	}

	log.Infof("newblockch.len queued")
}

func ServeBlock(h * chainhash.Hash) *btcutil.Block {
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

var miner * Miner

var Quit chan struct{}
var POWStopper chan struct{}
var errMootBlock error
var errInvalidBlock error
var connNotice chan interface{}

func (m *Miner) notice (notification *blockchain.Notification) {
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
		if sny != nil {
			log.Infof("SetCommittee for next syner %d", sny.Height)
			sny.SetCommittee()
		} else {
			log.Infof("No pending syners")
		}
		miner.syncMutex.Unlock()
	}
}

func UpdateLastWritten(last int32) bool {
	// write last sign block height to file instead of DB to ensure it is not cached/buffered
	writer := bufio.NewWriter(miner.lwbFile)

	miner.lwbFile.Seek(0, io.SeekStart)
	if last > miner.lastSignedBlock {
		miner.lastSignedBlock = last
		fmt.Fprintf(writer, "%d\n", last)
		writer.Flush()
		miner.lwbFile.Sync()		// do a file flush here
		return true
	}
	log.Infof("UpdateLastWritten: rejected because %d <= %d", last, miner.lastSignedBlock)
	return false
}

func Consensus(s PeerNotifier, dataDir string, addr []btcutil.Address, cfg *chaincfg.Params) {
	miner = &Miner{}
	miner.server = s
	miner.cfg = cfg
	miner.updateheight = make(chan int32, 200)
	miner.lastSignedBlock = 0

	lwbFile := dataDir + "/lastsignedblock"

	fp, err := os.Open(lwbFile)
	if fp != nil && err != io.EOF {
		reader := bufio.NewReader(fp)
		line, err := reader.ReadString('\n')
		if err == nil {
			fmt.Sscanf(line, "%d", &miner.lastSignedBlock)
		}
	}
	fp.Close()

	miner.lwbFile, err = os.OpenFile(lwbFile, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0600)
	defer miner.lwbFile.Close()

	if err != nil {
		log.Infof("UpdateLastWritten: unable to open %s", lwbFile)
		return
	}

	s.SubscribeChain(miner.notice)

	connNotice = make(chan interface{}, 10)

	miner.Sync = make(map[int32]*Syncer, 0)
	miner.syncMutex = sync.Mutex{}

	miner.name = make([][20]byte, len(addr))
	for i,name := range addr {
		copy(miner.name[i][:], name.ScriptAddress())
	}

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
		case height := <-miner.updateheight:
			log.Infof("Consensus <-miner.updateheight %d", height)
			miner.syncMutex.Lock()
			cleaner(height)
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}
			miner.syncMutex.Unlock()

		case c := <- connNotice:
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

		case <- Quit:
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

	s.SetCommittee()
	miner.syncMutex.Unlock()

	var hash * chainhash.Hash

	if !s.Runnable {
		log.Infof("syncer is not ready for height %d, message will be queued. Current que len = %d", h, len(s.commands))

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

		if len(s.commands) > 1 {
			hash = nil
		}

		if len(s.commands) > (wire.CommitteeSize - 1) * 10 {
			log.Infof("too many messages are queued. Discard oldest one.")
			<- s.commands
		}
	}

	if len(s.commands) > (wire.CommitteeSize - 1) * 10 {
		log.Infof("Runnable syner %d has too many (%d) messages queued. Discard oldest one.", s.Height, len(s.commands))
		<- s.commands
		s.DebugInfo()
//		return false, nil
	}

	s.commands <- m

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
	for i, t := range miner.Sync {
		if i < top {
			delete(miner.Sync, i)
			t.Quit()
		}
	}
}

func Shutdown() {
	miner.shutdown = true

	log.Infof("Syners:")
	for h,s := range miner.Sync {
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

func VerifyMsg(msg wire.OmegaMessage, pubkey * btcec.PublicKey) bool {
	signature, err := btcec.ParseSignature(msg.GetSignature(), btcec.S256())
	if err != nil {
		return false
	}
	valid := signature.Verify(msg.DoubleHashB(), pubkey)
	return valid
}

func DebugInfo() {
	top := int32(0)
	if miner == nil {
		return
	}
	miner.syncMutex.Lock()
	for h,_ := range miner.Sync {
		if h > top {
			top = h
		}
	}
	log.Infof("\nMiner has %d Syncers\n\nThe top syncer is %d:", len(miner.Sync), top)
	for h,s := range miner.Sync {
		if h < top - 2 {
			delete(miner.Sync, h)
			log.Infof("\nStopping %d", h)
			s.Quit()
		}
	}
	log.Infof("\nDone examing syner heights")
	if s,ok := miner.Sync[top]; ok {
		s.DebugInfo()
	}
	miner.syncMutex.Unlock()
}