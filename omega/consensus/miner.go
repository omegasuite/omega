package consensus

import (
	"fmt"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"net/http"
	"sync"
	"time"
)

const (
	maxTxPerBlock = 50000
)

type Message interface {
	Block() int32
}

var Debug        int // hash of last block

type PeerNotifier interface {
	MyPlaceInCommittee(r int32) int32
	CommitteeMsg([20]byte, wire.Message) bool
	CommitteeCast(wire.Message)
	CommitteeMsgMG([20]byte, wire.Message, int32)
	CommitteeCastMG([20]byte, wire.Message, int32)
	NewConsusBlock(block * btcutil.Block)
	GetPrivKey([20]byte) * btcec.PrivateKey
	BestSnapshot() * blockchain.BestState
	MinerBlockByHeight(int32) (* wire.MinerBlock,error)
	SubscribeChain(func (*blockchain.Notification))
	CommitteePolling()
}

type Miner struct {
	syncMutex    sync.Mutex
	Sync         map[int32]*Syncer
	server		 PeerNotifier
	updateheight chan int32
	name [20]byte

	// wait for end of task
	wg          sync.WaitGroup
}

type newblock struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
}

/*
type newhead struct {
	chain *blockchain.BlockChain
	head *MsgMerkleBlock
	flags blockchain.BehaviorFlags
}

 */

var newblockch chan newblock
// var newheadch chan newhead

func ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) {
	flags |= blockchain.BFNoConnect
	log.Infof("Consensus.ProcessBlock for block %s at %d, flags=%x",
		block.Hash().String(), block.Height(), flags)

	newblockch <- newblock { block, flags }
}

/*
func ProcessHeader(b *blockchain.BlockChain, block *MsgMerkleBlock) {
	flags := blockchain.BFNoConnect
	fmt.Printf("Consensus for header at %d", block.Height)
	newheadch <- newhead { b,block, flags }
}
*/

var miner * Miner

var Quit chan struct{}
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

			miner.syncMutex.Lock()
			if _, ok := miner.Sync[h+1]; ok && !miner.Sync[h+1].Runnable {
				miner.Sync[h+1].SetCommittee()
			}
			for t,s := range miner.Sync {
				if t < h {
					go s.Quit()
					delete(miner.Sync, t)
				}
			}
			miner.syncMutex.Unlock()
		}
	}
}

func Consensus(s PeerNotifier, addr btcutil.Address) {
	miner = &Miner{}
	miner.server = s
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

	defer miner.wg.Wait()

	log.Info("Consensus running")
	miner.wg.Add(1)

	ticker := time.NewTicker(time.Second * 10)

	defer miner.wg.Done()

	polling := true
	out:
	for polling {
		select {
		case <-ticker.C:
			best := miner.server.BestSnapshot()
			log.Infof("\nBest tx chain height: %d", best.Height)
			log.Infof("\nLast rotation: %d", best.LastRotation)

			DebugInfo()

			top := int32(-1)
			var tr *Syncer

			log.Infof("Poll Entering syncMutex.Lock")
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
			log.Infof("Poll Left syncMutex.Lock")

			log.Infof("\nTop Syncer: %d", top)
			if tr != nil {
				log.Infof("\nTop running Syncer: %d\n", tr.Height)
			}
			miner.server.CommitteePolling()

		case height := <- miner.updateheight:
			log.Infof("updateheight %d", height)
			cleaner(height)
			miner.syncMutex.Lock()
			for _, t := range miner.Sync {
				t.UpdateChainHeight(height)
			}
			miner.syncMutex.Unlock()

		case blk := <- newblockch:
			top := miner.server.BestSnapshot().Height
			bh := blk.block.Height()
			log.Infof("miner received newblockch %s at %d vs. %d",
				blk.block.Hash().String(), top, bh)

			if bh <= top {
				continue
			}

			if len(blk.block.MsgBlock().Transactions[0].SignatureScripts) > wire.CommitteeSize / 2 + 1 {
				// should never gets here
				log.Infof("Block is a consensus. Accept it and close processing for height %d.", bh)
				continue
/*
				miner.syncMutex.Lock()
				if _, ok := miner.Sync[bh]; ok {
					miner.Sync[bh].Quit()
					miner.syncMutex.Unlock()
//					delete(miner.Sync, bh)
					continue
				}
				miner.syncMutex.Unlock()
 */
			}

//			cleaner(top)
			miner.syncMutex.Lock()
			if _, ok := miner.Sync[bh]; !ok {
				log.Infof(" CreateSyncer at %d", bh)
				miner.Sync[bh] = CreateSyncer(bh)
			}
			log.Infof(" BlockInit at %d for block %s", bh, blk.block.Hash().String())
			miner.Sync[bh].BlockInit(blk.block)
			miner.syncMutex.Unlock()
/*
		case head := <- newheadch:
			top := head.chain.BestSnapshot().Height
//			cleaner(top)
			if head.head.Height < top {
				continue
			}

			if _, ok := miner.Sync[head.head.Height]; !ok {
				miner.Sync[head.head.Height] = CreateSyncer()
			}
			if !miner.Sync[head.head.Height].Initialized {
				miner.Sync[head.head.Height].Initialize(head.chain, head.head.Height)
			}
			miner.Sync[head.head.Height].HeaderInit(head.head)
*/
		case <- Quit:
			log.Info("consensus received Quit")
			polling = false
			ticker.Stop()
			DebugInfo()
			miner.syncMutex.Lock()
			for i, t := range miner.Sync {
				log.Infof("Sync %d to Quit", i)
				t.Quit()
				delete(miner.Sync, i)
			}
			miner.syncMutex.Unlock()
			break out
		}
	}

	for true {
		select {
		case <-miner.updateheight:
		case <-newblockch:
//		case <-newheadch:

		default:
			log.Info("consensus quits")
			return
		}
	}
}

func HandleMessage(m Message) * chainhash.Hash {
	// the messages here are consensus messages. specifically, it does not include block msg.
	h := m.Block()
	bh := miner.server.BestSnapshot().Height

	if h < bh {
//		miner.server.CommitteePolling()
		return nil
	}

	miner.syncMutex.Lock()
	s, ok := miner.Sync[h]

	if !ok {
		miner.Sync[h] = CreateSyncer(h)
		s = miner.Sync[h]
	} else if miner.Sync[h].Done {
		miner.syncMutex.Unlock()
		log.Infof("syncer has finished with %h. Ignore this message", h)
		return nil
	}
	miner.syncMutex.Unlock()
	
//	log.Infof("miner dispatching Message for height %d", m.Block())

	s.SetCommittee()

	var hash * chainhash.Hash

	if !s.Runnable {
		log.Infof("syncer is not ready for height %d, message will be queues. Current que len = %d", h, len(s.messages))

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
	}

	s.messages <- m

	return hash
}

func UpdateChainHeight(latestHeight int32) {
	if miner != nil {
		miner.updateheight <- latestHeight
	}
}

func cleaner(top int32) {
	miner.syncMutex.Lock()
	for i, t := range miner.Sync {
		if i < top {
			t.Quit()
			delete(miner.Sync, i)
		}
	}
	miner.syncMutex.Unlock()
}

func Shutdown() {
	close(Quit)
	miner.wg.Wait()
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
	log.Infof("\nI am %x. Miner has %d Syncers\n\n", miner.name, len(miner.Sync))
	top := int32(0)
	miner.syncMutex.Lock()
	for h,_ := range miner.Sync {
		if h > top {
			top = h
		}
	}
	for h,_ := range miner.Sync {
		if h < top - 2 {
			delete(miner.Sync, h)
		}
	}
	for h,s := range miner.Sync {
		log.Infof("Syncer at %d", h)
		s.DebugInfo()
	}
	miner.syncMutex.Unlock()
}