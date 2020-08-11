// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/omegasuite/btcd/chaincfg"
	"github.com/omegasuite/btcutil"
)

var BlockSizerQuit chan struct {}
type sizerAct struct{
	action int32
	result chan uint32
}
var queue chan sizerAct

// BlockSizeUpdater must run as a go routine
func (b *BlockChain) BlockSizeUpdater() {
	BlockSizerQuit = make(chan struct{})
	queue = make(chan sizerAct, 1000)

	if len(b.blockSizer.knownLimits) == 0 {
		b.blockSizer.knownLimits[0] = chaincfg.BlockBaseSize
	}

	log.Infof("BlockSizeUpdater: initial state: %v", b.blockSizer)

	for {
		select {
		case <-BlockSizerQuit:
			return

		case act := <-queue:
			if act.result != nil {
				if z, ok := b.blockSizer.knownLimits[act.action]; ok {
					act.result <- z
					continue
				}
			}

			log.Debugf("BlockSizeUpdater action = %d", act.action)

			if act.action < 0 {
				h := -act.action - (-act.action)%chaincfg.BlockSizeEvalPeriod
				h += chaincfg.BlockSizeEvalPeriod

				b.blockSizer.mtx.Lock()
				_, ok := b.blockSizer.knownLimits[h]
				if ok && -act.action <= h-chaincfg.SkipBlocks {
					delete(b.blockSizer.knownLimits, h)
					b.blockSizer.reset(0)
				}
				b.blockSizer.mtx.Unlock()
				continue
			}

			h := act.action - act.action%chaincfg.BlockSizeEvalPeriod

			var runto int32
			if act.result != nil {
				runto = h - chaincfg.BlockSizeEvalPeriod - chaincfg.SkipBlocks
				if runto < 0 {
					runto = 0
				}
			} else {
				b.blockSizer.mtx.Lock()
				_, ok := b.blockSizer.knownLimits[h]
				if ok {
					h += chaincfg.BlockSizeEvalPeriod
					_, ok = b.blockSizer.knownLimits[h]
					if ok {
						b.blockSizer.mtx.Unlock()
						continue
					}

					// forward going
					if act.action < h-chaincfg.StartEvalBlocks {
						b.blockSizer.mtx.Unlock()
						continue
					}

					if b.blockSizer.target != h || b.blockSizer.lastNode == nil {
						runto = h - chaincfg.SkipBlocks
					} else {
						t := h - act.action
						g := b.blockSizer.lastNode.Height - h + chaincfg.BlockSizeEvalPeriod + chaincfg.SkipBlocks
						s := (g / t) + 1
						if s < 20 {
							s = 20
						}
						runto = b.blockSizer.lastNode.Height - s
						if runto < h-chaincfg.BlockSizeEvalPeriod-chaincfg.SkipBlocks {
							runto = h - chaincfg.BlockSizeEvalPeriod - chaincfg.SkipBlocks
						}
					}
				} else {
					runto = h - chaincfg.BlockSizeEvalPeriod - chaincfg.SkipBlocks
					if runto < 0 {
						runto = 0
					}
				}
				b.blockSizer.mtx.Unlock()
			}

			if b.blockSizer.target != h {
				b.blockSizer.reset(h)
			}
			if b.blockSizer.lastNode == nil {
				b.blockSizer.lastNode = b.BestChain.NodeByHeight(h - chaincfg.SkipBlocks)
			}

			log.Infof("blockSizer accounting %d - %d by act @ %d", b.blockSizer.lastNode.Height, runto, act.action)

			p := b.blockSizer.lastNode.Parent
			for i := b.blockSizer.lastNode.Height - 1; i >= runto && p != nil; i-- {
				if p.Data.GetNonce() < 0 {
					q, _ := b.BlockByHash(&p.Hash)
					if q == nil {
						// this may happen during shutdown
						runto = -1
						break
					}
					b.blockSizer.blockCount++
					b.blockSizer.sizeSum += int64(len(q.MsgBlock().Transactions))
					b.blockSizer.timeSum += b.blockSizer.lastNode.Data.TimeStamp() - p.Data.TimeStamp()
				}
				b.blockSizer.lastNode = p
				p = p.Parent
			}
			if runto == 0 || runto == h-chaincfg.BlockSizeEvalPeriod-chaincfg.SkipBlocks {
				log.Infof("blockSizer stats: blockCount = %d, sizeSum = %d timeSum = %d",
					b.blockSizer.blockCount, b.blockSizer.sizeSum, b.blockSizer.timeSum)

				b.conclude()
				b.blockSizer.reset(0)

				if len(b.blockSizer.knownLimits) >= 5 {
					delete(b.blockSizer.knownLimits, h-4*chaincfg.BlockSizeEvalPeriod)
				}
				if act.result != nil {
					act.result <- b.blockSizer.knownLimits[h]
				}
			}
		}
	}

	// drain the queue
	for {
		select {
		case <-queue:
		}
	}
}

func (b *BlockChain) GetBlockLimit(ht int32) uint32 {
	// block limit in number of tx
	if ht < 0 {
		return 0
	}
	if ht < chaincfg.BlockSizeEvalPeriod {
		return chaincfg.BlockBaseSize
	}

	h := ht - ht % chaincfg.BlockSizeEvalPeriod

	b.blockSizer.mtx.Lock()
	z, ok := b.blockSizer.knownLimits[h]
	b.blockSizer.mtx.Unlock()

	if ok {
		if _, ok := b.blockSizer.knownLimits[h + chaincfg.BlockSizeEvalPeriod];	!ok && ht >= h + chaincfg.BlockSizeEvalPeriod - chaincfg.StartEvalBlocks {
			queue <- sizerAct{ht, nil}
		}
		return z
	}

	reply := make(chan uint32)
	queue <- sizerAct {h, reply }
	return <-reply
}

func (b *sizeCalculator) RollBackTo(h int32) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for i,_ := range b.knownLimits {
		if h <= i - chaincfg.SkipBlocks {
			// most likely it would never happend, because it require roll back of 2000 blks
			delete(b.knownLimits, i)
		}
	}
}

func (b *sizeCalculator) reset(h int32) {
	b.lastNode = nil
	b.blockCount = 0
	b.sizeSum = 0
	b.timeSum = 0
	b.target = h
}

func (c *BlockChain) conclude() {
	b := c.blockSizer
	h := b.target
/*
	defer func() {
		c.db.Update(func(dbTx database.Tx) error {
			state = *(c.BestSnapshot())
			state.sizeLimits = b.knownLimits
			err := dbPutBestState(dbTx, state)
			if err != nil {
				return err
			}
			return nil
		})
	}()
*/

	if b.blockCount == 0 {
		b.knownLimits[h] = chaincfg.BlockBaseSize
		return
	}

	// conclude calculation for a batch
	avgSize := b.sizeSum / int64(b.blockCount)
	if avgSize <= chaincfg.BlockBaseSize {
		b.knownLimits[h] = chaincfg.BlockBaseSize
		b.reset(0)
		return
	}

	avgTime := b.timeSum / int64(b.blockCount)

	csz := int64(chaincfg.BlockBaseSize)
	if avgTime >= chaincfg.TargetBlockRate {
		avgSize = (avgSize * chaincfg.TargetBlockRate) / avgTime
	}

	for csz < avgSize {
		csz <<= 1
	}

	b.reset(0)

	if avgSize * 10 > csz * 6 {		// 60% full. increase size
		csz <<= 1
	}
	b.knownLimits[h] = uint32(csz)
}

func (b *BlockChain) BlockSizerNotice(notification *Notification) {
	switch notification.Data.(type) {
	case *btcutil.Block:
		block := notification.Data.(*btcutil.Block).Height()

		switch notification.Type {
		case NTBlockConnected:
			queue <- sizerAct {block, nil }

		case NTBlockDisconnected:
			queue <- sizerAct {-block, nil }
		}
	}
}
