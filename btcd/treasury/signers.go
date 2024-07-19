// Copyright (c) 2024-2024 The Omegasuite developers
// Use of this source code is governed by applicable
// patent laws.

package treasury

import (
	"fmt"
	"github.com/omegasuite/btcd/btcec"
	"github.com/omegasuite/famofchains/btcd/database"
	"github.com/omegasuite/famofchains/btcd/wire"
	"github.com/omegasuite/famofchains/btcd/wire/common"
)

var PrivKeys []*btcec.PrivateKey

type PlgAsset struct {
	Utxo     wire.OutPoint
	Amount   uint64
	Firstuse uint32 // height when it becomes a signer
}

func (p *PlgAsset) serialize() []byte {
	var res []byte

	res = make([]byte, 48)
	copy(res, p.Utxo.ToBytes())
	common.LittleEndian.PutUint64(res[36:], p.Amount)
	common.LittleEndian.PutUint32(res[44:], p.Firstuse)

	return res[:]
}

func (p *PlgAsset) deserialize(d []byte) (int, error) {
	if len(d) < 36+4 {
		return 0, fmt.Errorf("Insufficient asset data")
	}
	f := 0
	if len(d) < 48 {
		f++
	}
	p.Utxo.Hash.SetBytes(d[f : f+32])
	p.Utxo.Index = common.LittleEndian.Uint32(d[f+32 : f+36])
	p.Amount = common.LittleEndian.Uint64(d[f+36:])
	if len(d) >= 48 {
		p.Firstuse = common.LittleEndian.Uint32(d[f+44:])
		return 48, nil
	}

	return 1 + 36 + 8, nil
}

type Signers struct {
	Address   [20]byte    // Address of signer
	Pubkey    []byte      // Pubkey of signer
	Voting    uint8       // Voting power in %
	Retiring  bool        // whether is Retiring
	Joined    uint32      // height when it becomes a signer
	Pledged   []*PlgAsset // Assets Pledged
	Btcprofit uint64      // profits in BTC
}

func (s *Signers) serialize() []byte {
	res := make([]byte, 8)
	res[0] = 0
	if s.Retiring {
		res[0] = 1
	}
	res[1] = s.Voting
	common.LittleEndian.PutUint32(res[2:], s.Joined)
	res[6] = uint8(len(s.Pubkey))
	res[7] = uint8(len(s.Pledged))
	res = append(res, s.Pubkey...)
	for _, plg := range s.Pledged {
		res = append(res, plg.serialize()...)
	}

	var h [8]byte
	common.LittleEndian.PutUint64(h[:], s.Btcprofit)
	res = append(res, h[:]...)

	return res
}

func (s *Signers) Deserialize(p []byte) (int, error) {
	if p[0] == 0 {
		s.Retiring = false
	} else {
		s.Retiring = true
	}
	s.Voting = p[1]
	s.Joined = common.LittleEndian.Uint32(p[2:])
	s.Pubkey = make([]byte, p[6])
	if p[6] == 20 { // tmp code
		return 6, fmt.Errorf("error")
	}
	copy(s.Pubkey, p[8:8+p[6]])
	d := p[7]
	n := int(8 + p[6])
	for ; n < len(p); d-- {
		plg := &PlgAsset{}
		m, err := plg.deserialize(p[n:])
		if err != nil {
			return n, err
		}
		n += m
		s.Pledged = append(s.Pledged, plg)
	}
	if d != 0 {
		return n, fmt.Errorf("Incorrect signer data")
	}
	s.Btcprofit = 0
	if n < len(p) {
		s.Btcprofit = common.LittleEndian.Uint64(p[n:])
		n += 8
	}
	return n, nil
}

func IsPledged(u *wire.OutPoint) bool {
	return collaterals.Exists(u)
}

func Declared(miner [20]byte) bool {
	_, ok := signers[miner]
	return ok
}

func Declare(dbTx database.Tx, miner [20]byte, pubkey []byte, height uint32) {
	if _, ok := signers[miner]; ok {
		return
	}

	sn := &Signers{
		Retiring: false,
		Address:  miner,
		Joined:   height,
		Pledged:  []*PlgAsset{},
	}

	sn.Pubkey = make([]byte, len(pubkey))
	copy(sn.Pubkey, pubkey)
	if len(signers) == 0 {
		eldest = sn
	}
	signers[miner] = sn

	bucket := dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	bucket.Put(miner[:], sn.serialize())
}

func UnDeclare(dbTx database.Tx, miner [20]byte) {
	if sn, ok := signers[miner]; !ok {
		return
	} else {
		if eldest == sn {
			return
		}

		delete(signers, miner)

		bucket := dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
		bucket.Delete(miner[:])
	}
}

func UnPledge(dbTx database.Tx, u *wire.OutPoint, miner [20]byte) error {
	sn, ok := signers[miner]
	if !ok {
		return fmt.Errorf("Pledge before declaration")
	}

	has := false
	var amount int64
	for i, p := range sn.Pledged {
		if u.Equal(&p.Utxo) {
			has = true
			amount = int64(p.Amount)
			sn.Pledged = append(sn.Pledged[:i], sn.Pledged[i+1:]...)
			break
		}
	}
	if !has {
		return nil
	}

	totalOmg -= uint64(amount)
	collaterals.Delete(u)

	bucket := dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	for w, s := range signers {
		s.Voting = VotingPower(w)
		bucket.Put(w[:], s.serialize())
	}
	return nil
}

func Pledge(dbTx database.Tx, u *wire.OutPoint, miner [20]byte, amount int64, height uint32) error {
	sn, ok := signers[miner]
	if !ok {
		return fmt.Errorf("Pledge before declaration")
	}

	for _, p := range sn.Pledged {
		if u.Equal(&p.Utxo) {
			return nil
		}
	}

	plg := &PlgAsset{
		Utxo:     *u,
		Amount:   uint64(amount),
		Firstuse: height,
	}

	totalOmg += plg.Amount

	collaterals.Add(u)
	sn.Pledged = append(sn.Pledged, plg)

	bucket := dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	for w, s := range signers {
		s.Voting = VotingPower(w)
		bucket.Put(w[:], s.serialize())
	}
	return nil
}

func VotingPower(owner [20]byte) uint8 {
	s, ok := signers[owner]
	if !ok {
		return 0
	}
	if s.Retiring {
		return 0
	}
	omgs := uint64(0)
	for _, t := range s.Pledged {
		omgs += t.Amount
	}
	p := uint32(omgs) * 10000 / uint32(totalOmg)
	return uint8(p / 100)
}

func IsMatching(script []byte) bool {
	return isMatching(script) >= 0
}

func Matching(script []byte) int32 {
	return isMatching(script)
}

func isMatching(script []byte) int32 {
	// check if it is a transaction that transfers asset to Layer 2
	// 1. To a designated MS Address holding Bitcoins for bridge
	// 2. To a designated Address holding OMNI assets for bridge
	// 3. To a designated Address holding BRC20 assets for bridge
	// 4. To a designated Address holding SRC20 assets for bridge

	if IsOmni(script) {
		return 1
	}
	if IsBRC20(script) {
		return 2
	}
	if IsSRC20(script) {
		return 3
	}

	if len(script) < 26 {
		return -1
	}

	return -1
}

func matchsigners(script []byte) (bool, []byte, []*Signers, byte) {
	// check if it is a transaction that transfers asset to Layer 2
	// 1. To a designated MS Address holding Bitcoins for bridge
	// 2. To a designated Address holding OMNI assets for bridge
	// 3. To a designated Address holding BRC20 assets for bridge
	// 4. To a designated Address holding SRC20 assets for bridge

	if IsOmni(script) {
		return false, nil, nil, 0
	}
	if IsBRC20(script) {
		return false, nil, nil, 0
	}
	if IsSRC20(script) {
		return false, nil, nil, 0
	}

	if len(script) < 26 {
		return false, nil, nil, 0
	}

	sig := make([]*Signers, 0)

	return true, nil, sig, 0
}

func PlantoRetire(dbTx database.Tx, who [20]byte) {
	s, ok := signers[who]
	if !ok || s.Retiring {
		return
	}
	s.Retiring = true
	bucket := dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	bucket.Put(who[:], s.serialize())

	if s == eldest {
		eldest = nil
		for _, s := range signers {
			if s.Retiring {
				continue
			}
			if eldest == nil || s.Joined < eldest.Joined {
				eldest = s
			}
		}
	}
}

func UnPlantoRetire(dbTx database.Tx, who [20]byte) {
	s, ok := signers[who]
	if !ok || !s.Retiring {
		return
	}
	s.Retiring = false
	mydb.Update(func(tx database.Tx) error {
		bucket := tx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
		bucket.Put(who[:], s.serialize())
		return nil
	})
}

func Retire(dbTx database.Tx, who [20]byte, height uint32) {
	if !MayRetire(who) {
		return
	}
	s := signers[who]
	for _, p := range s.Pledged {
		collaterals.Delete(&p.Utxo)
		totalOmg -= p.Amount
	}
	delete(signers, who)

	bucket := dbTx.Metadata().Bucket([]byte(common.RetiredBRIDGESIGNERS))
	var h [28]byte
	common.LittleEndian.PutUint32(h[:], height)
	copy(h[4:], who[:])
	bucket.Put(h[:], s.serialize())

	bucket = dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	bucket.Delete(who[:])
	for w, s := range signers {
		s.Voting = VotingPower(w)
		bucket.Put(w[:], s.serialize())
	}
}

func UnRetire(dbTx database.Tx, who [20]byte, height uint32) {
	_, ok := signers[who]
	if ok {
		return
	}

	bucket := dbTx.Metadata().Bucket([]byte(common.RetiredBRIDGESIGNERS))
	var h [28]byte
	common.LittleEndian.PutUint32(h[:], height)
	copy(h[4:], who[:])
	d := bucket.Get(h[:])

	sn := &Signers{}
	sn.Deserialize(d)
	signers[sn.Address] = sn
	for _, p := range sn.Pledged {
		collaterals.Add(&p.Utxo)
		totalOmg += p.Amount
	}

	bucket.Delete(h[:])

	bucket = dbTx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
	for w, s := range signers {
		s.Voting = VotingPower(w)
		bucket.Put(w[:], s.serialize())
	}
}

func Withdraw(u *wire.OutPoint) error {
done:
	for k, s := range signers {
		for i, p := range s.Pledged {
			if p.Utxo.Hash.IsEqual(&u.Hash) && p.Utxo.Index == u.Index {
				totalOmg -= p.Amount
				if len(s.Pledged) == 1 {
					mydb.Update(func(tx database.Tx) error {
						bucket := tx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
						bucket.Delete(k[:])
						return nil
					})
					delete(signers, k)
					break done
				}
				if i == len(s.Pledged)-1 {
					s.Pledged = s.Pledged[:i]
				} else if i == 0 {
					s.Pledged = s.Pledged[1:]
				} else {
					s.Pledged = append(s.Pledged[:i], s.Pledged[i+1:]...)
				}
				mydb.Update(func(tx database.Tx) error {
					bucket := tx.Metadata().Bucket([]byte(common.BRIDGESIGNERS))
					v := make([]byte, 0)
					for _, plg := range s.Pledged {
						v = append(v, plg.serialize()...)
					}
					bucket.Put(k[:], v)
					return nil
				})
				break done
			}
		}
	}

	collaterals.Delete(u)

	return nil
}
