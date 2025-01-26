// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2018-2021 The Omegasuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"sync"
)

type Collaterals struct {
	stateLock         sync.Mutex
	lockedCollaterals map[OutPoint]struct{} // reference counts of them
}

func (s *Collaterals) Exists(p *OutPoint) bool {
	s.stateLock.Lock()
	_, ok := s.lockedCollaterals[*p]
	s.stateLock.Unlock()
	return ok
}

func (s *Collaterals) Delete(p *OutPoint) {
	s.stateLock.Lock()
	delete(s.lockedCollaterals, *p)
	s.stateLock.Unlock()
}

func (s *Collaterals) Add(p *OutPoint) {
	s.stateLock.Lock()
	s.lockedCollaterals[*p] = struct{}{}
	s.stateLock.Unlock()
}

func NewCollaterals() *Collaterals {
	return &Collaterals{
		lockedCollaterals: make(map[OutPoint]struct{}),
	}
}
