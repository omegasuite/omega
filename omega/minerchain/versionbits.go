/* Copyright (C) 2019-2021 Omegasuite developers - All Rights Reserved
* This file is part of the omega chain library.
*
* Use of this source code is governed by license that can be
* found in the LICENSE file.
*
 */

package minerchain

import (
//	"fmt"
	"github.com/omegasuite/btcd/blockchain/chainutil"

	"github.com/omegasuite/btcd/chaincfg"
//	"github.com/omegasuite/btcd/wire"
)

const (
	// vbTopBits defines the bits to set in the version to signal that the
	// version bits scheme is being used.
	vbTopBits = 0x10000

	// vbNumBits is the total number of bits available for use with the
	// version bits scheme.
	vbNumBits = 16
	vbNumMask = 0xFFFF

	// unknownVerNumToCheck is the number of previous blocks to consider
	// when checking for a threshold of unknown block versions for the
	// purposes of warning the user.
	unknownVerNumToCheck = 100

	// unknownVerWarnNum is the threshold of previous blocks that have an
	// unknown version to use for the purposes of warning the user.
	unknownVerWarnNum = unknownVerNumToCheck / 2
)

// deploymentChecker provides a thresholdConditionChecker which can be used to
// test a specific deployment rule.  This is required for properly detecting
// and activating consensus rule changes.
type deploymentChecker struct {
	deployment *chaincfg.ConsensusDeployment
	chain      *MinerChain
}

// Ensure the deploymentChecker type implements the thresholdConditionChecker
// interface.
var _ thresholdConditionChecker = deploymentChecker{}

// BeginTime returns the unix timestamp for the median block time after which
// voting on a rule change starts (at the next window).
//
// This implementation returns the value defined by the specific deployment the
// checker is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) BeginTime() uint64 {
	return c.deployment.StartTime
}

// EndTime returns the unix timestamp for the median block time after which an
// attempted rule change fails if it has not already been locked in or
// activated.
//
// This implementation returns the value defined by the specific deployment the
// checker is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) EndTime() uint64 {
	return c.deployment.ExpireTime
}

// RuleChangeActivationThreshold is the number of blocks for which the condition
// must be true in order to lock in a rule change.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) RuleChangeActivationThreshold() uint32 {
	return c.chain.chainParams.RuleChangeActivationThreshold
}

// MinerConfirmationWindow is the number of blocks in each threshold state
// retarget window.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) MinerConfirmationWindow() uint32 {
	return c.chain.chainParams.MinerConfirmationWindow
}

// Condition returns true when the specific bit defined by the deployment
// associated with the checker is set.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) Condition(node *chainutil.BlockNode) bool {
	conditionMask := c.deployment.FeatureMask
	version := node.Data.GetVersion()
	return version & conditionMask == conditionMask
}

func (b *MinerChain) NextBlockVersion(prevNode *chainutil.BlockNode) (uint32, error) {
	return b.calcNextBlockVersion(prevNode)
}

// calcNextBlockVersion calculates the expected version of the block after the
// passed previous block node based on the state of started and locked in
// rule change deployments.
//
// This function differs from the exported CalcNextBlockVersion in that the
// exported version uses the current best chain as the previous block node
// while this function accepts any block node.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *MinerChain) calcNextBlockVersion(prevNode *chainutil.BlockNode) (uint32, error) {
	// Set the appropriate bits for each actively defined rule deployment
	// that is either in the process of being voted on, or locked in for the
	// activation at the next threshold window change.
	expectedVersion := uint32(0)	// wire.CodeVersion	// uint32(0x20000)		// current version
	for id := 0; id < len(b.chainParams.Deployments); id++ {
		deployment := &b.chainParams.Deployments[id]

		if expectedVersion > deployment.PrevVersion {
			continue
		}

		expectedVersion = deployment.PrevVersion
		cache := &b.deploymentCaches[id]
		checker := deploymentChecker{deployment: deployment, chain: b}
		state, err := b.thresholdState(prevNode, checker, cache)
		if err != nil {
			return 0, err
		}
		if state == ThresholdStarted || state == ThresholdLockedIn {
			expectedVersion |= deployment.FeatureMask
		} else if state == ThresholdActive {
			expectedVersion = (deployment.PrevVersion + (1 << vbNumBits)) &^ ((1 << vbNumBits) - 1)
		}
	}
/*
	if expectedVersion > wire.CodeVersion {
		return expectedVersion, fmt.Errorf("Code version is older than expected")
	}
*/
	return expectedVersion, nil
}

// CalcNextBlockVersion calculates the expected version of the block after the
// end of the current best chain based on the state of started and locked in
// rule change deployments.
//
// This function is safe for concurrent access.
func (b *MinerChain) CalcNextBlockVersion() (uint32, error) {
//	log.Infof("CalcNextBlockVersion: ChainLock.RLock")
	b.chainLock.Lock()
	version, err := b.calcNextBlockVersion(b.BestChain.Tip())
	b.chainLock.Unlock()
//	log.Infof("CalcNextBlockVersion: ChainLock.Unlock")

	return version, err
}

// warnUnknownRuleActivations displays a warning when any unknown new rules are
// either about to activate or have been activated.  This will only happen once
// when new rules have been activated and every block for those about to be
// activated.
//
func (b *MinerChain) warnUnknownRuleActivations(node *chainutil.BlockNode) error {
	v := node.Data.GetVersion()
	checked := false
	for _,d := range b.chainParams.Deployments {
		if v &^ ((1 << vbNumBits) - 1) == d.PrevVersion {
			if (v & ((1 << vbNumBits) - 1)) &^ d.FeatureMask != 0 {
				log.Warnf("Unknown new rules are activated in block %d", node.Height)
			}
			checked = true
		} else if v &^ ((1 << vbNumBits) - 1) == (d.PrevVersion + (1 << vbNumBits)) {
			checked = true
		}
	}

	if !checked {
		log.Warnf("Unknown new rules are activated in block %d", node.Height)
	}

/*
	// Warn if any unknown new rules are either about to activate or have
	// already been activated.
	for bit := uint32(0); bit < vbNumBits; bit++ {
		checker := bitConditionChecker{bit: bit, chain: b}
		cache := &b.warningCaches[bit]
		state, err := b.thresholdState(node.Parent, checker, cache)
		if err != nil {
			return err
		}

		switch state {
		case ThresholdActive:
			if !b.unknownRulesWarned {
				log.Warnf("Unknown new rules activated (bit %d)", bit)
				b.unknownRulesWarned = true
			}

		case ThresholdLockedIn:
			window := int32(checker.MinerConfirmationWindow())
			activationHeight := window - (node.Height % window)
			log.Warnf("Unknown new rules are about to activate in "+
				"%d blocks (bit %d)", activationHeight, bit)
		}
	}
 */

	return nil
}

// warnUnknownVersions logs a warning if a high enough percentage of the last
// blocks have unexpected versions.
//
// This function MUST be called with the chain state lock held (for writes)
func (b *MinerChain) warnUnknownVersions(node *chainutil.BlockNode) error {
	// Nothing to do if already warned.
	if b.unknownVersionsWarned {
		return nil
	}

	// Warn if enough previous blocks have unexpected versions.
	numUpgraded := uint32(0)
	for i := uint32(0); i < unknownVerNumToCheck && node != nil; i++ {
		expectedVersion, err := b.calcNextBlockVersion(node.Parent)
/*
		if (expectedVersion >> vbNumBits) > (wire.CodeVersion >> vbNumBits) {
			log.Error("New rules are in effect. You are running an older version of the software.")
			b.unknownVersionsWarned = true
			return fmt.Errorf("New rules are in effect. You are running an older version of the software.")
		}
 */
		if err != nil {
			return err
		}
		v := node.Data.GetVersion()
		if ((v & ^expectedVersion) & vbNumMask) != 0 || ((v >> vbNumBits) > (expectedVersion >> vbNumBits)) {
			numUpgraded++
		}

		node = node.Parent
	}

	if numUpgraded > unknownVerWarnNum {
		log.Warn("Unknown block versions are being mined, so new " +
			"rules might be in effect.  Are you running the " +
			"latest version of the software?")
		b.unknownVersionsWarned = true
	}

	return nil
}
