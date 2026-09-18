package regstate

import (
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
)

// These tests answer a design question rather than guard a behaviour: if
// registrations are applied lazily — skipping peers an agent will never dial —
// what actually breaks?
//
// All fixtures are single-block, because that is the interesting case: peers in
// different blocks share no commitment and no openings, so cross-block skipping
// is trivially safe.
//
// The two relations the RBE code relies on, both over block k:
//
//	com[k]     = Σ_{i∈S} pk_i                     (ApplyRegistration, Encrypt's ct0)
//	opening_j  = Σ_{i∈S, i≠j} xi_i[jBar]          (ApplyRegistration)
//
// and the pairing identity e(xi_i[jBar], g2) == e(pk_i, h2[B-1-jBar]), which is
// what makes the Decrypt consistency check and VerifyMembership pass.

// ---------------------------------------------------------------------------
// Step 3: ApplyRegistration
// ---------------------------------------------------------------------------

// TestStep3_SkipEarlyPeersThenApplyLater is the productpage/ratings question
// directly: three peers are never applied, the fourth is applied on its own.
func TestStep3_SkipEarlyPeersThenApplyLater(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 4)
	state := f.newState()

	target := f.peers[3]
	if !state.ApplyRegistration(target.id, target.pk, target.xi) {
		t.Fatal("ApplyRegistration reported already-applied on a fresh state")
	}

	if !ValidatePodChallenge(state, target.id, target.req) {
		t.Error("challenge failed for a peer applied without its three predecessors; " +
			"the accumulator would not be order-free")
	}
}

// TestStep3_OrderIndependence applies the same set in reverse and checks every
// peer still passes: the sums are group sums, so only the set matters.
func TestStep3_OrderIndependence(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)
	state := f.newState()

	for i := len(f.peers) - 1; i >= 0; i-- {
		p := f.peers[i]
		state.ApplyRegistration(p.id, p.pk, p.xi)
	}

	for _, p := range f.peers {
		if !ValidatePodChallenge(state, p.id, p.req) {
			t.Errorf("id=%d: challenge failed after reverse-order application", p.id)
		}
	}
}

// TestStep3_UnappliedPeerFailsChallenge is the security floor of the lazy
// design: deferral must be "apply just in time, then challenge", never "skip
// and challenge". A peer absent from com[k] cannot pass.
func TestStep3_UnappliedPeerFailsChallenge(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 4)
	state := f.newState()

	applied := f.peers[3]
	state.ApplyRegistration(applied.id, applied.pk, applied.xi)

	skipped := f.peers[0]
	if ValidatePodChallenge(state, skipped.id, skipped.req) {
		t.Errorf("id=%d: challenge passed for a peer that was never applied", skipped.id)
	}
}

// TestStep3_CommitmentOpeningSetMismatch splits the two halves of
// ApplyRegistration — commitment updated, openings not — which is exactly the
// hazard a lazy-openings rewrite introduces.
func TestStep3_CommitmentOpeningSetMismatch(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)
	state := f.newState()

	a, b, target := f.peers[0], f.peers[1], f.peers[2]
	state.ApplyRegistration(a.id, a.pk, a.xi)
	state.ApplyRegistration(target.id, target.pk, target.xi)

	if !ValidatePodChallenge(state, target.id, target.req) {
		t.Fatal("baseline challenge failed; fixture is wrong")
	}

	// Fold b's public key into the commitment without folding its xi into the
	// openings: com[k] now covers {a, b, target}, opening covers {a}.
	k := state.pp.IdToBlock(b.id)
	state.pp.Commitments[k].Add(state.pp.Commitments[k], b.pk)

	if ValidatePodChallenge(state, target.id, target.req) {
		t.Error("challenge passed with com[k] and openings over different sets; " +
			"the two halves of ApplyRegistration are not required to move together")
	}
}

// TestStep3_LazyOpeningMaterialization validates the optimization proposed in
// REGISTRATION-COST-FINDINGS.md: fold only pk eagerly, keep xi as bytes, and
// materialize one peer's opening at first contact by replaying the stored set.
func TestStep3_LazyOpeningMaterialization(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)
	state := f.newState()

	// Eager path: one decompression, one add. xi is retained as raw bytes.
	type pending struct {
		id      int
		xiBytes [][]byte
	}
	var applied []pending

	for _, p := range f.peers {
		k := state.pp.IdToBlock(p.id)
		state.pp.Commitments[k].Add(state.pp.Commitments[k], p.pk)

		raw := make([][]byte, len(p.xi))
		for i, x := range p.xi {
			if x == nil {
				continue
			}
			bts := x.Bytes()
			raw[i] = bts[:]
		}
		applied = append(applied, pending{id: p.id, xiBytes: raw})
	}

	// Lazy path, at first contact with target: opening = Σ_{i≠target} xi_i[jBar].
	target := f.peers[2]
	k := state.pp.IdToBlock(target.id)
	jBar := state.pp.IdToIdBar(target.id)

	sum := new(bls.G1)
	sum.SetIdentity()
	decompressions := 0
	for _, e := range applied {
		if e.id == target.id || e.xiBytes[jBar] == nil {
			continue
		}
		x := new(bls.G1)
		if err := x.SetBytes(e.xiBytes[jBar]); err != nil {
			t.Fatalf("decompress xi for id=%d: %v", e.id, err)
		}
		decompressions++
		sum.Add(sum, x)
	}

	state.mu.Lock()
	if state.userOpenings[k] == nil {
		state.userOpenings[k] = make(map[int][]*bls.G1)
	}
	state.userOpenings[k][target.id] = []*bls.G1{sum}
	state.mu.Unlock()

	if !ValidatePodChallenge(state, target.id, target.req) {
		t.Error("challenge failed against a lazily materialized opening")
	}
	t.Logf("materializing one opening over %d stored registrations took %d G1 decompressions "+
		"(eager path would have done %d per registration)",
		len(applied), decompressions, state.pp.BlockSize)
}

// ---------------------------------------------------------------------------
// Steps 3b and 4: ApplyOrderedCommitment and VerifyMembershipOrdered
// ---------------------------------------------------------------------------

// TestStep3b_SkippingBreaksLaterProofs is the answer to "can I skip 3b for
// peers I don't care about": no. A proof is a statement about the whole prefix,
// so a gap in the shadow commitment fails a legitimate later peer.
func TestStep3b_SkippingBreaksLaterProofs(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 4)
	state := f.newState()

	// Peers 0-2 are "ratings": their ordered commitment is never applied.
	target := f.peers[3]
	state.ApplyOrderedCommitment(target.id, target.pk)

	if state.VerifyMembershipOrdered(target.id, target.pk, target.proof) {
		t.Error("proof verified against a shadow commitment missing its prefix; " +
			"ApplyOrderedCommitment would be skippable")
	}

	// Same peer, same proof, complete prefix: now it verifies.
	full := f.newState()
	for _, p := range f.peers {
		full.ApplyOrderedCommitment(p.id, p.pk)
	}
	if !full.VerifyMembershipOrdered(target.id, target.pk, target.proof) {
		t.Error("proof failed against the complete prefix; fixture is wrong")
	}
}

// TestStep3b_OrderIndependentGivenCompletePrefix separates the two things that
// get conflated: 3b's *order* is free (it is a group sum), its *completeness*
// is not.
func TestStep3b_OrderIndependentGivenCompletePrefix(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)

	target := f.peers[4]
	perm := []int{2, 0, 4, 3, 1} // includes target, excludes nothing

	state := f.newState()
	for _, i := range perm {
		p := f.peers[i]
		state.ApplyOrderedCommitment(p.id, p.pk)
	}

	if !state.VerifyMembershipOrdered(target.id, target.pk, target.proof) {
		t.Error("proof failed after out-of-order application of the complete prefix")
	}
}

// TestStep4_DeferralNeedsASnapshot shows the trap and the fix side by side:
// verifying later against the live commitment fails, verifying against the
// commitment as it stood at insertion succeeds.
func TestStep4_DeferralNeedsASnapshot(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)
	state := f.newState()

	target := f.peers[2]

	// Apply the prefix through target, then snapshot com[k].
	for _, p := range f.peers[:3] {
		state.ApplyOrderedCommitment(p.id, p.pk)
	}
	k := state.pp.IdToBlock(target.id)
	snapshot := new(bls.G1)
	bts := state.orderedCommitments[k].Bytes()
	if err := snapshot.SetBytes(bts[:]); err != nil {
		t.Fatalf("snapshot com[k]: %v", err)
	}

	// Later registrations arrive while target's check is still pending.
	for _, p := range f.peers[3:] {
		state.ApplyOrderedCommitment(p.id, p.pk)
	}

	if state.VerifyMembershipOrdered(target.id, target.pk, target.proof) {
		t.Error("deferred proof verified against a commitment that had moved on; " +
			"the in-place mutation in ApplyOrderedCommitment is not actually a hazard")
	}

	ppCopy := *state.pp
	comms := make([]*bls.G1, len(state.orderedCommitments))
	copy(comms, state.orderedCommitments)
	comms[k] = snapshot
	ppCopy.Commitments = comms

	if !rbe.VerifyMembership(&ppCopy, target.id, target.pk, target.proof) {
		t.Error("deferred proof failed against its own snapshot; snapshotting is not a fix")
	}
}
