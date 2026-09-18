package regstate

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"golang.org/x/sync/singleflight"
	gproto "google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
	trincutil "istio.io/istio/security/pkg/trinc/util"
)

var lazyLog = log.RegisterScope("regstate-lazy", "lazy registration accumulator")

// LazyStore is an alternative registration accumulator that moves the
// pairing-heavy and decompression-heavy work off the stream path and onto first
// contact with a peer. It is selected by MAZU_LAZY_REGISTRATION_ENABLED and is
// deliberately *disjoint* from LocalRBEState: it never reads or writes
// pp.Commitments, orderedCommitments or userOpenings, so the two paths cannot
// corrupt each other and the flag is a clean A/B switch.
//
// # Why this is sound
//
// The eager path in store.go folds each registration into two in-place
// accumulators over block k:
//
//	com[k]     = Σ_{i∈S} pk_i                 (used by Encrypt, and by Decrypt's check)
//	opening_j  = Σ_{i∈S, i≠j} xi_i[jBar]      (the value a peer decrypts with)
//
// Both are group sums, so only the *set* S matters, not the order it was
// applied in. A membership proof, by contrast, is a statement about a *prefix*:
//
//	proof_id = Σ_{i<id} xi_i[idBar]   verifies against   Σ_{i≤id} pk_i
//
// So this store keeps the registrations themselves — an append-only log per
// block, in stream order — and derives all three values from that log at
// validation time. Nothing is mutated in place, which means:
//
//   - no snapshot bookkeeping is needed for the prefix commitment; the prefix
//     of the log *is* the snapshot,
//   - the commitment and the opening handed to the challenge are computed from
//     one observation of the log, so they always cover the same set S. Splitting
//     those two apart is the failure mode that looks like a crypto bug (see
//     TestStep3_CommitmentOpeningSetMismatch in defer_semantics_test.go),
//   - a registration arriving mid-validation cannot invalidate a validation
//     already in flight.
//
// # What the eager path still does
//
// Counter attestation stays eager, so the TRINC chain is verified in order as
// it arrives, and so does the single G1 decompression of pk. xi — 256 points,
// and by measurement the bulk of the per-registration cost — is retained as
// bytes and decompressed one index at a time, for peers actually dialed.
//
// # Known limitations
//
//   - The log is append-only and unbounded; a long-lived agent in a churning
//     mesh grows it without limit. The eager path has the same shape of problem
//     (it appends one G1 per block member per registration) but bounded pruning
//     is future work for both.
//   - Deferring the xi decompression also defers the subgroup check that
//     G1.SetBytes performs, so a malformed xi point is caught at first contact
//     rather than at arrival. Validation fails closed when that happens.
//   - Failed validations are not cached, so a peer that cannot be validated is
//     re-checked on every connection. Only successes are memoized.
type LazyStore struct {
	mu sync.RWMutex

	// pp is read for its immutable parts only (CRS, BlockSize, id mapping).
	// Commitments are never read from or written to it; see ppWith.
	pp *rbe.PublicParams

	// blocks maps a block ID to its registrations in stream order. Entries are
	// append-only and never mutated after append, which is what lets a reader
	// copy the slice header under RLock and then do the crypto unlocked.
	blocks map[int][]*lazyEntry

	// pos maps a user ID to its index within its own block's slice. Presence
	// also serves as the idempotency check for a replayed registration.
	pos map[int]int

	// validated memoizes successful validations. A proven key-ID binding does
	// not expire when later peers register, so this never needs invalidating.
	validated map[int]bool

	// flight coalesces concurrent first-contact validations of the same peer,
	// which is the scale-up case: N connections to one new pod at once.
	flight singleflight.Group
}

// lazyEntry is one registration, held with xi still in wire form.
type lazyEntry struct {
	id int

	// pk is decompressed eagerly: every commitment sum needs it.
	pk *bls.G1

	// req holds xi as byte slices. Individual points are decompressed on
	// demand, at one index per peer dialed.
	req *pb.RegisterRequest

	// proofBytes is the membership proof, decompressed at validation time.
	proofBytes []byte
}

// LazyTiming reports where a validation spent its time, so the cold path can be
// attributed without a profiler. Durations are microseconds.
type LazyTiming struct {
	Cached bool // served from the memo; the other fields are then zero

	MaterializeUs int64 // commitment sums + xi decompressions
	ProofUs       int64 // VerifyMembership against the prefix commitment
	ChallengeUs   int64 // encrypt/decrypt round
	TotalUs       int64

	BlockDepth     int // registrations in this peer's block at validation time
	Decompressions int // xi points actually decompressed
}

// NewLazyStore returns a LazyStore over the given public parameters. pp is
// retained by reference but only its immutable fields are used.
func NewLazyStore(pp *rbe.PublicParams) *LazyStore {
	lazyLog.Infof("[dev] lazy registration store initialized (BlockSize=%d, NumBlocks=%d)",
		pp.BlockSize, pp.NumBlocks)
	return &LazyStore{
		pp:        pp,
		blocks:    make(map[int][]*lazyEntry),
		pos:       make(map[int]int),
		validated: make(map[int]bool),
	}
}

// ProcessRegistrationLazy is the eager half of the lazy path, and the
// counterpart to ProcessRegistration for stream-delivered registrations.
//
// It verifies the counter attestation, decompresses pk, and appends the
// registration to its block's log. It performs no pairings, no opening updates
// and exactly one G1 decompression. Callers must invoke it in stream order and
// from a single goroutine — the log order is the registration order that every
// membership proof is checked against.
//
// Returns false if the registration is unusable, in which case it is not
// appended. A registration already in the log is a no-op and returns true.
func ProcessRegistrationLazy(lz *LazyStore, notif *pb.RegistrationNotification) bool {
	start := time.Now()
	id := int(notif.GetId())

	// --- Step 1: counter attestation (kept eager, in order) ---
	if notif.GetCounterAttestation() != nil && notif.GetRegisterRequestBytes() != nil {
		attestation := trincutil.AttestationFromProto(notif.GetCounterAttestation())

		regMsg := notif.GetRegisterRequestBytes()
		proofBytes, _ := gproto.Marshal(notif.GetProof())
		attestUserData := append(regMsg, proofBytes...)

		if !trincutil.DoVerifyCounter(attestUserData, attestation) {
			lazyLog.Errorf("attestation verification failed for id=%d", id)
			return false
		}
	}

	if notif.GetRegisterRequestBytes() == nil {
		lazyLog.Errorf("registration for id=%d has no RegisterRequest bytes", id)
		return false
	}

	// --- Step 2 (partial): unmarshal, then decompress pk only ---
	// The unmarshal keeps xi as byte slices; the 256 xi decompressions that
	// dominate the eager path are deferred to first contact.
	req := &pb.RegisterRequest{}
	if err := gproto.Unmarshal(notif.GetRegisterRequestBytes(), req); err != nil {
		lazyLog.Errorf("failed to unmarshal RegisterRequest for id=%d: %v", id, err)
		return false
	}

	pk := new(bls.G1)
	if err := pk.SetBytes(req.GetPublicKey().GetPoint()); err != nil {
		lazyLog.Errorf("public key for id=%d is not a valid G1 point: %v", id, err)
		return false
	}

	var proofBytes []byte
	if p := notif.GetProof(); p != nil && len(p.GetPoint()) > 0 {
		proofBytes = p.GetPoint()
	}

	// --- Step 3: append to the block log ---
	appended := lz.append(id, pk, req, proofBytes)

	elapsed := time.Since(start)
	lazyEagerLatency.Record(float64(elapsed.Microseconds()) / 1000.0)
	if appended {
		lazyLog.Infof("[dev] lazy: appended registration id=%d in %v (no xi decompression, no pairings)", id, elapsed)
	} else {
		lazyLog.Infof("[dev] lazy: registration id=%d already in log, skipping", id)
	}
	return true
}

// append adds an entry to its block log. Returns false if the ID was already
// present, in which case the log is left untouched.
func (lz *LazyStore) append(id int, pk *bls.G1, req *pb.RegisterRequest, proofBytes []byte) bool {
	lz.mu.Lock()
	defer lz.mu.Unlock()

	if _, ok := lz.pos[id]; ok {
		return false
	}

	k := lz.pp.IdToBlock(id)
	lz.blocks[k] = append(lz.blocks[k], &lazyEntry{
		id:         id,
		pk:         pk,
		req:        req,
		proofBytes: proofBytes,
	})
	lz.pos[id] = len(lz.blocks[k]) - 1
	return true
}

// Has reports whether a registration for id has been delivered.
func (lz *LazyStore) Has(id int) bool {
	lz.mu.RLock()
	defer lz.mu.RUnlock()
	_, ok := lz.pos[id]
	return ok
}

// Validated reports whether id has already passed validation.
func (lz *LazyStore) Validated(id int) bool {
	lz.mu.RLock()
	defer lz.mu.RUnlock()
	return lz.validated[id]
}

// Len returns the number of registrations in the log.
func (lz *LazyStore) Len() int {
	lz.mu.RLock()
	defer lz.mu.RUnlock()
	return len(lz.pos)
}

type lazyResult struct {
	ok     bool
	timing *LazyTiming
}

// Validate runs the deferred half of the path for one peer: it materializes the
// peer's opening from the retained xi bytes, verifies the membership proof
// against the prefix commitment, and runs the challenge-response against the
// full commitment. The result is memoized on success.
//
// Concurrent calls for the same peer are coalesced, so a fan-in of N
// connections to one newly registered pod pays the cost once.
func (lz *LazyStore) Validate(id int) (bool, *LazyTiming) {
	lz.mu.RLock()
	done := lz.validated[id]
	lz.mu.RUnlock()
	if done {
		return true, &LazyTiming{Cached: true}
	}

	v, _, _ := lz.flight.Do(strconv.Itoa(id), func() (any, error) {
		// Another caller may have finished while we waited for the slot.
		lz.mu.RLock()
		done := lz.validated[id]
		lz.mu.RUnlock()
		if done {
			return lazyResult{true, &LazyTiming{Cached: true}}, nil
		}

		ok, timing := lz.validateUncached(id)
		if ok {
			lz.mu.Lock()
			lz.validated[id] = true
			lz.mu.Unlock()
		}
		return lazyResult{ok, timing}, nil
	})

	res := v.(lazyResult)
	return res.ok, res.timing
}

// validateUncached does the actual work. It takes one observation of the block
// log and derives every value it needs from that single observation, so the
// prefix commitment, the full commitment and the opening are guaranteed
// mutually consistent even if registrations keep arriving underneath.
func (lz *LazyStore) validateUncached(id int) (result bool, timing *LazyTiming) {
	timing = &LazyTiming{}
	totalStart := time.Now()
	defer func() {
		timing.TotalUs = time.Since(totalStart).Microseconds()
	}()

	// BLS operations panic on malformed inputs; a peer must not be able to take
	// the agent down by registering a bad point.
	defer func() {
		if err := recover(); err != nil {
			lazyLog.Errorf("[dev] lazy: panic validating id=%d: %+v", id, err)
			result = false
		}
	}()

	// Entries are append-only and never mutated, so a bounded slice taken under
	// RLock stays valid and immutable once released: a concurrent append either
	// reallocates (leaving this array alone) or writes past this length.
	lz.mu.RLock()
	k := lz.pp.IdToBlock(id)
	pos, ok := lz.pos[id]
	entries := lz.blocks[k]
	lz.mu.RUnlock()

	if !ok {
		lazyLog.Infof("[dev] lazy: no registration in log for id=%d", id)
		return false, timing
	}
	entries = entries[:len(entries):len(entries)]
	self := entries[pos]
	idBar := lz.pp.IdToIdBar(id)
	timing.BlockDepth = len(entries)

	// --- Materialize: two commitment sums and this peer's opening ---
	matStart := time.Now()

	comPrefix := new(bls.G1) // Σ_{i≤pos} pk_i — what self's proof was issued against
	comPrefix.SetIdentity()
	comFull := new(bls.G1) // Σ_{i∈entries} pk_i — what the challenge encrypts to
	comFull.SetIdentity()
	opening := new(bls.G1) // Σ_{i∈entries, i≠pos} xi_i[idBar]
	opening.SetIdentity()

	xi := new(bls.G1)
	for i, e := range entries {
		comFull.Add(comFull, e.pk)
		if i <= pos {
			comPrefix.Add(comPrefix, e.pk)
		}
		if i == pos {
			continue
		}

		raw := e.req.GetXi()
		if idBar >= len(raw) {
			continue
		}
		point := raw[idBar].GetPoint()
		if len(point) == 0 {
			// xi[jBar] is legitimately absent for some indices; NewKeyPair
			// leaves them nil where the CRS has no corresponding h1 element.
			continue
		}
		if err := xi.SetBytes(point); err != nil {
			lazyLog.Errorf("[dev] lazy: xi[%d] from id=%d is not a valid G1 point: %v", idBar, e.id, err)
			return false, timing
		}
		timing.Decompressions++
		opening.Add(opening, xi)
	}
	timing.MaterializeUs = time.Since(matStart).Microseconds()

	// --- Step 4: membership proof against the prefix commitment ---
	if len(self.proofBytes) > 0 {
		proofStart := time.Now()
		proof := new(bls.G1)
		if err := proof.SetBytes(self.proofBytes); err != nil {
			lazyLog.Errorf("[dev] lazy: proof for id=%d is not a valid G1 point: %v", id, err)
			return false, timing
		}
		verified := rbe.VerifyMembership(lz.ppWith(k, comPrefix), id, self.pk, proof)
		timing.ProofUs = time.Since(proofStart).Microseconds()
		if !verified {
			lazyLog.Errorf("[dev] lazy: membership verification failed for id=%d at depth=%d pos=%d",
				id, len(entries), pos)
			return false, timing
		}
	}

	// --- Step 5: challenge-response against the full commitment ---
	chalStart := time.Now()
	valid := challengeAt(lz.ppWith(k, comFull), opening, id, self.req)
	timing.ChallengeUs = time.Since(chalStart).Microseconds()
	if !valid {
		lazyLog.Warnf("[dev] lazy: challenge-response failed for id=%d", id)
		return false, timing
	}

	// Recorded on the success path only: a failed validation is either a fast
	// reject (no registration, bad point) or a crypto failure, and folding
	// either into the latency distribution would misreport the cold path. The
	// [benchmark] log line in ext_authz reports failures with their timings.
	lazyValidateLatency.With(LazyPhase.Value("materialize")).Record(float64(timing.MaterializeUs) / 1000.0)
	lazyValidateLatency.With(LazyPhase.Value("rbe_proof")).Record(float64(timing.ProofUs) / 1000.0)
	lazyValidateLatency.With(LazyPhase.Value("challenge_response")).Record(float64(timing.ChallengeUs) / 1000.0)
	lazyValidateTotalLatency.Record(float64(time.Since(totalStart).Microseconds()) / 1000.0)

	return true, timing
}

// ppWith returns a shallow copy of the public parameters whose commitment for
// block k is com. The Commitments slice is copied because rbe.User.Update
// assigns through to pp.Commitments, and the shared pp must stay untouched.
func (lz *LazyStore) ppWith(k int, com *bls.G1) *rbe.PublicParams {
	ppCopy := *lz.pp
	comms := make([]*bls.G1, len(lz.pp.Commitments))
	copy(comms, lz.pp.Commitments)
	comms[k] = com
	ppCopy.Commitments = comms
	return &ppCopy
}

// challengeAt is ValidatePodChallenge with the commitment and the opening
// passed in explicitly rather than read from shared mutable state. Taking both
// as arguments is the point: they have to cover the same set of registrations,
// and a signature that demands both makes that impossible to forget.
func challengeAt(pp *rbe.PublicParams, opening *bls.G1, id int, req *pb.RegisterRequest) bool {
	nonce := []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	nonceHash := keycurator.HashToGt(nonce)

	cipherText := rbe.Encrypt(pp, id, nonceHash)

	rbeId := &security.RbeId{
		Ip:    req.GetIp(),
		Token: req.GetToken(),
	}
	sk := new(bls.Scalar)
	sk.SetUint64(uint64(rbeId.SecretKey()))

	user := rbe.NewUserForDecrypt(pp, id, sk)
	user.Update(pp.Commitments, []*bls.G1{opening})

	decrypted, err := user.Decrypt(cipherText)
	if err != nil {
		lazyLog.Errorf("[dev] lazy: failed to decrypt nonce for id=%d: %v", id, err)
		return false
	}
	return nonceHash.IsEqual(decrypted)
}
