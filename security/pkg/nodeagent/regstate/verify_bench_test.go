package regstate

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	rbepb "github.com/etclab/rbe/proto"
	gproto "google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

// Benchmarks for the per-registration cost of ProcessRegistration, broken down
// by step, so the eager-vs-deferred question can be settled with numbers.
//
// The steps, as they appear in ProcessRegistration:
//
//	1. counter attestation   — needs a TPM public key; benchmarked separately
//	2. unmarshal + decompress — BlockSize G1 decompressions
//	3. ApplyRegistration     — BlockSize G1 adds + opening appends
//	3b. ApplyOrderedCommitment — 1 G1 add
//	4. VerifyMembershipOrdered — ~3 pairings
//	5. ValidatePodChallenge    — ~7 pairings + an encrypt/decrypt round
//
// Run:
//
//	go test ./security/pkg/nodeagent/regstate/ -run XXX -bench . -benchtime 20x
//
// benchtime is given in iterations, not seconds: the pairing-heavy steps run in
// milliseconds and the default 1s target wastes minutes in setup replay.
//
// MAZU_BENCH_MAX_USERS overrides the RBE parameter size (default 65536, which
// is what the deployed public params use and gives BlockSize=NumBlocks=256).
// Setup is O(peers x BlockSize) scalar multiplications, so shrinking it makes
// iteration faster at the cost of no longer measuring the production shape.

const defaultBenchMaxUsers = 65536

// benchPeers is the number of distinct synthetic registrations built per
// fixture. ProcessRegistration is idempotent per ID, so a benchmark loop has to
// cycle through distinct IDs and reset the state when it wraps.
const benchPeers = 32

func benchMaxUsers() int {
	if v := os.Getenv("MAZU_BENCH_MAX_USERS"); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
	}
	return defaultBenchMaxUsers
}

// benchPeer is one synthetic registration, pre-built so that the benchmark loop
// measures only ProcessRegistration and not fixture construction.
type benchPeer struct {
	id    int
	notif *pb.RegistrationNotification
	// reqBytes is retained separately so step-level benchmarks can unmarshal
	// without reaching back through the notification.
	reqBytes []byte
	req      *pb.RegisterRequest
	pk       *bls.G1
	xi       []*bls.G1
	proof    *bls.G1
}

// benchFixture holds the shared, expensive-to-build RBE parameters plus a
// registration sequence in stream order.
type benchFixture struct {
	basePP *rbe.PublicParams
	peers  []*benchPeer
}

// buildFixture generates `count` synthetic registrations in stream order.
//
// Each peer mirrors what a real pod does: derive the RBE ID from the token,
// derive the secret key from ip|token, and build the keypair against the shared
// CRS. Proofs are accumulated the same way ApplyRegistration does, which is what
// the KC's ProveMembership returns — rbe.KeyCurator is deliberately not used
// here because its RegisterUser calls CheckXiConsistency, which costs BlockSize
// pairings per registration and would dominate setup.
func buildFixture(tb testing.TB, count int) *benchFixture {
	tb.Helper()

	maxUsers := benchMaxUsers()
	pp := rbe.NewPublicParams(maxUsers)

	// openingAcc[blockID][idBar] is the running sum of xi contributions for the
	// user at idBar in that block — i.e. the proof that user would be handed.
	openingAcc := make(map[int]map[int]*bls.G1)
	seen := make(map[int]bool)
	peers := make([]*benchPeer, 0, count)

	for i := 0; len(peers) < count; i++ {
		token := fmt.Sprintf("bench-token-%d", i)
		ip := fmt.Sprintf("10.42.%d.%d", (i/256)%256, i%256)

		id := int((&security.RbeId{Token: token}).ToNumber())
		if id >= maxUsers || seen[id] {
			// ToNumber() folds md5 down to 16 bits, so collisions happen.
			continue
		}
		seen[id] = true

		sk := new(bls.Scalar)
		sk.SetUint64(uint64((&security.RbeId{Ip: ip, Token: token}).SecretKey()))
		kp := rbe.NewKeyPair(pp, id, sk)

		k := pp.IdToBlock(id)
		idBar := pp.IdToIdBar(id)
		if openingAcc[k] == nil {
			openingAcc[k] = make(map[int]*bls.G1)
		}

		// The proof is this user's opening as of its own registration: the sum
		// of xi[idBar] over everyone already registered in the block.
		proof := new(bls.G1)
		if acc, ok := openingAcc[k][idBar]; ok {
			b := acc.Bytes()
			proof.SetBytes(b[:])
		} else {
			proof.SetIdentity()
		}

		// Fold this registration into every other member's opening.
		for jBar := 0; jBar < pp.BlockSize; jBar++ {
			if jBar == idBar || kp.Xi[jBar] == nil {
				continue
			}
			acc, ok := openingAcc[k][jBar]
			if !ok {
				acc = new(bls.G1)
				acc.SetIdentity()
				openingAcc[k][jBar] = acc
			}
			acc.Add(acc, kp.Xi[jBar])
		}

		req := &pb.RegisterRequest{
			Id:        int64(id),
			PublicKey: g1ToProto(kp.PublicKey),
			Xi:        xiToProto(kp.Xi),
			Ip:        ip,
			Token:     token,
		}
		reqBytes, err := gproto.Marshal(req)
		if err != nil {
			tb.Fatalf("marshal RegisterRequest: %v", err)
		}

		peers = append(peers, &benchPeer{
			id:       id,
			reqBytes: reqBytes,
			req:      req,
			pk:       kp.PublicKey,
			xi:       kp.Xi,
			proof:    proof,
			notif: &pb.RegistrationNotification{
				Id:                   int64(id),
				Proof:                g1ToProto(proof),
				RegisterRequestBytes: reqBytes,
				// CounterAttestation is left nil: step 1 needs a TPM public key
				// on disk and is measured by BenchmarkStep1CounterAttestation.
			},
		})
	}

	return &benchFixture{basePP: pp, peers: peers}
}

func g1ToProto(p *bls.G1) *rbepb.G1 {
	if p == nil {
		return &rbepb.G1{}
	}
	b := p.Bytes()
	return &rbepb.G1{Point: b[:]}
}

func xiToProto(xi []*bls.G1) []*rbepb.G1 {
	out := make([]*rbepb.G1, len(xi))
	for i, x := range xi {
		out[i] = g1ToProto(x)
	}
	return out
}

// newState returns a LocalRBEState sharing the fixture's CRS but with its own
// commitment slices, so a benchmark can reset accumulated state between passes
// without regenerating the (expensive) public parameters.
func (f *benchFixture) newState() *LocalRBEState {
	ppCopy := *f.basePP
	ppCopy.Commitments = identityCommitments(f.basePP.NumBlocks)

	return &LocalRBEState{
		pp:                 &ppCopy,
		userOpenings:       make(map[int]map[int][]*bls.G1),
		registeredIds:      make(map[int]bool),
		orderedCommitments: identityCommitments(f.basePP.NumBlocks),
		orderedIds:         make(map[int]bool),
	}
}

func identityCommitments(n int) []*bls.G1 {
	out := make([]*bls.G1, n)
	for i := range out {
		out[i] = new(bls.G1)
		out[i].SetIdentity()
	}
	return out
}

// applyThrough replays peers[:n] into the state so a benchmark can measure a
// single step against a realistically-populated block.
func (f *benchFixture) applyThrough(state *LocalRBEState, store *Store, n int) {
	for _, p := range f.peers[:n] {
		if !ProcessRegistration(store, state, p.notif, SourceStream) {
			panic(fmt.Sprintf("fixture replay failed for id=%d", p.id))
		}
	}
}

// quietLogs silences the regstate scopes for the duration of a benchmark.
// ProcessRegistration emits ~6 Infof calls per registration; leaving them on
// measures the logger as much as the crypto. Pass false to measure the
// production configuration including logging.
func quietLogs(tb testing.TB, quiet bool) {
	tb.Helper()
	if !quiet {
		return
	}
	for _, name := range []string{"regstate", "regstate-store", "regstate-lazy"} {
		if s := log.FindScope(name); s != nil {
			prev := s.GetOutputLevel()
			s.SetOutputLevel(log.NoneLevel)
			tb.Cleanup(func() { s.SetOutputLevel(prev) })
		}
	}
}

// TestBenchFixtureIsValid guards the benchmarks: if the synthetic registrations
// are malformed, ProcessRegistration would bail early and the benchmarks would
// silently measure a fraction of the real work. This asserts that every step
// actually runs and passes.
func TestBenchFixtureIsValid(t *testing.T) {
	quietLogs(t, true)
	f := buildFixture(t, 3)
	state := f.newState()
	store := NewStore()

	for _, p := range f.peers {
		if !ProcessRegistration(store, state, p.notif, SourceStream) {
			t.Fatalf("ProcessRegistration failed for id=%d", p.id)
		}
		reg, ok := store.Get(p.id)
		if !ok {
			t.Fatalf("registration not stored for id=%d", p.id)
		}
		if !reg.ProofVerified {
			t.Errorf("id=%d: membership proof did not verify — step 4 is being skipped, "+
				"benchmarks would understate the real cost", p.id)
		}
		if !reg.PodValid {
			t.Errorf("id=%d: challenge-response failed — step 5 is not doing real work, "+
				"benchmarks would understate the real cost", p.id)
		}
	}
}

// BenchmarkProcessRegistration measures the whole eager path per registration,
// with and without logging.
func BenchmarkProcessRegistration(b *testing.B) {
	for _, tc := range []struct {
		name  string
		quiet bool
	}{
		{"logs=off", true},
		{"logs=on", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			quietLogs(b, tc.quiet)
			f := buildFixture(b, benchPeers)

			state := f.newState()
			store := NewStore()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if i%len(f.peers) == 0 && i > 0 {
					// Wrapped the pool: every ID is already applied and would
					// short-circuit, so start a fresh state off the clock.
					b.StopTimer()
					state = f.newState()
					store = NewStore()
					b.StartTimer()
				}
				ProcessRegistration(store, state, f.peers[i%len(f.peers)].notif, SourceStream)
			}
		})
	}
}

// BenchmarkStep2UnmarshalAndDecompress measures the proto unmarshal plus the
// BlockSize G1 decompressions that feed ApplyRegistration. This is the step that
// scales with BlockSize rather than with peer count, and it cannot be deferred
// without restructuring how openings are materialized.
func BenchmarkStep2UnmarshalAndDecompress(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p := f.peers[i%len(f.peers)]
		req := &pb.RegisterRequest{}
		if err := gproto.Unmarshal(p.reqBytes, req); err != nil {
			b.Fatal(err)
		}
		pk := new(bls.G1)
		pk.SetBytes(req.GetPublicKey().GetPoint())
		xi := make([]*bls.G1, len(req.GetXi()))
		for j, v := range req.GetXi() {
			if len(v.GetPoint()) == 0 {
				continue
			}
			xi[j] = new(bls.G1)
			xi[j].SetBytes(v.GetPoint())
		}
	}
}

// BenchmarkStep3ApplyRegistration measures the accumulator update in isolation:
// BlockSize G1 adds plus the opening appends.
func BenchmarkStep3ApplyRegistration(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)

	state := f.newState()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if i%len(f.peers) == 0 && i > 0 {
			b.StopTimer()
			state = f.newState()
			b.StartTimer()
		}
		p := f.peers[i%len(f.peers)]
		state.ApplyRegistration(p.id, p.pk, p.xi)
	}
}

// BenchmarkStep4VerifyMembershipOrdered measures the membership pairing check.
// Deferring this one requires snapshotting the per-block commitment, since
// ApplyOrderedCommitment mutates it in place.
func BenchmarkStep4VerifyMembershipOrdered(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)

	// Replay everything but the last peer, then verify that peer repeatedly:
	// the commitment is then in the exact state its proof was issued against.
	state := f.newState()
	store := NewStore()
	f.applyThrough(state, store, len(f.peers)-1)

	last := f.peers[len(f.peers)-1]
	state.ApplyOrderedCommitment(last.id, last.pk)

	if !state.VerifyMembershipOrdered(last.id, last.pk, last.proof) {
		b.Fatal("fixture proof does not verify; benchmark would measure a failing path")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.VerifyMembershipOrdered(last.id, last.pk, last.proof)
	}
}

// BenchmarkStep5ValidatePodChallenge measures the encrypt/decrypt challenge —
// the largest block of pairings, and the one that defers cleanly because it
// reads current commitments and openings with no ordering dependency.
func BenchmarkStep5ValidatePodChallenge(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)

	state := f.newState()
	store := NewStore()
	f.applyThrough(state, store, len(f.peers))

	last := f.peers[len(f.peers)-1]
	if !ValidatePodChallenge(state, last.id, last.req) {
		b.Fatal("fixture challenge fails; benchmark would measure a failing path")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePodChallenge(state, last.id, last.req)
	}
}

// BenchmarkStep5ChallengeByBlockDepth answers whether the challenge cost grows
// with the number of peers already registered in the same block — which decides
// whether deferral saves a constant per peer or an increasing amount.
//
// All peers are forced into one block so depth is controlled rather than left
// to how md5 happens to scatter the IDs.
func BenchmarkStep5ChallengeByBlockDepth(b *testing.B) {
	quietLogs(b, true)
	f := buildSingleBlockFixture(b, 64)

	for _, depth := range []int{1, 8, 32, 64} {
		if depth > len(f.peers) {
			continue
		}
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			state := f.newState()
			store := NewStore()
			f.applyThrough(state, store, depth)

			target := f.peers[depth-1]
			if !ValidatePodChallenge(state, target.id, target.req) {
				b.Fatalf("fixture challenge fails at depth=%d", depth)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ValidatePodChallenge(state, target.id, target.req)
			}
		})
	}
}

// buildSingleBlockFixture is buildFixture restricted to a single block, so that
// every generated peer contributes to the same commitment and opening history.
// Finding tokens whose 16-bit ID lands in one block takes ~NumBlocks md5s per
// peer, which is negligible next to the keypair generation.
func buildSingleBlockFixture(tb testing.TB, count int) *benchFixture {
	tb.Helper()

	maxUsers := benchMaxUsers()
	pp := rbe.NewPublicParams(maxUsers)
	targetBlock := 0

	openingAcc := make(map[int]*bls.G1)
	seen := make(map[int]bool)
	peers := make([]*benchPeer, 0, count)

	for i := 0; len(peers) < count; i++ {
		token := fmt.Sprintf("bench-block-token-%d", i)
		ip := fmt.Sprintf("10.43.%d.%d", (i/256)%256, i%256)

		id := int((&security.RbeId{Token: token}).ToNumber())
		if id >= maxUsers || seen[id] || pp.IdToBlock(id) != targetBlock {
			continue
		}
		seen[id] = true

		sk := new(bls.Scalar)
		sk.SetUint64(uint64((&security.RbeId{Ip: ip, Token: token}).SecretKey()))
		kp := rbe.NewKeyPair(pp, id, sk)
		idBar := pp.IdToIdBar(id)

		proof := new(bls.G1)
		if acc, ok := openingAcc[idBar]; ok {
			bts := acc.Bytes()
			proof.SetBytes(bts[:])
		} else {
			proof.SetIdentity()
		}

		for jBar := 0; jBar < pp.BlockSize; jBar++ {
			if jBar == idBar || kp.Xi[jBar] == nil {
				continue
			}
			acc, ok := openingAcc[jBar]
			if !ok {
				acc = new(bls.G1)
				acc.SetIdentity()
				openingAcc[jBar] = acc
			}
			acc.Add(acc, kp.Xi[jBar])
		}

		req := &pb.RegisterRequest{
			Id:        int64(id),
			PublicKey: g1ToProto(kp.PublicKey),
			Xi:        xiToProto(kp.Xi),
			Ip:        ip,
			Token:     token,
		}
		reqBytes, err := gproto.Marshal(req)
		if err != nil {
			tb.Fatalf("marshal RegisterRequest: %v", err)
		}

		peers = append(peers, &benchPeer{
			id:       id,
			reqBytes: reqBytes,
			req:      req,
			pk:       kp.PublicKey,
			xi:       kp.Xi,
			proof:    proof,
			notif: &pb.RegistrationNotification{
				Id:                   int64(id),
				Proof:                g1ToProto(proof),
				RegisterRequestBytes: reqBytes,
			},
		})
	}

	return &benchFixture{basePP: pp, peers: peers}
}
