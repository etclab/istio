package regstate

import (
	"fmt"
	"sync"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	rbepb "github.com/etclab/rbe/proto"
	gproto "google.golang.org/protobuf/proto"

	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

// Tests for the lazy registration accumulator. Fixtures come from
// verify_bench_test.go; buildSingleBlockFixture is used throughout because
// peers in different blocks share no commitment and no openings, so every
// interaction worth testing happens within one block.

// appendAll replays peers[:n] into the lazy store in stream order.
func appendAll(tb testing.TB, lz *LazyStore, f *benchFixture, n int) {
	tb.Helper()
	for _, p := range f.peers[:n] {
		if !ProcessRegistrationLazy(lz, p.notif) {
			tb.Fatalf("ProcessRegistrationLazy failed for id=%d", p.id)
		}
	}
}

// TestLazyParityWithEagerPath is the load-bearing test: the same fixture that
// the eager path accepts must be accepted by the lazy path, for every peer.
func TestLazyParityWithEagerPath(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)

	// Eager path, for reference.
	state := f.newState()
	store := NewStore()
	for _, p := range f.peers {
		if !ProcessRegistration(store, state, p.notif, SourceStream) {
			t.Fatalf("eager ProcessRegistration failed for id=%d", p.id)
		}
		reg, ok := store.Get(p.id)
		if !ok || !reg.ProofVerified || !reg.PodValid {
			t.Fatalf("eager path did not fully verify id=%d", p.id)
		}
	}

	// Lazy path over the same registrations.
	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, len(f.peers))

	if got, want := lz.Len(), len(f.peers); got != want {
		t.Errorf("log length = %d, want %d", got, want)
	}
	for _, p := range f.peers {
		ok, timing := lz.Validate(p.id)
		if !ok {
			t.Errorf("id=%d: lazy validation failed where the eager path passed", p.id)
			continue
		}
		if timing.BlockDepth != len(f.peers) {
			t.Errorf("id=%d: block depth = %d, want %d", p.id, timing.BlockDepth, len(f.peers))
		}
		if timing.Decompressions != len(f.peers)-1 {
			t.Errorf("id=%d: decompressed %d xi points, want %d (one per other peer in the block)",
				p.id, timing.Decompressions, len(f.peers)-1)
		}
	}
}

// TestLazySelectiveValidation is the productpage/ratings case: only the peer
// actually dialed is ever validated, and the peers that are skipped cost
// nothing and affect nothing.
func TestLazySelectiveValidation(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 4)

	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, len(f.peers))

	target := f.peers[3]
	if ok, _ := lz.Validate(target.id); !ok {
		t.Fatalf("id=%d: validation failed", target.id)
	}
	for _, p := range f.peers[:3] {
		if lz.Validated(p.id) {
			t.Errorf("id=%d: was validated despite never being dialed", p.id)
		}
	}

	// Validating out of stream order is fine too.
	for _, i := range []int{1, 0, 2} {
		if ok, _ := lz.Validate(f.peers[i].id); !ok {
			t.Errorf("id=%d: validation failed out of order", f.peers[i].id)
		}
	}
}

// TestLazyValidationCached checks the memo: a second validation is served from
// it, and the verdict survives later registrations landing in the same block
// (a proven key-ID binding does not expire because a new peer appeared).
func TestLazyValidationCached(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 5)

	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, 3)

	target := f.peers[1]
	ok, timing := lz.Validate(target.id)
	if !ok {
		t.Fatalf("id=%d: first validation failed", target.id)
	}
	if timing.Cached {
		t.Error("first validation reported as cached")
	}

	if ok, timing = lz.Validate(target.id); !ok || !timing.Cached {
		t.Errorf("second validation: ok=%t cached=%t, want true/true", ok, timing.Cached)
	}

	// More registrations arrive; the verdict stands and new peers validate.
	appendAll(t, lz, f, len(f.peers))
	if ok, _ := lz.Validate(target.id); !ok {
		t.Errorf("id=%d: verdict lost after the block advanced", target.id)
	}
	if ok, _ := lz.Validate(f.peers[4].id); !ok {
		t.Errorf("id=%d: validation failed for a peer appended later", f.peers[4].id)
	}
}

// TestLazyValidationAtIncreasingDepth covers the case the eager path gets for
// free but a derived-on-read accumulator has to earn: a peer registered early
// must still validate once the block has grown around it.
func TestLazyValidationAtIncreasingDepth(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 6)

	for depth := 1; depth <= len(f.peers); depth++ {
		lz := NewLazyStore(f.basePP)
		appendAll(t, lz, f, depth)

		for i := 0; i < depth; i++ {
			if ok, _ := lz.Validate(f.peers[i].id); !ok {
				t.Errorf("depth=%d: id=%d (position %d) failed validation", depth, f.peers[i].id, i)
			}
		}
	}
}

// TestLazyUnknownPeerDenied — a peer whose registration has not been streamed
// is not validatable. Lazy mode denies rather than fetching from the KC.
func TestLazyUnknownPeerDenied(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)

	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, 2)

	absent := f.peers[2]
	if lz.Has(absent.id) {
		t.Fatalf("id=%d: reported present before being appended", absent.id)
	}
	if ok, _ := lz.Validate(absent.id); ok {
		t.Errorf("id=%d: validated without a registration in the log", absent.id)
	}
}

// TestLazyAppendIsIdempotent — the KC replays on reconnect; a duplicate must
// not enter the log twice, which would corrupt every prefix after it.
func TestLazyAppendIsIdempotent(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)

	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, len(f.peers))
	appendAll(t, lz, f, len(f.peers)) // replay

	if got, want := lz.Len(), len(f.peers); got != want {
		t.Errorf("log length after replay = %d, want %d", got, want)
	}
	for _, p := range f.peers {
		if ok, _ := lz.Validate(p.id); !ok {
			t.Errorf("id=%d: validation failed after a replayed append", p.id)
		}
	}
}

// TestLazyOutOfOrderAppendBreaksProofs documents why the agent must not append
// the fast-path notification: the log order is the prefix that every membership
// proof is checked against, so appending out of order fails a legitimate peer.
func TestLazyOutOfOrderAppendBreaksProofs(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)

	lz := NewLazyStore(f.basePP)
	// Stream order is 0, 1, 2. Append 1 first.
	for _, i := range []int{1, 0, 2} {
		if !ProcessRegistrationLazy(lz, f.peers[i].notif) {
			t.Fatalf("append failed for id=%d", f.peers[i].id)
		}
	}

	if ok, _ := lz.Validate(f.peers[1].id); ok {
		t.Error("a peer validated against a prefix it was not registered against; " +
			"log order would not need to match stream order")
	}
}

// TestLazyTamperedXiRejected — a registration carrying a valid but wrong xi
// point for the target index must not let the target pass. This is the check
// that moves from arrival time to first contact when xi decompression is
// deferred, so it needs to still be a real check.
func TestLazyTamperedXiRejected(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)

	target := f.peers[2]
	targetIdBar := f.basePP.IdToIdBar(target.id)

	for _, tc := range []struct {
		name  string
		point []byte
	}{
		// A syntactically valid G1 point in the wrong place: only the pairing
		// checks can catch this.
		{"valid point, wrong value", f.peers[0].pk.Bytes()},
		// Garbage: caught by the deferred SetBytes subgroup check.
		{"malformed point", make([]byte, 96)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lz := NewLazyStore(f.basePP)

			for i, p := range f.peers {
				notif := p.notif
				if i == 0 {
					notif = tamperXi(t, p, targetIdBar, tc.point)
				}
				if !ProcessRegistrationLazy(lz, notif) {
					// A malformed pk would be rejected here; xi is not touched
					// eagerly, so the append is expected to succeed.
					t.Fatalf("append failed for id=%d", p.id)
				}
			}

			if ok, _ := lz.Validate(target.id); ok {
				t.Errorf("id=%d validated against a tampered xi", target.id)
			}
		})
	}
}

// TestLazyTamperedProofRejected — the membership proof is still verified, just
// later. A bogus proof must fail rather than be skipped.
func TestLazyTamperedProofRejected(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 3)

	lz := NewLazyStore(f.basePP)
	for i, p := range f.peers {
		notif := p.notif
		if i == len(f.peers)-1 {
			notif = gproto.Clone(p.notif).(*pb.RegistrationNotification)
			notif.Proof = &rbepb.G1{Point: f.peers[0].pk.Bytes()}
		}
		if !ProcessRegistrationLazy(lz, notif) {
			t.Fatalf("append failed for id=%d", p.id)
		}
	}

	last := f.peers[len(f.peers)-1]
	if ok, _ := lz.Validate(last.id); ok {
		t.Errorf("id=%d validated with a tampered membership proof", last.id)
	}
}

// TestLazyConcurrentValidation exercises the singleflight coalescing and the
// lock-free read of the append-only log. Run with -race.
func TestLazyConcurrentValidation(t *testing.T) {
	quietLogs(t, true)
	f := buildSingleBlockFixture(t, 6)

	lz := NewLazyStore(f.basePP)
	appendAll(t, lz, f, 3)

	// Validators fan in on the peers already in the log while the stream keeps
	// appending — the scale-up shape.
	var wg sync.WaitGroup
	results := make(chan bool, 64)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range f.peers[3:] {
			if !ProcessRegistrationLazy(lz, p.notif) {
				t.Errorf("concurrent append failed for id=%d", p.id)
			}
		}
	}()

	for i := 0; i < 3; i++ {
		target := f.peers[i]
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, _ := lz.Validate(target.id)
				results <- ok
			}()
		}
	}

	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Error("a concurrent validation failed for a peer already in the log")
		}
	}
}

// tamperXi rebuilds a peer's notification with xi[idx] replaced.
func tamperXi(tb testing.TB, p *benchPeer, idx int, point []byte) *pb.RegistrationNotification {
	tb.Helper()

	req := &pb.RegisterRequest{}
	if err := gproto.Unmarshal(p.reqBytes, req); err != nil {
		tb.Fatalf("unmarshal: %v", err)
	}
	if idx >= len(req.Xi) {
		tb.Fatalf("xi index %d out of range (len=%d)", idx, len(req.Xi))
	}
	req.Xi[idx] = &rbepb.G1{Point: point}

	reqBytes, err := gproto.Marshal(req)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}

	notif := gproto.Clone(p.notif).(*pb.RegistrationNotification)
	notif.RegisterRequestBytes = reqBytes
	return notif
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// BenchmarkLazyEagerAppend measures the stream-path cost per registration under
// the lazy accumulator — the number that replaces the eager path's per-peer
// cost. Attestation is nil in the fixture, as it is for BenchmarkProcessRegistration,
// so the two are directly comparable.
func BenchmarkLazyEagerAppend(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)

	lz := NewLazyStore(f.basePP)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if i%len(f.peers) == 0 && i > 0 {
			b.StopTimer()
			lz = NewLazyStore(f.basePP)
			b.StartTimer()
		}
		ProcessRegistrationLazy(lz, f.peers[i%len(f.peers)].notif)
	}
}

// BenchmarkLazyValidateByBlockDepth measures the deferred first-contact cost,
// which is what the connection path pays. It grows with the number of
// registrations in the peer's block, since the opening is summed over them —
// unlike the eager path's challenge, which was flat.
func BenchmarkLazyValidateByBlockDepth(b *testing.B) {
	quietLogs(b, true)
	f := buildSingleBlockFixture(b, 64)

	for _, depth := range []int{1, 8, 32, 64} {
		if depth > len(f.peers) {
			continue
		}
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// A fresh store per iteration: Validate memoizes, so reusing
				// one would measure a map lookup.
				b.StopTimer()
				lz := NewLazyStore(f.basePP)
				appendAll(b, lz, f, depth)
				target := f.peers[depth-1]
				b.StartTimer()

				if ok, _ := lz.Validate(target.id); !ok {
					b.Fatalf("validation failed at depth=%d", depth)
				}
			}
		})
	}
}

// BenchmarkLazyValidateCached measures the steady-state cost once a peer has
// been validated — every connection after the first.
func BenchmarkLazyValidateCached(b *testing.B) {
	quietLogs(b, true)
	f := buildSingleBlockFixture(b, 8)

	lz := NewLazyStore(f.basePP)
	appendAll(b, lz, f, len(f.peers))
	target := f.peers[4]
	if ok, _ := lz.Validate(target.id); !ok {
		b.Fatal("priming validation failed")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lz.Validate(target.id)
	}
}

// BenchmarkStep2UnmarshalOnly separates the proto unmarshal from the 256 G1
// decompressions in step 2 — the split REGISTRATION-COST-FINDINGS.md lists as
// unmeasured. The difference against BenchmarkStep2UnmarshalAndDecompress is
// the decompression share, and the unmarshal is the floor the lazy eager path
// cannot go below.
func BenchmarkStep2UnmarshalOnly(b *testing.B) {
	quietLogs(b, true)
	f := buildFixture(b, benchPeers)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p := f.peers[i%len(f.peers)]
		req := &pb.RegisterRequest{}
		if err := gproto.Unmarshal(p.reqBytes, req); err != nil {
			b.Fatal(err)
		}
		// pk only: what the lazy eager path decompresses.
		pk := new(bls.G1)
		if err := pk.SetBytes(req.GetPublicKey().GetPoint()); err != nil {
			b.Fatal(err)
		}
	}
}
