package regstate

import (
	"fmt"
	"sync"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/trinc"

	"istio.io/istio/pkg/log"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
)

// RegistrationSource indicates which path delivered a registration notification.
type RegistrationSource int

const (
	SourceStream   RegistrationSource = iota // ordered replay + live from KC
	SourceFastPath                           // own registration, before ordered replay
	SourceOnDemand                           // fetched out-of-order by ext_authz
)

// UserRegistration holds verified registration data for a single user.
type UserRegistration struct {
	ID            int
	Proof         *bls.G1
	Attestation   *trinc.CounterAttestation
	PodValid      bool // result of encrypt/decrypt challenge-response
	ProofVerified bool // true only when proof was verified against ordered commitments
}

// Store is a thread-safe map of user ID to registration data.
// The agent populates it (writer); the ext_authz server reads it (reader).
type Store struct {
	mu    sync.RWMutex
	users map[int]*UserRegistration
}

func NewStore() *Store {
	return &Store{users: make(map[int]*UserRegistration)}
}

func (s *Store) Put(reg *UserRegistration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[reg.ID] = reg
}

func (s *Store) Get(id int) (*UserRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.users[id]
	return r, ok
}

// SetProofVerified marks an existing registration as proof-verified.
// Returns true if the entry existed and was updated, false otherwise.
func (s *Store) SetProofVerified(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := s.users[id]
	if !ok {
		return false
	}
	reg.ProofVerified = true
	return true
}

func (s *Store) GetAll() map[int]*UserRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[int]*UserRegistration, len(s.users))
	for k, v := range s.users {
		cp[k] = v
	}
	return cp
}

var storeLog = log.RegisterScope("regstate-store", "registration state store")

// LocalRBEState tracks the agent's local view of RBE commitments and openings,
// mirroring the KeyCurator's RegisterUser() logic on the receiving side.
// Openings are stored sparsely: only for users we've actually seen in notifications.
type LocalRBEState struct {
	mu            sync.RWMutex
	pp            *rbe.PublicParams               // separate copy, loaded from file
	userOpenings  map[int]map[int][]*bls.G1       // blockId -> userId -> opening history
	registeredIds map[int]bool                    // track which IDs have been applied (for idempotency)

	// Ordered commitment shadow — updated ONLY by SourceStream registrations.
	// Mirrors the KC's commitment evolution for proof verification.
	orderedCommitments []*bls.G1
	orderedIds         map[int]bool
}

// NewLocalRBEState loads PP from file via keycurator.TryParseRbePpFromFile().
// Openings are lazily initialized per-user on first encounter.
func NewLocalRBEState() (*LocalRBEState, error) {
	pp, err := keycurator.TryParseRbePpFromFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load PP from file: %w", err)
	}

	storeLog.Infof("[dev] initialized LocalRBEState with MaxUsers=%d, BlockSize=%d, NumBlocks=%d",
		pp.MaxUsers, pp.BlockSize, pp.NumBlocks)

	// Deep-copy initial commitments (identity points) into orderedCommitments.
	orderedComm := make([]*bls.G1, len(pp.Commitments))
	for i, c := range pp.Commitments {
		cp := new(bls.G1)
		b := c.Bytes()
		cp.SetBytes(b[:])
		orderedComm[i] = cp
	}

	return &LocalRBEState{
		pp:                 pp,
		userOpenings:       make(map[int]map[int][]*bls.G1),
		registeredIds:      make(map[int]bool),
		orderedCommitments: orderedComm,
		orderedIds:         make(map[int]bool),
	}, nil
}

// getOrInitOpening returns the opening history for userId in blockId,
// lazily initializing it to a single identity element if not yet present.
// Must be called with s.mu held.
func (s *LocalRBEState) getOrInitOpening(blockId, userId int) []*bls.G1 {
	block, ok := s.userOpenings[blockId]
	if !ok {
		block = make(map[int][]*bls.G1)
		s.userOpenings[blockId] = block
	}
	openings, ok := block[userId]
	if !ok {
		identity := new(bls.G1)
		identity.SetIdentity()
		openings = []*bls.G1{identity}
		block[userId] = openings
	}
	return openings
}

// ApplyRegistration mirrors rbe.KeyCurator.RegisterUser(): updates commitments
// and openings for other users in the same block. Returns false if already applied (idempotent).
func (s *LocalRBEState) ApplyRegistration(id int, publicKey *bls.G1, xi []*bls.G1) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.registeredIds[id] {
		return false
	}

	pp := s.pp
	k := pp.IdToBlock(id)
	idBar := pp.IdToIdBar(id)

	// update commitment: com[k] = com[k] + pk
	com := pp.Commitments[k]
	com.Add(com, publicKey)

	// update openings for the other users in that block
	for jBar := 0; jBar < pp.BlockSize; jBar++ {
		if jBar == idBar {
			continue
		}

		jId := pp.IdBarToId(jBar, k)
		jOpenings := s.getOrInitOpening(k, jId)
		lastOpening := jOpenings[len(jOpenings)-1]

		newOpening := new(bls.G1)
		newOpening.Add(lastOpening, xi[jBar])

		s.userOpenings[k][jId] = append(jOpenings, newOpening)
	}

	s.registeredIds[id] = true
	return true
}

// GetPP returns the local public params (thread-safe).
func (s *LocalRBEState) GetPP() *rbe.PublicParams {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pp
}

// GetOpening returns the opening history for a given userId (thread-safe).
// Returns a single identity element if the user hasn't been seen yet.
func (s *LocalRBEState) GetOpening(userId int) []*bls.G1 {
	s.mu.Lock()
	defer s.mu.Unlock()
	blockId := s.pp.IdToBlock(userId)
	return s.getOrInitOpening(blockId, userId)
}

// IsRegistered returns whether the given ID has been applied (thread-safe).
func (s *LocalRBEState) IsRegistered(id int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registeredIds[id]
}

// ApplyOrderedCommitment updates the ordered commitment shadow for the given
// user's block. Only called for SourceStream registrations. Idempotent via orderedIds.
// Returns true if this was a new application, false if already applied.
func (s *LocalRBEState) ApplyOrderedCommitment(id int, publicKey *bls.G1) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.orderedIds[id] {
		return false
	}

	k := s.pp.IdToBlock(id)
	com := s.orderedCommitments[k]
	com.Add(com, publicKey)

	s.orderedIds[id] = true
	return true
}

// VerifyMembershipOrdered verifies an RBE membership proof against the ordered
// commitment shadow (not the primary pp.Commitments). Creates a shallow copy of
// PP with orderedCommitments substituted. Thread-safe (takes RLock).
func (s *LocalRBEState) VerifyMembershipOrdered(id int, publicKey *bls.G1, proof *bls.G1) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ppCopy := *s.pp
	ppCopy.Commitments = s.orderedCommitments
	return rbe.VerifyMembership(&ppCopy, id, publicKey, proof)
}
