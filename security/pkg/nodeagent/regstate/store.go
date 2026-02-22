package regstate

import (
	"sync"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/trinc"
)

// UserRegistration holds verified registration data for a single user.
type UserRegistration struct {
	ID          int
	Proof       *bls.G1
	Attestation *trinc.CounterAttestation
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

func (s *Store) GetAll() map[int]*UserRegistration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make(map[int]*UserRegistration, len(s.users))
	for k, v := range s.users {
		cp[k] = v
	}
	return cp
}
