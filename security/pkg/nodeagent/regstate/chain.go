package regstate

import (
	"fmt"
	"sync"

	"istio.io/istio/pkg/log"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

// ChainVerifier enforces monotonically increasing TRINC counter values
// across an ordered sequence of registration notifications. It detects
// gaps or reordering that would indicate a tampered notification log.
type ChainVerifier struct {
	mu          sync.Mutex
	lastCounter uint64
	initialized bool
}

var chainLog = log.RegisterScope("chain-verifier", "chain verifier log")

func NewChainVerifier() *ChainVerifier {
	return &ChainVerifier{}
}

// Verify checks that the notification's counter attestation has the expected
// next counter value (lastCounter + 1). The first notification initializes
// the expected counter. Returns nil if the notification has no attestation
// (attestation disabled).
func (cv *ChainVerifier) Verify(notif *pb.RegistrationNotification) error {
	if notif.GetCounterAttestation() == nil {
		return nil
	}

	counter := notif.GetCounterAttestation().GetCounter()

	cv.mu.Lock()
	defer cv.mu.Unlock()

	if !cv.initialized {
		cv.lastCounter = counter
		cv.initialized = true
		return nil
	}

	if counter != cv.lastCounter+1 {
		return fmt.Errorf("counter chain broken: expected %d, got %d (id=%d)",
			cv.lastCounter+1, counter, notif.GetId())
	} else {
		chainLog.Infof("counter chain verified: expected %d, got %d (id=%d)",
			cv.lastCounter+1, counter, notif.GetId())
	}

	cv.lastCounter = counter
	return nil
}
