package regstate

import (
	"fmt"
	"time"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	gproto "google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
	trincutil "istio.io/istio/security/pkg/trinc/util"
)

var regstateLog = log.RegisterScope("regstate", "registration state verification")

// VerifyAndStore is a backward-compatible wrapper that processes a registration
// as if it came from the ordered stream.
func VerifyAndStore(store *Store, rbeState *LocalRBEState, notif *pb.RegistrationNotification) bool {
	return ProcessRegistration(store, rbeState, notif, SourceStream)
}

// ProcessRegistration verifies and stores a registration notification with
// source-aware processing. Stream registrations update the ordered commitment
// shadow and verify proofs against it. FastPath and OnDemand skip proof
// verification (relying on challenge-response) and mark ProofVerified=false.
// When the stream later delivers a previously-applied registration, deferred
// proof verification runs and the store is updated.
func ProcessRegistration(store *Store, rbeState *LocalRBEState, notif *pb.RegistrationNotification, source RegistrationSource) bool {
	id := int(notif.GetId())

	// --- Step 1: Verify counter attestation ---
	if notif.GetCounterAttestation() != nil && notif.GetRegisterRequestBytes() != nil {
		attestation := trincutil.AttestationFromProto(notif.GetCounterAttestation())

		regMsg := notif.GetRegisterRequestBytes()
		proofBytes, _ := gproto.Marshal(notif.GetProof())
		attestUserData := append(regMsg, proofBytes...)

		if !trincutil.DoVerifyCounter(attestUserData, attestation) {
			regstateLog.Errorf("attestation verification failed for id=%d", id)
			return false
		}
		regstateLog.Infof("attestation verified for id=%d", id)
	}

	// --- Step 2: Extract publicKey, xi, and req from the RegisterRequest ---
	var publicKey *bls.G1
	var xi []*bls.G1
	var req *pb.RegisterRequest

	if notif.GetRegisterRequestBytes() != nil {
		req = &pb.RegisterRequest{}
		if err := gproto.Unmarshal(notif.GetRegisterRequestBytes(), req); err != nil {
			regstateLog.Errorf("failed to unmarshal RegisterRequest for id=%d: %v", id, err)
			return false
		}

		publicKey = new(bls.G1)
		publicKey.SetBytes(req.GetPublicKey().GetPoint())

		xi = make([]*bls.G1, len(req.GetXi()))
		for i, v := range req.GetXi() {
			if len(v.GetPoint()) == 0 {
				xi[i] = nil
			} else {
				xi[i] = new(bls.G1)
				xi[i].SetBytes(v.GetPoint())
			}
		}
	}

	// --- Step 3: Apply registration to primary RBE state ---
	alreadyApplied := false
	if publicKey != nil && xi != nil {
		if rbeState.ApplyRegistration(id, publicKey, xi) {
			regstateLog.Infof("[dev] applied registration to local RBE state for id=%d (source=%d)", id, source)
		} else {
			regstateLog.Infof("[dev] registration already applied for id=%d (source=%d), skipping state update", id, source)
			alreadyApplied = true
		}
	}

	// --- Step 3b: Update ordered commitment shadow (stream only) ---
	if source == SourceStream && publicKey != nil {
		rbeState.ApplyOrderedCommitment(id, publicKey)
	}

	// --- Step 4: Verify RBE membership proof (stream only, using ordered commitments) ---
	var proof *bls.G1
	if notif.GetProof() != nil && len(notif.GetProof().GetPoint()) > 0 {
		proof = new(bls.G1)
		proof.SetBytes(notif.GetProof().GetPoint())
	}

	proofVerified := false
	if source == SourceStream && proof != nil && publicKey != nil {
		if !rbeState.VerifyMembershipOrdered(id, publicKey, proof) {
			regstateLog.Errorf("membership verification failed for id=%d", id)
			return false
		}
		regstateLog.Infof("membership verified for id=%d (ordered)", id)
		proofVerified = true

		// Deferred proof verification: if the registration was already applied
		// by FastPath or OnDemand, just update ProofVerified and return early.
		if alreadyApplied {
			store.SetProofVerified(id)
			regstateLog.Infof("[dev] deferred proof verification completed for id=%d", id)
			return true
		}
	}

	// --- Step 5: Challenge-response validation ---
	podValid := false
	if req != nil {
		podValid = ValidatePodChallenge(rbeState, id, req)
		if podValid {
			regstateLog.Infof("pod challenge-response validated for id=%d", id)
		} else {
			regstateLog.Warnf("pod challenge-response failed for id=%d", id)
		}
	}

	// --- Step 6: Store verified registration ---
	store.Put(&UserRegistration{
		ID:            id,
		Proof:         proof,
		Attestation:   trincutil.AttestationFromProto(notif.GetCounterAttestation()),
		PodValid:      podValid,
		ProofVerified: proofVerified,
	})

	regstateLog.Infof("stored verified registration for id=%d (podValid=%t, proofVerified=%t, source=%d)", id, podValid, proofVerified, source)
	return true
}

// ValidatePodChallenge encrypts a nonce for the given user and verifies they
// can decrypt it, proving the key binding in the commitment is correct.
// Mirrors CheckPodValidity() in security/pkg/key-curator/util/util.go.
func ValidatePodChallenge(rbeState *LocalRBEState, otherUserId int, req *pb.RegisterRequest) (result bool) {
	// BLS crypto operations can panic on invalid inputs
	defer func() {
		if err := recover(); err != nil {
			regstateLog.Errorf("[dev] panic during pod challenge for id=%d: %+v", otherUserId, err)
		}
	}()

	pp := rbeState.GetPP()

	// 1. Generate nonce and hash to Gt
	nonce := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	nonceHash := keycurator.HashToGt(nonce)

	// 2. Encrypt nonce for the other user (standalone, no User needed)
	cipherText := rbe.Encrypt(pp, otherUserId, nonceHash)

	// 3. Derive other user's secret key from ip+token
	otherRbeId := &security.RbeId{
		Ip:    req.GetIp(),
		Token: req.GetToken(),
	}
	sk := new(bls.Scalar)
	sk.SetUint64(uint64(otherRbeId.SecretKey()))

	// 4. Create other user with the derived secret key
	otherUser := rbe.NewUserWithSecret(pp, otherUserId, sk)

	// 5. Get openings and update the other user
	openings := rbeState.GetOpening(otherUserId)
	otherUser.Update(pp.Commitments, openings)

	// 6. Decrypt and compare
	decryptedNonce, err := otherUser.Decrypt(cipherText)
	if err != nil {
		regstateLog.Errorf("[dev] failed to decrypt nonce for id=%d: %v", otherUserId, err)
		return false
	}

	return nonceHash.IsEqual(decryptedNonce)
}
