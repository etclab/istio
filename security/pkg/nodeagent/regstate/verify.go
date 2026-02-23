package regstate

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	gproto "google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/log"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	trincutil "istio.io/istio/security/pkg/trinc/util"
)

var regstateLog = log.RegisterScope("regstate", "registration state verification")

// VerifyAndStore verifies the counter attestation, applies the registration to
// the local RBE state, verifies the membership proof, then stores the result.
func VerifyAndStore(store *Store, rbeState *LocalRBEState, notif *pb.RegistrationNotification) bool {
	id := int(notif.GetId())

	// --- Step 1: Verify counter attestation ---
	if notif.GetCounterAttestation() != nil && notif.GetRegisterRequestBytes() != nil {
		attestation := trincutil.AttestationFromProto(notif.GetCounterAttestation())

		// reconstruct attestUserData in the same byte order as the server:
		// regMsg + proofBytes
		regMsg := notif.GetRegisterRequestBytes()
		proofBytes, _ := gproto.Marshal(notif.GetProof())
		attestUserData := append(regMsg, proofBytes...)

		if !trincutil.DoVerifyCounter(attestUserData, attestation) {
			regstateLog.Errorf("attestation verification failed for id=%d", id)
			return false
		}
		regstateLog.Infof("attestation verified for id=%d", id)
	}

	// --- Step 2: Extract publicKey and xi from the RegisterRequest ---
	var publicKey *bls.G1
	var xi []*bls.G1

	if notif.GetRegisterRequestBytes() != nil {
		req := &pb.RegisterRequest{}
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

	// --- Step 3: Apply registration to local RBE state ---
	if publicKey != nil && xi != nil {
		if rbeState.ApplyRegistration(id, publicKey, xi) {
			regstateLog.Infof("[dev] applied registration to local RBE state for id=%d", id)
		} else {
			regstateLog.Infof("[dev] registration already applied for id=%d, skipping state update", id)
		}
	}

	// --- Step 4: Verify RBE membership proof ---
	var proof *bls.G1
	if notif.GetProof() != nil && len(notif.GetProof().GetPoint()) > 0 {
		proof = new(bls.G1)
		proof.SetBytes(notif.GetProof().GetPoint())
	}

	if proof != nil && publicKey != nil {
		pp := rbeState.GetPP()
		if !rbe.VerifyMembership(pp, id, publicKey, proof) {
			regstateLog.Errorf("membership verification failed for id=%d", id)
			return false
		}
		regstateLog.Infof("membership verified for id=%d", id)
	}

	// --- Step 5: Store verified registration ---
	// TODO: CheckPodValidity()-style validation goes here next
	store.Put(&UserRegistration{
		ID:          id,
		Proof:       proof,
		Attestation: trincutil.AttestationFromProto(notif.GetCounterAttestation()),
	})

	regstateLog.Infof("stored verified registration for id=%d", id)
	return true
}
