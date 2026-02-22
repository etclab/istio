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

// VerifyAndStore verifies the membership proof and counter attestation from a
// RegistrationNotification, then stores the result in the Store if valid.
func VerifyAndStore(store *Store, pp *rbe.PublicParams, notif *pb.RegistrationNotification) bool {
	id := int(notif.GetId())

	// deserialize proof
	var proof *bls.G1
	if notif.GetProof() != nil && len(notif.GetProof().GetPoint()) > 0 {
		proof = new(bls.G1)
		proof.SetBytes(notif.GetProof().GetPoint())
	}

	// TODO: do not verify proof currently as we haven't applied the openings,commitments updates
	// TODO: to our state and we wouldn't be able to verify the proof without it
	// verify membership proof if present
	// if proof != nil && notif.GetRegisterRequestBytes() != nil {
	// 	req := &pb.RegisterRequest{}
	// 	if err := gproto.Unmarshal(notif.GetRegisterRequestBytes(), req); err != nil {
	// 		regstateLog.Errorf("failed to unmarshal RegisterRequest for id=%d: %v", id, err)
	// 		return false
	// 	}
	// 	pubKey := new(bls.G1)
	// 	pubKey.SetBytes(req.GetPublicKey().GetPoint())

	// 	if !rbe.VerifyMembership(pp, id, pubKey, proof) {
	// 		regstateLog.Errorf("membership verification failed for id=%d", id)
	// 		return false
	// 	}
	// 	regstateLog.Infof("membership verified for id=%d", id)
	// }

	// verify counter attestation if present
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

	// store verified registration
	store.Put(&UserRegistration{
		ID:          id,
		Proof:       proof,
		Attestation: trincutil.AttestationFromProto(notif.GetCounterAttestation()),
	})

	regstateLog.Infof("stored verified registration for id=%d", id)
	return true
}
