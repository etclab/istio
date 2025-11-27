package trincutil

import (
	"crypto/sha256"
	"math/big"

	"github.com/etclab/trinc"
	"istio.io/istio/pkg/log"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

const TPM_SK_PATH = "/etc/tpm-keys/privateKey"
const TPM_PK_PATH = "/etc/tpm-keys/publicKey"
const DefaultTPMDevPath = "/dev/tpmrm0"

// returns and returns the secret key from TPM
func ReadTPMSk() {
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(TPM_SK_PATH)
	if err != nil {
		log.Errorf("[dev] Error reading TPM_SK_PATH %v", err)
	}

	log.Infof("[dev] Read TPM_SK_PATH %v", sk)
}

func DoAttestCounter(msg []byte) (attestation *trinc.CounterAttestation, err error) {
	// msgHash is simply sha256 hash of message bytes
	msgHash := sha256.Sum256(msg)

	skFile := TPM_SK_PATH
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
	if err != nil {
		log.Errorf("[dev] error: can't load private key file %q: %v", skFile, err)
	}

	tk, err := trinc.NewTrinket(DefaultTPMDevPath, sk)
	if err != nil {
		log.Errorf("[dev] error: can't create trinket: %v", err)
	}
	defer tk.Close()

	attestation, err = tk.AttestCounter(msgHash[:])
	if err != nil {
		log.Errorf("[dev] error: can't generate attestation: %v", err)
	}
	return attestation, err
}

func AttestationFromProto(attestationPb *pb.CounterAttestation) *trinc.CounterAttestation {
	attestation := &trinc.CounterAttestation{}
	if attestationPb != nil {
		attestation.Counter = attestationPb.GetCounter()
		attestation.MsgHash = attestationPb.GetMsgHash()
		attestation.Signature = &trinc.ECDSASignature{
			R: new(big.Int).SetBytes(attestationPb.GetSignature().GetR()),
			S: new(big.Int).SetBytes(attestationPb.GetSignature().GetS()),
		}
	}
	return attestation
}

// func doAttestNVPCR(skFile, msgFile, attestationFile string) {
// 	hash := hashFile(msgFile)

// 	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(skFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't load private key file %q: %v", skFile, err)
// 	}

// 	tk, err := trinc.NewTrinket(trinc.DefaultTPMDevPath, sk)
// 	if err != nil {
// 		mu.Fatalf("error: can't create trinket: %v", err)
// 	}
// 	defer tk.Close()

// 	err = tk.ExtendNVPCR(hash)
// 	if err != nil {
// 		mu.Fatalf("error: can't extend nvpcr: %v", err)
// 	}

// 	a, err := tk.AttestNVPCR()
// 	if err != nil {
// 		mu.Fatalf("error: can't generate attestation: %v", err)
// 	}
// 	fmt.Println(a)

// 	err = a.ToFile(attestationFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't write attestation to file %q: %v", attestationFile, err)
// 	}
// }

// DoVerifyCounter is disabled
// func DoVerifyCounter(msgBytes []byte, attestation *trinc.CounterAttestation) bool {
// 	if attestation == nil || msgBytes == nil {
// 		log.Errorf("[dev] error: attestation or msgBytes is nil")
// 		return false
// 	}

// 	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(TPM_PK_PATH)
// 	if err != nil {
// 		log.Errorf("[dev] error: can't read public key file %q: %v", TPM_PK_PATH, err)
// 		return false
// 	}
// 	log.Infof("[dev] Read TPM_PK_PATH %v", pk)

// 	msgHash := sha256.Sum256(msgBytes)

// 	result := attestation.Verify(pk)
// 	if !result {
// 		log.Errorf("[dev] failure: attestation has an invalid signature")
// 		return false
// 	}

// 	if !bytes.Equal(attestation.MsgHash, msgHash[:]) {
// 		log.Errorf("[dev] failure: attestation MsgHash != expected hash")
// 		return false
// 	}

// 	log.Infof("[dev] attestation verified successfully")
// 	return true
// }

// func doVerifyPCR(pkFile, msgFile, attestationFile string) {
// 	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't read public key file %q: %v", pkFile, err)
// 	}

// 	hash := hashFile(msgFile)
// 	b := make([]byte, 32)
// 	b = append(b, hash[:]...)
// 	expected := sha256.Sum256(b)
// 	fmt.Printf("expected nvpcr: %x\n", hash)

// 	a, err := trinc.LoadNVPCRAttestationFromFile(attestationFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't read attestation file %q: %v", attestationFile, err)
// 	}
// 	fmt.Println(a)

// 	result := a.Verify(pk)
// 	if !result {
// 		fmt.Println("failure: attestation has an invalid signature")
// 		os.Exit(1)
// 	}

// 	if !bytes.Equal(a.NVPCR, expected[:]) {
// 		fmt.Println("failure: attestation NVPCR != expected hash")
// 		os.Exit(1)
// 	}

// 	fmt.Println("attestation verified successfully")
// }
