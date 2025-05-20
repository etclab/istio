package trincutil

import (
	"crypto/sha256"

	"github.com/etclab/trinc"
	"istio.io/istio/pkg/log"
)

const TPM_SK_PATH = "/etc/tpm-keys/privateKey"
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

// func doVerifyCounter(pkFile, msgFile, attestationFile string) {
// 	pk, err := trinc.LoadECDSAPublicKeyFromPEMFile(pkFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't read public key file %q: %v", pkFile, err)
// 	}

// 	hash := hashFile(msgFile)
// 	fmt.Printf("expected hash: %x\n", hash)

// 	a, err := trinc.LoadCounterAttestationFromFile(attestationFile)
// 	if err != nil {
// 		mu.Fatalf("error: can't read attestation file %q: %v", attestationFile, err)
// 	}
// 	fmt.Println(a)

// 	result := a.Verify(pk)
// 	if !result {
// 		fmt.Println("failure: attestation has an invalid signature")
// 		os.Exit(1)
// 	}

// 	if !bytes.Equal(a.MsgHash, hash) {
// 		fmt.Println("failure: attestation MsgHash != expected hash")
// 		os.Exit(1)
// 	}

// 	fmt.Println("attestation verified successfully")
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
