package trincutil

import (
	"github.com/etclab/trinc"
	"istio.io/istio/pkg/log"
)

const TPM_SK_PATH = "/etc/tpm-keys/privateKey"
const DEVICE_PATH = "/dev/tpmrm0"

// returns and returns the secret key from TPM
func ReadTPMSk() {
	sk, err := trinc.LoadECDSAPrivateKeyFromPEMFile(TPM_SK_PATH)
	if err != nil {
		log.Errorf("[dev] Error reading TPM_SK_PATH %v", err)
	}

	log.Infof("[dev] Read TPM_SK_PATH %v", sk)
}
