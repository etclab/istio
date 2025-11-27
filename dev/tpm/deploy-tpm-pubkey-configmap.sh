#!/bin/bash
# filepath: /users/apoudel/mazu/scripts/workspace/istio/dev/tpm/deploy-tpm-pubkey-configmap.sh

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Create a ConfigMap with the public key in each namespace
# NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
NAMESPACES=(default istio-system)

for NAMESPACE in $NAMESPACES; do
  kubectl delete configmap tpm-pubkey -n $NAMESPACE

  kubectl create configmap tpm-pubkey \
    --from-file=publicKey=${SCRIPT_DIR}/test-keys/pk.key \
    -n ${NAMESPACE} \
    --dry-run=client -o yaml | kubectl apply -f -

done
