#!/bin/bash
# filepath: /users/apoudel/mazu/scripts/workspace/istio/dev/tpm/deploy-tpm-pubkey-configmap.sh

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Create a ConfigMap with the public key in each namespace
# NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
NAMESPACES=(default)

for NAMESPACE in $NAMESPACES; do
  kubectl delete configmap tpm-pubkey -n $NAMESPACE

  kubectl create configmap tpm-pubkey \
    --from-file=publicKey=${SCRIPT_DIR}/test-keys/pk.key \
    -n ${NAMESPACE} \
    --dry-run=client -o yaml | kubectl apply -f -
  
  # Get all deployments in the namespace
  DEPLOYMENTS=$(kubectl get deployments -n $NAMESPACE -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  
  for DEPLOYMENT in $DEPLOYMENTS; do
    echo "Patching deployment: $DEPLOYMENT in namespace: $NAMESPACE"
    
    # Get the container names for this deployment
    CONTAINER_NAMES=$(kubectl get deployment $DEPLOYMENT -n $NAMESPACE -o jsonpath='{.spec.template.spec.containers[*].name}')
    
    for CONTAINER in $CONTAINER_NAMES; do
      echo "  Patching container: $CONTAINER"
      
      kubectl -n $NAMESPACE patch deployment $DEPLOYMENT --type='strategic' -p="
spec:
  template:
    spec:
      volumes:
        - name: tpm-pubkey-volume
          configMap:
            name: tpm-pubkey
      containers:
        - name: $CONTAINER
          volumeMounts:
            - name: tpm-pubkey-volume
              mountPath: /etc/tpm-keys
              readOnly: true
"
    done
  done
done

echo "All deployments have been patched with the TPM public key ConfigMap."