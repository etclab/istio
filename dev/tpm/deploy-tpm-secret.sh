SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

kubectl delete secret tpm-keys -n istio-system

kubectl create secret generic tpm-keys \
  --from-file=privateKey=${SCRIPT_DIR}/test-keys/sk.key \
  --from-file=publicKey=${SCRIPT_DIR}/test-keys/pk.key \
  -n istio-system

kubectl -n istio-system patch deployment istiod --type='strategic' -p='
spec:
  template:
    spec:
      volumes:
        - name: tpm-keys-volume
          secret:
            secretName: tpm-keys
      containers:
        - name: discovery
          volumeMounts:
            - name: tpm-keys-volume
              mountPath: /etc/tpm-keys
              readOnly: true
'

# kubectl get deployments istiod -n istio-system -o yaml > istiod-deploy.yaml
# POD_NAME=$(kubectl get pods -n istio-system -l app=istiod -o jsonpath='{.items[0].metadata.name}')
# kubectl get pods "${POD_NAME}" -n istio-system -o yaml > istiod-pod.yaml