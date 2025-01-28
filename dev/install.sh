#!/bin/bash 

set -Eeuo pipefail
set -x

# install istio
go run ./istioctl/cmd/istioctl install --set hub=$HUB --set tag=$TAG -y

# enable sidecar injection 
kubectl label namespace default istio-injection=enabled

# install the bookinfo app
kubectl apply -f all.yaml

# always pull the latest istiod image
kubectl patch deployment istiod -n istio-system --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "Always"}]'

# kubectl edit configmap istio-sidecar-injector -n istio-system
# kubectl edit deployment istiod -n istio-system