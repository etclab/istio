#!/bin/bash

# TODO: setup tpm device on all nodes before running this script
# ./setup-tpm-all-nodes.sh -d wisc.cloudlab.us c220g1-030802 c220g1-030810 c220g1-030815 c220g1-030808

DOCKER_USER=atosh502
export HUB="docker.io/$DOCKER_USER"
export TAG=$DOCKER_USER

export GOTOOLCHAIN=auto

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cd $SCRIPT_DIR/../

./dev/install-etcd.sh
./dev/tpm/install-k8s-tpm-device.sh

go run ./istioctl/cmd/istioctl install --set hub=$HUB --set tag=$TAG --set "values.global.imagePullPolicy=Always" -y

kubectl label namespace default istio-injection=enabled
kubectl apply -f ./dev/yaml/token-review-role.yaml 
kubectl apply -f ./dev/yaml/token-review-binding.yaml 


./dev/tpm/deploy-tpm-secret.sh
./dev/tpm/patch-istiod-tpm-device.sh

cd -