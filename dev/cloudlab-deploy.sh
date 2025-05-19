#!/bin/bash

DOCKER_USER=atosh502
export HUB="docker.io/$DOCKER_USER"
export TAG=$DOCKER_USER

export GOTOOLCHAIN=auto

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cd $SCRIPT_DIR/../

./dev/install-etcd.sh
./dev/deploy-tpm-secret.sh
# ./setup-tpm-all-nodes.sh -d wisc.cloudlab.us c220g1-030802 c220g1-030810 c220g1-030815 c220g1-030808

go run ./istioctl/cmd/istioctl install --set hub=$HUB --set tag=$TAG --set "values.global.imagePullPolicy=Always" -y