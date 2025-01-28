#!/bin/bash 

set -Eeuo pipefail
set -x

echo $(date)

kubectl get pods -n istio-system