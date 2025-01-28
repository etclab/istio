#!/bin/bash 

set -Eeuo pipefail
set -x

echo $(date)

kubectl apply -f all.yaml