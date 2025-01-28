#!/bin/bash 

set -Eeuo pipefail
set -x

echo $(date)

kubectl rollout restart deployment -n default