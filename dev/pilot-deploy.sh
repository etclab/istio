#!/bin/bash

make DEBUG=1 docker.pilot
make push.docker.pilot
kubectl set image deployment/istiod -n istio-system discovery=atosh502/pilot:atosh502
kubectl rollout restart deployment istiod -n istio-system
