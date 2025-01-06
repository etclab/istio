#!/bin/bash

make DEBUG=1 docker.pilot
make push.docker.pilot
kubectl set image deployment/istiod -n istio-system discovery=$DOCKER_USER/pilot:$DOCKER_USER
kubectl rollout restart deployment istiod -n istio-system

# make DEBUG=1 docker.pilot && make push.docker.pilot

# make DEBUG=1 docker.pilot && make push.docker.pilot && kubectl set image deployment/istiod -n istio-system discovery=$DOCKER_USER/pilot:$DOCKER_USER && kubectl rollout restart deployment istiod -n istio-system
