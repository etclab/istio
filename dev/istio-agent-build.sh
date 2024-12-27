#!/bin/bash 

make DEBUG=1 docker.proxyv2
make push.docker.proxyv2

kubectl rollout restart deployment ratings-v1

# make DEBUG=1 docker.proxyv2 && make push.docker.proxyv2 
# make DEBUG=1 docker.proxyv2 && make push.docker.proxyv2 && kubectl rollout restart deployment ratings-v1

# go run ./istioctl/cmd/istioctl proxy-config listeners $POD_NAME -o json > listeners-ratings.json
# go run ./istioctl/cmd/istioctl proxy-config cluster $POD_NAME -o json > cluster-ratings.json
