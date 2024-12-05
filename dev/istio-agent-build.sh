#!/bin/bash 

make DEBUG=1 docker.proxyv2
make push.docker.proxyv2

kubectl rollout restart deployment ratings-v1