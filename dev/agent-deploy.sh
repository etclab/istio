#!/bin/bash

# ensure kubectl pulls new image from docker hub
# kubectl edit configmap istio-sidecar-injector -n istio-system
# set imagepullpolicy to Always

make DEBUG=1 docker.proxyv2
make push.docker.proxyv2
# delete the pod -> new pod is deployed with the new image
kubectl delete pods -l app=ratings 
