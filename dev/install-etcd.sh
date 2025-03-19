#!/bin/bash

kubectl delete -f dev/yaml/etcd.yaml

# delete the old pvcs
kubectl delete pvc -l app=etcd -n istio-system

# create the istio-system namespace
kubectl create namespace istio-system || echo "namespace already exists"

kubectl apply -f dev/yaml/etcd.yaml