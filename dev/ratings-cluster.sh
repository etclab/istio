#!/bin/bash

go run ./istioctl/cmd/istioctl proxy-config cluster $(kubectl get pods --selector=app=ratings -o jsonpath='{.items[0].metadata.name}') -o json > ratings-cluster.json