#!/bin/bash

go run ./istioctl/cmd/istioctl proxy-config listeners $(kubectl get pods --selector=app=ratings -o jsonpath='{.items[0].metadata.name}') -o json > ratings-listeners.json