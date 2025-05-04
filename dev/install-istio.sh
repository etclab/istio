#!/bin/bash

minikube stop -p $USER
minikube delete -p $USER

minikube start --profile=$USER --memory=65536 --cpus=32 --kubernetes-version=v1.31.0 --driver=kvm2

minikube profile $USER

go run ./istioctl/cmd/istioctl install --set hub=$HUB --set tag=$TAG -y