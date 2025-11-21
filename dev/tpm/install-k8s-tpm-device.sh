#!/bin/bash

helm repo add k8s-tpm-device https://boxboat.github.io/k8s-tpm-device/chart
helm repo update
helm upgrade --install k8s-tpm-device --namespace tpm-device --create-namespace k8s-tpm-device/k8s-tpm-device 