#!/bin/bash

# patch istiod to use the TPM device resource

# 116 is the group id of tss
kubectl -n istio-system patch deployment istiod --type='strategic' --patch '
spec:
  template:
    spec:
      securityContext:
        supplementalGroups: [116]
      containers:
      - name: discovery
        resources:
          limits:
            tpm.boxboat.io/tpmrm: 1
'
