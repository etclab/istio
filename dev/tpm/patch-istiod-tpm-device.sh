#!/bin/bash

# patch istiod to use the TPM device resource
kubectl -n istio-system patch deployment istiod --type='strategic' --patch '
spec:
  template:
    spec:
      containers:
      - name: discovery
        resources:
          limits:
            tpm.boxboat.io/tpmrm: 1
'
