#!/bin/bash

kubectl logs -l app=productpage -c productpage --tail=100000000 > productpage.log
kubectl logs -l app=productpage -c istio-proxy --tail=100000000 > pp-istio-proxy.log