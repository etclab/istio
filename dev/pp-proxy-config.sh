#!/bin/bash

# https://istio.io/latest/docs/ops/diagnostic-tools/proxy-cmd/

# go run ./istioctl/cmd/istioctl proxy-config clusters $1 > dev/pp-proxy-configs/clusters

# clusters
go run ./istioctl/cmd/istioctl proxy-config clusters $1 -o json > dev/pp-proxy-configs/clusters

# go run ./istioctl/cmd/istioctl proxy-config listeners $1 > dev/pp-proxy-configs/listeners

# inbound listeners
# go run ./istioctl/cmd/istioctl proxy-config listeners $1 --port 15006 -o json > dev/pp-proxy-configs/inbound-listeners.json

# outbound listeners
# go run ./istioctl/cmd/istioctl proxy-config listeners $1 --port 15001 -o json > dev/pp-proxy-configs/outbound-listeners.json

# routes
# go run ./istioctl/cmd/istioctl proxy-config routes $1 --name 9080 -o json > dev/pp-proxy-configs/routes.json

# endpoints
# go run ./istioctl/cmd/istioctl proxy-config endpoints $1 --cluster "outbound|9080||details.default.svc.cluster.local" > dev/pp-proxy-configs/endpoints-details

