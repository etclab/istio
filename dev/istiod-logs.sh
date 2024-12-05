#!/bin/bash

kubectl logs -n istio-system -l app=istiod --tail=100000000 > istiod.log