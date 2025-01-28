### Admin Signed JWT Token
<details closed>
  <summary>Sample Token</summary>
  eyJhbGciOiJSUzI1NiIsImtpZCI6IkpYODdYN2hTajBCV2ZpMXRoTncxc2ZpQVd1UnpQRDFmR1Z5anBSVzByYk0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzY4NTE3NTk3LCJpYXQiOjE3MzY5ODE1OTcsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiYTlhMTg2YjktNThjNC00MDAwLWI3NjctZTU1Mzk5ZDI3OGRkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoibWluaWt1YmUiLCJ1aWQiOiJhYWQ0MmE2Yi1iNWRjLTRkOTYtOTViMy05MDJjZTNkYzllNGEifSwicG9kIjp7Im5hbWUiOiJyYXRpbmdzLXYxLTg5OTc5NTY1OS03ZHI0eiIsInVpZCI6Ijg1OTdiYzNiLTcyMTktNDdkYy05ZDlkLWE0YTZiZmViOGQ5NCJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiYm9va2luZm8tcmF0aW5ncyIsInVpZCI6IjNiM2Y2M2RlLTE0M2QtNGMwNy1hNDYyLWZhNDQxYjRlN2MyYyJ9LCJ3YXJuYWZ0ZXIiOjE3MzY5ODUyMDR9LCJuYmYiOjE3MzY5ODE1OTcsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmJvb2tpbmZvLXJhdGluZ3MifQ.tHAyksVFZNwIaATTBqLYIzxNce_hD1q0OFrlo7JVCWBLC2RsOcATf4wJ5eT5Jxs_83Rxa2sCT1KGTNbqxTxZj9aqw2NGqHFumaRzvQS89SOz-ix0unSyeqDEDAcnMuF-p2nmIJVFdlS5PBSvzY63H4YyvBC21lXNk2AcePEyPnj8dlvqsU0QLLPyDp4B_SzmGWQ3juq_8SjtGAnz6CBf0OI6rBBf_bb1IJwav0daqPbn2VCXvZOKivz_W-bM2rYYl8nYVPOQrulENu5Pc8ipXHd3b91qe1RlRr4BY5u5yK7_0AklzzilPqdynucys5M3ND-ClZb2BRHMGHWD6o0O4A
</details>

### Token Contents
- Header
```json
{
  "alg": "RS256",
  "kid": "JX87X7hSj0BWfi1thNw1sfiAWuRzPD1fGVyjpRW0rbM"
}
```

- Payload
```json
{
  "aud": [
    "https://kubernetes.default.svc.cluster.local"
  ],
  "exp": 1768517597,
  "iat": 1736981597,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "jti": "a9a186b9-58c4-4000-b767-e55399d278dd",
  "kubernetes.io": {
    "namespace": "default",
    "node": {
      "name": "minikube",
      "uid": "aad42a6b-b5dc-4d96-95b3-902ce3dc9e4a"
    },
    "pod": {
      "name": "ratings-v1-899795659-7dr4z",
      "uid": "8597bc3b-7219-47dc-9d9d-a4a6bfeb8d94"
    },
    "serviceaccount": {
      "name": "bookinfo-ratings",
      "uid": "3b3f63de-143d-4c07-a462-fa441b4e7c2c"
    },
    "warnafter": 1736985204
  },
  "nbf": 1736981597,
  "sub": "system:serviceaccount:default:bookinfo-ratings"
}
```
  - Kubernetes creates the `ratings` service running as `bookinfo-ratings` service account in the `pod.name` pod. 
  - `pod.uid` is unique to each deployed pod
  - `sub` refers to the Subject of the token (ie who the token refers to)
  - `iat` and `exp` are the issued at and expiry times of the token but Kubernetes invalidates the token once the pod goes down even though it has not expired
---
### SPIFFE URL
- SPIFFE URL has the structure:
```bash
spiffe://<trust_domain>/ns/<namespace>/sa/<service_account>
```
- SPIFFE URL for above `ratings` service is:
```bash
spiffe://cluster.local/ns/default/sa/bookinfo-ratings
```