- Test if keycurator service is registered and running on the grpc server
    - Grpc server is running on `:15010`; secure version of the server runs on `:15012`
    - Port forward `kubectl port-forward -n istio-system <pod-name> 15010:15010`
    - using [grpcurl](https://github.com/fullstorydev/grpcurl?tab=readme-ov-file#from-source) list services: `grpcurl -plaintext :15010 list`
    - using grpcurl call methods on keycurator service: `grpcurl -plaintext -d '{"id": "alice", "pp": "pp-alice"}' :15010 keycurator.KeyCurator/Update`


- Build and deploy code changes
    - Edit the istiod deployment and set `imagePullPolicy` to `Always` as the latest image is not pulled from docker hub by default: `kubectl edit deployment istiod -n istio-system`
    - Build and deploy pilot with: `./dev/pilot-deploy.sh`
    - Get logs with: `./dev/get-log.sh`