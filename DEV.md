- Cmd for adding types from `etclab/rbe/proto/rbe.proto`
    - Inside `security/pkg/key-curator` download the `rbe.proto` from rbe repo: `wget https://raw.githubusercontent.com/etclab/rbe/refs/heads/proto/proto/rbe.proto -O rbeproto/rbe.proto`
    - Generate with: `protoc --go_out=. --go_opt=paths=source_relative rbeproto/rbe.proto`
    - And generate code for `key_curator.proto` with: `protoc -I./rbeproto -I./key-curator --go_out=./key-curator --go_opt=paths=source_relative --go-grpc_out=./key-curator --go-grpc_opt=paths=source_relative key-curator/key_curator.proto`
    - Test service with grpcurl: `grpcurl -plaintext -import-path ./security/pkg/key-curator/rbeproto/ -proto rbe.proto -import-path ./security/pkg/key-curator/key-curator -proto key_curator.proto :15010 keycurator.KeyCurator/FetchPublicParams`


- Test if keycurator service is registered and running on the grpc server
    - Grpc server is running on `:15010`; secure version of the server runs on `:15012`
    - Port forward `kubectl port-forward -n istio-system <pod-name> 15010:15010`
    - using [grpcurl](https://github.com/fullstorydev/grpcurl?tab=readme-ov-file#from-source) list services: `grpcurl -plaintext :15010 list`
    - using grpcurl call methods on keycurator service: `grpcurl -plaintext -d '{"id": "alice", "pp": "pp-alice"}' :15010 keycurator.KeyCurator/Update`


- Build and deploy code changes
    - Edit the istiod deployment and set `imagePullPolicy` to `Always` as the latest image is not pulled from docker hub by default: `kubectl edit deployment istiod -n istio-system`
    - Build and deploy pilot with: `./dev/pilot-deploy.sh`
    - Get logs with: `./dev/get-log.sh`