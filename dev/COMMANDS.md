### Commands

- check if sidecar injection is enabled
    - `kubectl get namespace -L istio-injection`
    - enable sidecar injection with: `kubectl label namespace default istio-injection=enabled`

- set `imagePullPolicy` to `Always` for `istiod` (this ensures latest image for istiod is pulled from docker hub)
    - `kubectl edit deployment istiod -n istio-system`
    - set `imagePullPolicy: Always`
- update policy of sidecar to always pull new image 
	- `kubectl edit configmap istio-sidecar-injector -n istio-system`
	- set the `imagePullPolicy: Always`

- get logs from proxy (proxy resides with app container in a pod)
	- `kubectl logs <pod-name> -c istio-proxy > detailsv1-proxy.log`
- describe a kubernetes pod (useful for viewing configs and init containers within the pod) 
	- `kubectl describe pod <pod-name> > details-describe`
- get containers within a pod
	- `kubectl get pods <pod-name> -o jsonpath='{.spec.containers[*].name}'`
- update container image inside a deployment
	- `kubectl set image deployment/details-v1 istio-proxy=atosh502/proxyv2:atosh502`
- get logs from proxy (using the deployment selector instead of pod name)
	- `kubectl logs $(kubectl get pods --selector=app=details -o jsonpath='{.items[0].metadata.name}') -c istio-proxy > detailsv1-proxy.log`
- delete a pod (this will first delete then restart the pod)
	- `kubectl delete pods -l app=details`
- port forward from within kubernetes
	- `kubectl port-forward --address localhost deployment/details-v1 40000:40000`
- get a shell inside a pod's container:
	- `kubectl exec -it details-v1-79dfbd6fff-jsgz8 -c istio-proxy -- /bin/bash`
- scale number of replicas
	- `kubectl scale deployment/my-nginx --replicas=1`
- set `debug` logging for a pod using annotation (set this inside `spec:template:metadata:annotations`)
	- `sidecar.istio.io/logLevel: "debug"`
- rollout a kubernetes deployment
	- `kubectl rollout restart deployment ratings-v1`



