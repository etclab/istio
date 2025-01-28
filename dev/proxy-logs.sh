# first get the (first) pod name of the details service
# then get the logs for istio-proxy container from the pod
# kubectl logs $(kubectl get pods --selector=app=details -o jsonpath='{.items[0].metadata.name}') -c istio-proxy > detailsv1-proxy.log
# kubectl logs $(kubectl get pods --selector=app=ratings -o jsonpath='{.items[0].metadata.name}') -c istio-proxy > ratingsv1-proxy.log
kubectl logs $(kubectl get pods --selector=app=ratings -o jsonpath='{.items[0].metadata.name}') -c istio-proxy > ratingsv1-proxy.log
