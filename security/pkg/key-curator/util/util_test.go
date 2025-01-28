package keycurator

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPodValiditySave(t *testing.T) {
	podValidityMap := map[string]bool{
		"10.244.0.203|9080|spiffe://cluster.local/ns/default/sa/bookinfo-details":     true,
		"10.244.0.204|9080|spiffe://cluster.local/ns/default/sa/bookinfo-productpage": true,
		"10.244.0.205|9080|spiffe://cluster.local/ns/default/sa/bookinfo-ratings":     true,
		"10.244.0.206|9080|spiffe://cluster.local/ns/default/sa/bookinfo-reviews":     true,
	}

	data, err := json.Marshal(podValidityMap)
	if err != nil {
		t.Errorf("Error marshalling podValidityMap: %v", err)
	}

	f, err := os.Create("pod_validity_map.json")
	if err != nil {
		t.Errorf("Error creating file: %v", err)
	}
	defer f.Close()

	_, err = f.WriteString(string(data))
	if err != nil {
		t.Errorf("Error writing to file: %v", err)
	}
}
