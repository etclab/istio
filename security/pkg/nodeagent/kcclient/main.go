package kcclient

// maybe call this rbeclient?

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"istio.io/istio/pkg/log"

	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

var kcClientLog = log.RegisterScope("kcclient", "key curator client debugging")

type KeyCuratorClient struct {
	Client pb.KeyCuratorClient
	conn   *grpc.ClientConn
}

func (kc *KeyCuratorClient) Close() {
	if kc.conn != nil {
		kc.conn.Close()
	}
}

// registers a workload's id with the key curator
func Register() {
	// create required messages
	// call the methods on key curator server
	// get the pp and possibly save it to secretcache for now
}

// gets the workload's updated public parameters
func UpdatePP() {
	// ...
}

func NewKeyCuratorClient(addr string) (*KeyCuratorClient, error) {
	// when do I close connection then?
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		kcClientLog.Errorf("failed to connect to key curator endpoint %s: %v", addr, err)
		return nil, fmt.Errorf("failed to connect to key curator endpoint")
	}

	kcClient := &KeyCuratorClient{}
	kcClient.conn = conn
	kcClient.Client = pb.NewKeyCuratorClient(conn)

	return kcClient, nil
}
