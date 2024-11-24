package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	log "istio.io/istio/pkg/log"
)

func TestKeyCurator() {
	// GrpcAddr
	addr := ":15010"

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("[key-curator/client] did not connect: %v", err)
	}
	defer conn.Close()
}
