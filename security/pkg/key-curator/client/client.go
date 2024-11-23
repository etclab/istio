package client

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	log "istio.io/istio/pkg/log"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

func TestKeyCurator() {
	// GrpcAddr
	addr := ":15010"

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("[key-curator/client] did not connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewKeyCuratorClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.Update(ctx, &pb.UpdateRequest{Id: "alice", Pp: "pp-alice"})
	if err != nil {
		log.Fatalf("[key-curator/client] could not update pp: %v", err)
	}
	log.Infof("[key-curator/client] update success got pp: %s", r.GetU())
}
