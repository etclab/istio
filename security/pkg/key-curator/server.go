package keycurator

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

type KeyCuratorServer struct {
	pb.UnimplementedKeyCuratorServer

	Authenticators []security.Authenticator

	// ca             CertificateAuthority
	// serverCertTTL  time.Duration

	// todo: (besides ca & serverCertTTL) authenticators, monitoring and nodeAuthorizer seem relevant
	// monitoring     monitoringMetrics
	// nodeAuthorizer *MulticlusterNodeAuthorizor
}

// Register registers a GRPC server on the specified port.
func (s *KeyCuratorServer) Register(grpcServer *grpc.Server) {
	pb.RegisterKeyCuratorServer(grpcServer, s)
}

func (s *KeyCuratorServer) Update(_ context.Context, in *pb.UpdateRequest) (*pb.UpdateResponse, error) {
	log.Printf("update from: %v", in.GetId())
	return &pb.UpdateResponse{U: "upd"}, nil
}

func main() {

	addr := "localhost:16000"
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterKeyCuratorServer(s, &KeyCuratorServer{})

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
