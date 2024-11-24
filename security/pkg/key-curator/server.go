package keycurator

import (
	"context"
	"net"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/rbe/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

type KeyCuratorServer struct {
	pb.UnimplementedKeyCuratorServer
	kc   *rbe.KeyCurator
	pp   *rbe.PublicParams
	user *rbe.User // todo: remove the user from keycurator after testing

	Authenticators []security.Authenticator

	// ca             CertificateAuthority
	// serverCertTTL  time.Duration

	// todo: (besides ca & serverCertTTL) authenticators, monitoring and nodeAuthorizer seem relevant
	// monitoring     monitoringMetrics
	// nodeAuthorizer *MulticlusterNodeAuthorizor
}

func NewKeyCuratorServer(maxUsers int) *KeyCuratorServer {
	pp := rbe.NewPublicParams(maxUsers)
	kc := rbe.NewKeyCurator(pp)

	u := rbe.NewUser(pp, 1)
	kc.RegisterUser(1, u.PublicKey(), u.Xi())

	return &KeyCuratorServer{
		pp:   pp,
		kc:   kc,
		user: u,
	}
}

func (kcs *KeyCuratorServer) FetchPublicParams(_ context.Context, in *emptypb.Empty) (*pb.PublicParamsResponse, error) {
	return &pb.PublicParamsResponse{Pp: kcs.pp.ToProto()}, nil
}

// server creates a user with id:1 for testing
// alice sends an encrypted message to the server to Decrypt()
// alice encrypts the message with id:1
func (kcs *KeyCuratorServer) Decrypt(_ context.Context, in *pb.DecryptRequest) (*emptypb.Empty, error) {
	id := int(in.GetId())
	ctProto := in.GetCiphertext()

	ciphertext := new(rbe.Ciphertext)
	ciphertext.FromoProto(ctProto)

	coms := kcs.kc.PP.Commitments
	opening := kcs.kc.UserOpenings[id]
	kcs.user.Update(coms, opening)

	plain, err := kcs.user.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("decrypt failed: %v", err)
	}
	log.Infof("plaintext: %v\n", plain)

	return &emptypb.Empty{}, nil
}

func (kcs *KeyCuratorServer) FetchUpdate(_ context.Context, in *pb.UpdateRequest) (*pb.UpdateResponse, error) {
	id := int(in.GetId())

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	return &pb.UpdateResponse{Opening: opening, Commitments: commitments}, nil
}

func (kcs *KeyCuratorServer) RegisterUser(_ context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	id := int(in.GetId())
	publicKey := new(bls.G1)
	publicKey.SetBytes(in.GetPublicKey().GetPoint())

	xi := make([]*bls.G1, len(in.GetXi()))
	for i, v := range in.GetXi() {
		xg1 := new(bls.G1)
		xg1.SetBytes(v.GetPoint())
		xi[i] = xg1
	}

	kcs.kc.RegisterUser(id, publicKey, xi)

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	return &pb.RegisterResponse{Opening: opening, Commitments: commitments}, nil
}

// Register registers a GRPC server on the specified port.
func (s *KeyCuratorServer) Register(grpcServer *grpc.Server) {
	pb.RegisterKeyCuratorServer(grpcServer, s)
}

func main() {

	addr := "localhost:16000"
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterKeyCuratorServer(s, &KeyCuratorServer{})

	log.Infof("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
