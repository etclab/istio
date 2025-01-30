package keycurator

import (
	"context"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/rbe/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
)

type RegistrationEvent struct {
	token     string
	ip        string
	port      string
	id        int
	publicKey *bls.G1
	xi        []*bls.G1
}

type KeyCuratorServer struct {
	pb.UnimplementedKeyCuratorServer
	kc *rbe.KeyCurator
	pp *rbe.PublicParams

	history []*RegistrationEvent

	// todo: see how authenticators are used
	Authenticators []security.Authenticator
}

func NewKeyCuratorServer(maxUsers int) *KeyCuratorServer {
	pp := rbe.NewPublicParams(maxUsers)
	kc := rbe.NewKeyCurator(pp)
	history := make([]*RegistrationEvent, 0)

	return &KeyCuratorServer{
		pp:      pp,
		kc:      kc,
		history: history,
	}
}

func (kcs *KeyCuratorServer) FetchPublicParams(_ context.Context, in *emptypb.Empty) (*pb.PublicParamsResponse, error) {
	return &pb.PublicParamsResponse{Pp: kcs.pp.ToProto()}, nil
}

func (kcs *KeyCuratorServer) addToHistory(token string, ip string, port string, id int, publicKey *bls.G1, xi []*bls.G1) {
	kcs.history = append(kcs.history, &RegistrationEvent{token, ip, port, id, publicKey, xi})
}

// fetches updates for all users
func (kcs *KeyCuratorServer) FetchAllUpdates(_ context.Context, in *emptypb.Empty) (*pb.AllUpdatesResponse, error) {
	allOpenings := []*pb.Opening{}
	allCommitments := []*proto.G1{}

	for _, v := range kcs.kc.UserOpenings {
		openings := []*proto.G1{}
		for _, u := range v {
			openings = append(openings, &proto.G1{Point: u.Bytes()})
		}
		allOpenings = append(allOpenings, &pb.Opening{Opening: openings})
	}

	for _, v := range kcs.kc.PP.Commitments {
		allCommitments = append(allCommitments, &proto.G1{Point: v.Bytes()})
	}

	// TODO: how would this change on sending proof of membership instead?
	history := []*pb.RegistrationEvent{}
	for _, v := range kcs.history {

		xiProto := make([]*proto.G1, len(v.xi))
		for i, v := range v.xi {
			if v == nil {
				xiProto[i] = nil
			} else {
				xiProto[i] = &proto.G1{Point: v.Bytes()}
			}
		}

		history = append(history, &pb.RegistrationEvent{
			Token:     v.token,
			Ip:        v.ip,
			Port:      v.port,
			Id:        int32(v.id),
			PublicKey: &proto.G1{Point: v.publicKey.Bytes()},
			Xi:        xiProto,
		})
	}

	return &pb.AllUpdatesResponse{
		AllOpenings:    allOpenings,
		AllCommitments: allCommitments,
		History:        history,
	}, nil
}

func (kcs *KeyCuratorServer) FetchUpdate(_ context.Context, in *pb.UpdateRequest) (*pb.UserOpeningResponse, error) {
	id := int(in.GetId())

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments}, nil
}

func (kcs *KeyCuratorServer) RegisterUser(_ context.Context, in *pb.RegisterRequest) (*pb.UserOpeningResponse, error) {
	log.Infof("[dev] received register request for user with id: %d", in.GetId())
	// log.Infof("[dev] the register request %v", in)

	id := int(in.GetId())
	publicKey := new(bls.G1)
	publicKey.SetBytes(in.GetPublicKey().GetPoint())

	// log.Infof("[dev] public key %v", publicKey)

	xi := make([]*bls.G1, len(in.GetXi()))
	for i, v := range in.GetXi() {
		if len(v.GetPoint()) == 0 {
			xi[i] = nil
		} else {
			xg1 := new(bls.G1)
			xg1.SetBytes(v.GetPoint())
			xi[i] = xg1
		}
	}

	// log.Infof("[dev] xi values %v", xi)

	kcs.kc.RegisterUser(id, publicKey, xi)
	kcs.addToHistory(in.Token, in.Ip, in.Port, int(in.Id), publicKey, xi)

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments}, nil
}

// Register registers a GRPC server on the specified port.
func (s *KeyCuratorServer) Register(grpcServer *grpc.Server) {
	pb.RegisterKeyCuratorServer(grpcServer, s)
}
