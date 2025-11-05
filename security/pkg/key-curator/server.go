package keycurator

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/rbe/proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"

	clientv3 "go.etcd.io/etcd/client/v3"
	gproto "google.golang.org/protobuf/proto"
)

const RBE_USER_PREFIX = "rbe-user"
const RBE_PP_KEY = "rbe-system/pp"

type RegistrationEvent struct {
	token     string
	ip        string
	port      string
	id        int
	publicKey *bls.G1
	xi        []*bls.G1

	source string // either api or etcd
}

// TODO: rename this to something more meaningful
type UserRequest struct {
	id     int
	req    *pb.RegisterRequest
	source string

	respChan chan *pb.UserOpeningResponse
}

type KeyCuratorServer struct {
	pb.UnimplementedKeyCuratorServer
	kc *rbe.KeyCurator
	pp *rbe.PublicParams

	history              []*RegistrationEvent
	EtcdClient           *clientv3.Client
	registeredIds        map[int]bool // used to track registered user ids
	registrationResponse map[int]*pb.UserOpeningResponse

	registrationQueue chan UserRequest

	// todo: see how authenticators are used
	Authenticators []security.Authenticator
}

func (kcs *KeyCuratorServer) ListWatchRBEUsers() {
	currentRevision := kcs.fetchExistingUsers()
	if currentRevision < 0 {
		log.Errorf("Failed to fetch existing users, cannot start watch")
		return
	} else {
		log.Infof("[dev] current revision is %d", currentRevision)
	}

	go kcs.watchEtcdKeys(currentRevision)
}

func (kcs *KeyCuratorServer) initEtcdWithRetry() {
	backoff := 5 * time.Second
	maxBackoff := 2 * time.Minute
	maxAttempts := 20
	attempts := 0

	for {
		attempts++
		err := kcs.tryConnectToEtcd()
		if err == nil {
			log.Infof("[dev] Successfully connected to etcd after %d attempts", attempts)

			// Restore system params if any exist
			kcs.restoreSystemParams()

			kcs.listenRegistrationRequests()

			// get existing RBE users and then start watching for new users
			kcs.ListWatchRBEUsers()
			return
		}

		log.Warnf("[dev] Failed to connect to etcd (attempt %d): %v", attempts, err)

		if maxAttempts > 0 && attempts >= maxAttempts {
			log.Errorf("[dev] Max connection attempts reached. Giving up on etcd connection")
			return
		}

		// Sleep with exponential backoff, capped at maxBackoff
		time.Sleep(backoff)
		backoff = time.Duration(math.Min(float64(backoff*2), float64(maxBackoff)))
	}
}

// if there's existing public params in etcd, restore them
// if not update the public params in etcd with the current ones
func (kcs *KeyCuratorServer) restoreSystemParams() {
	ppRes, err := kcs.EtcdClient.Get(context.Background(), RBE_PP_KEY)
	if err != nil {
		log.Errorf("[dev] failed to fetch public params from etcd: %v", err)
		return
	}

	log.Infof("[dev] fetched %d public params from etcd", len(ppRes.Kvs))

	if len(ppRes.Kvs) > 0 {
		log.Infof("[dev] found public params in etcd, restoring them")

		record := ppRes.Kvs[0]
		ppValue := record.Value

		ppProto := &proto.PublicParams{}
		err := gproto.Unmarshal([]byte(ppValue), ppProto)
		if err != nil {
			log.Errorf("[dev] failed to unmarshal public params from etcd: %v", err)
			return
		}

		kcs.pp.FromProto(ppProto)
		kcs.kc = rbe.NewKeyCurator(kcs.pp) // reinitialize KeyCurator with restored public params
		log.Infof("[dev] restored public params from etcd")
	} else {
		log.Infof("[dev] no public params found in etcd, storing current public params")
		pp := kcs.pp.ToProto()
		ppValue, err := gproto.Marshal(pp)
		if err != nil {
			log.Errorf("[dev] failed to marshal public params: %v", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = kcs.EtcdClient.Put(ctx, RBE_PP_KEY, string(ppValue))
		if err != nil {
			log.Errorf("[dev] failed to store public params in etcd: %v", err)
			return
		}

		log.Infof("[dev] stored current public params in etcd")
	}
}

func (kcs *KeyCuratorServer) fetchExistingUsers() int64 {
	getRes, err := kcs.EtcdClient.Get(context.Background(), RBE_USER_PREFIX, clientv3.WithPrefix())
	if err != nil {
		log.Errorf("[dev] failed to fetch existing users from etcd: %v", err)
		return -1
	}

	log.Infof("[dev] fetched %d existing users from etcd", len(getRes.Kvs))
	for _, kv := range getRes.Kvs {
		value := kv.Value

		req := &pb.RegisterRequest{}
		err := gproto.Unmarshal([]byte(value), req)
		if err == nil {
			id := int(req.Id)
			userReq := UserRequest{
				id:       id,
				req:      req,
				source:   "etcd",
				respChan: make(chan *pb.UserOpeningResponse, 1),
			}

			kcs.registrationQueue <- userReq

			resp := <-userReq.respChan // wait for the response
			close(userReq.respChan)
			// ignore the response for now
			if resp == nil {
				log.Errorf("[dev] error registering user %d from etcd: %v", id, err)
			} else {
				log.Infof("[dev] registered user %d from etcd", id)
			}
		} else {
			log.Infof("[dev] error unmarshalling request for user %d: %v", kv.Key, err)
		}
	}

	log.Infof("current revision is %d", getRes.Header.Revision)
	return getRes.Header.Revision
}

func (kcs *KeyCuratorServer) tryConnectToEtcd() error {
	etcdClient, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"etcd.istio-system.svc:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("[dev] failed to create etcd client: %w", err)
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = etcdClient.Status(ctx, etcdClient.Endpoints()[0])
	if err != nil {
		etcdClient.Close()
		return fmt.Errorf("[dev] etcd server unreachable: %w", err)
	}

	kcs.EtcdClient = etcdClient
	log.Infof("[dev] Connected to etcd: %v", etcdClient.Endpoints())
	return nil
}

func (kcs *KeyCuratorServer) watchEtcdKeys(currentRevision int64) {
	rch := kcs.EtcdClient.Watch(context.Background(), RBE_USER_PREFIX, clientv3.WithPrefix(), clientv3.WithRev(currentRevision+1))
	for wresp := range rch {
		if wresp.Canceled {
			log.Warnf("[dev] etcd watch canceled: %v", wresp.Err())
			return
		}

		log.Infof("[dev] etcd watch response: %+v", wresp)
		for _, ev := range wresp.Events {
			log.Infof("[dev] type: %s, key: %q\n", ev.Type, ev.Kv.Key)

			if ev.Type == clientv3.EventTypePut {
				// key is of form: "rbe-user/13610"
				key := string(ev.Kv.Key)
				value := ev.Kv.Value

				parts := strings.Split(key, "/")
				if len(parts) == 2 {
					id, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Warnf("[dev] error parsing user id: %d, %v", id, err)
						continue
					}

					_, registered := kcs.registeredIds[id]
					if registered {
						log.Infof("[dev] user with id %d is already registered, skipping", id)
					} else {
						// finally add user to your id space
						req := &pb.RegisterRequest{}
						err := gproto.Unmarshal([]byte(value), req)
						if err == nil {
							userReq := UserRequest{
								id:       id,
								req:      req,
								source:   "etcd",
								respChan: make(chan *pb.UserOpeningResponse, 1),
							}

							kcs.registrationQueue <- userReq

							resp := <-userReq.respChan // wait for the response
							close(userReq.respChan)
							// ignore the response for now
							if resp == nil {
								log.Errorf("[dev] error registering user %d from etcd: %v", id, err)
							} else {
								log.Infof("[dev] registered user %d from etcd", id)
							}
						} else {
							log.Infof("[dev] error unmarshalling request for user %d: %v", id, err)
						}
					}
				}
			}
		}
	}
}

func (kcs *KeyCuratorServer) listenRegistrationRequests() {
	go func() {
		for request := range kcs.registrationQueue {
			_, registered := kcs.registeredIds[request.id]
			if registered {
				log.Infof("[dev] user with id %d is already registered, skipping", request.id)
				continue
			}

			// Process the registration request (one at a time)
			result, err := kcs.registerUserUtil(request.id, request.req, request.source)
			if err != nil {
				log.Errorf("[dev] error processing registration request for user %d: %v", request.id, err)
				continue
			}

			// send a response back
			if request.respChan != nil {
				request.respChan <- result
			}
		}
	}()
}

// StoreAtEtcd sends request to etcd server to store the user id and the
// exact user request
func (kcs *KeyCuratorServer) StoreAtEtcd(id int, req *pb.RegisterRequest) {
	if kcs.EtcdClient == nil {
		log.Warnf("[dev] etcd client is not initialized, cannot store user")
		return
	}

	key := fmt.Sprintf("%s/%d", RBE_USER_PREFIX, id)
	value, err := gproto.Marshal(req)
	if err != nil {
		log.Errorf("[dev] failed to marshal request for user %d: %v", id, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = kcs.EtcdClient.Put(ctx, key, string(value))
	if err != nil {
		log.Errorf("[dev] failed to store user in etcd: %v", err)
		return
	}

	log.Infof("[dev] stored user %d in etcd", id)
}

func NewKeyCuratorServer(maxUsers int) *KeyCuratorServer {
	pp := rbe.NewPublicParams(maxUsers)
	kc := rbe.NewKeyCurator(pp)
	history := make([]*RegistrationEvent, 0)
	registeredIds := make(map[int]bool)

	kcServer := &KeyCuratorServer{
		pp:            pp,
		kc:            kc,
		history:       history,
		registeredIds: registeredIds,

		registrationQueue: make(chan UserRequest, 100),
	}

	go kcServer.initEtcdWithRetry()

	return kcServer
}

func (kcs *KeyCuratorServer) FetchPublicParams(_ context.Context, in *emptypb.Empty) (*pb.PublicParamsResponse, error) {
	return &pb.PublicParamsResponse{Pp: kcs.pp.ToProto()}, nil
}

// how does history change when multiple istiod instances are running?
func (kcs *KeyCuratorServer) addToHistory(token string, ip string, port string,
	id int, publicKey *bls.G1, xi []*bls.G1, source string) {
	kcs.history = append(kcs.history,
		&RegistrationEvent{token, ip, port, id, publicKey, xi, source})
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
			Id:        int64(v.id),
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

func (kcs *KeyCuratorServer) registerUserUtil(id int, in *pb.RegisterRequest,
	source string) (*pb.UserOpeningResponse, error) {
	publicKey := new(bls.G1)
	publicKey.SetBytes(in.GetPublicKey().GetPoint())

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

	kcs.kc.RegisterUser(id, publicKey, xi)
	kcs.addToHistory(in.Token, in.Ip, in.Port, int(in.Id), publicKey, xi, source)

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	kcs.registeredIds[id] = true
	if source == "api" {
		// only send to etcd if registering a new user via API
		// this means only this instance of istiod received this request
		// so we need to sent it to etcd so that other instances can pick it up
		kcs.StoreAtEtcd(id, in)
	}

	return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments}, nil
}

func (kcs *KeyCuratorServer) RegisterUser(_ context.Context, in *pb.RegisterRequest) (*pb.UserOpeningResponse, error) {
	log.Infof("[dev] received register request for user with id: %d", in.GetId())

	id := int(in.GetId())
	// rethink the check for registered user ids
	_, registered := kcs.registeredIds[id]
	if registered {
		log.Warnf("[dev] user with id %d is already registered, returning cached response", id)
		// return &pb.UserOpeningResponse{
		// 	Opening:     []*proto.G1{},
		// 	Commitments: []*proto.G1{},
		// }, fmt.Errorf("user with id %d is already registered", id)
		return kcs.registrationResponse[id], nil
	}

	userReq := UserRequest{
		id:       id,
		req:      in,
		source:   "api",
		respChan: make(chan *pb.UserOpeningResponse, 1),
	}

	kcs.registrationQueue <- userReq

	userOpeningResp := <-userReq.respChan // wait for the response
	close(userReq.respChan)
	if userOpeningResp == nil {
		errMsg := fmt.Errorf("[dev] error registering user %d from api", id)
		log.Errorf(errMsg.Error())
		return nil, errMsg
	} else {
		if kcs.registrationResponse == nil {
			kcs.registrationResponse = make(map[int]*pb.UserOpeningResponse)
		}
		log.Infof("[dev] caching registration response for user %d", id)
		kcs.registrationResponse[id] = userOpeningResp
	}
	log.Infof("[dev] registered user %d from api", id)

	return userOpeningResp, nil
}

// Register registers a GRPC server on the specified port.
func (s *KeyCuratorServer) Register(grpcServer *grpc.Server) {
	pb.RegisterKeyCuratorServer(grpcServer, s)
}
