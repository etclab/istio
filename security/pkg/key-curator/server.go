package keycurator

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/rbe/proto"
	"github.com/etclab/trinc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	etcdutil "istio.io/istio/security/pkg/etcd/util"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	clientv3 "go.etcd.io/etcd/client/v3"
	gproto "google.golang.org/protobuf/proto"
	kconstants "istio.io/istio/security/pkg/key-curator/constants"
)

// for lack of a better name using the prefix "history"
// the idea is as new services register themselves with the key curator server
// they get added under this prefix in etcd
// client then watch for new updates under this prefix
// key format: history/<hash-of-token>
// value: serialized(token,id,IP,pk,registration_proof,attest_counter)
const HISTORY = "history"

type RegistrationEvent struct {
	// TODO: remove these fileds as "request" already has them
	token     string
	ip        string
	port      string
	id        int
	publicKey *bls.G1
	xi        []*bls.G1

	request *pb.RegisterRequest

	source string // either api or etcd

	counterAttestation *trinc.CounterAttestation
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

	// leaseId is also my pod id
	leaseId     string
	leaderPodId atomic.Value // string
	isLeader    atomic.Bool

	registrationResponse map[int]*pb.UserOpeningResponse

	history       []*RegistrationEvent
	EtcdClient    *clientv3.Client
	registeredIds map[int]bool                      // used to track registered user ids
	attestations  map[int]*trinc.CounterAttestation // track attestations for each id

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
	ppRes, err := kcs.EtcdClient.Get(context.Background(), kconstants.RBE_PP_KEY, clientv3.WithPrefix())
	if err != nil {
		log.Errorf("[dev] failed to fetch public params from etcd: %v", err)
		return
	}

	log.Infof("[dev] fetched %d public params from etcd", len(ppRes.Kvs))

	if len(ppRes.Kvs) > 0 {
		pp := new(rbe.PublicParams)

		for _, kv := range ppRes.Kvs {
			value := kv.Value
			key := kv.Key
			keyStr := string(key)

			log.Infof("[dev] received key: %s, len(value): %d", key, len(value))

			// check if key is for public params
			if keyStr == kconstants.RBE_PP_KEY {
				ppProto := &proto.PublicParams{}
				err := gproto.Unmarshal([]byte(value), ppProto)
				if err != nil {
					log.Errorf("[dev] failed to unmarshal public params from etcd: %v", err)
					return
				}

				ppCopy := new(rbe.PublicParams)
				ppCopy.FromProto(ppProto)

				pp.MaxUsers = ppCopy.MaxUsers
				pp.BlockSize = ppCopy.BlockSize
				pp.NumBlocks = ppCopy.NumBlocks
				pp.G1 = ppCopy.G1
				pp.G2 = ppCopy.G2

				log.Infof("[dev] saved public params from etcd")
			}

			if keyStr == kconstants.RBE_PP_CRS_H1_KEY {
				crsH1Proto := &pb.H1{}
				err := gproto.Unmarshal([]byte(value), crsH1Proto)
				if err != nil {
					log.Errorf("[dev] failed to unmarshal crsH1 from etcd: %v", err)
					return
				}

				size := len(crsH1Proto.H1)
				h1 := make([]*bls.G1, size)

				for i, v := range crsH1Proto.GetH1() {
					if len(v.GetPoint()) == 0 {
						h1[i] = nil
					} else {
						h1[i] = new(bls.G1)
						err := h1[i].SetBytes(v.GetPoint())
						if err != nil {
							log.Errorf("error setting crs.H1[%d]: %v", i, err)
						}
					}
				}

				if pp.CRS == nil {
					pp.CRS = new(rbe.CRS)
				}
				pp.CRS.H1 = h1
			}

			if keyStr == kconstants.RBE_PP_CRS_H2_KEY {
				crsH2Proto := &pb.H2{}
				err := gproto.Unmarshal([]byte(value), crsH2Proto)
				if err != nil {
					log.Errorf("[dev] failed to unmarshal crsH2 from etcd: %v", err)
					return
				}

				size := len(crsH2Proto.H2)
				h2 := make([]*bls.G2, size)

				for i, v := range crsH2Proto.GetH2() {
					if len(v.GetPoint()) == 0 {
						h2[i] = nil
					} else {
						h2[i] = new(bls.G2)
						err := h2[i].SetBytes(v.GetPoint())
						if err != nil {
							log.Errorf("error setting crs.H2[%d]: %v", i, err)
						}
					}
				}

				if pp.CRS == nil {
					pp.CRS = new(rbe.CRS)
				}
				pp.CRS.H2 = h2
			}

			if keyStr == kconstants.RBE_PP_COMMITMENTS_KEY {
				commitmentsProto := &pb.Commitments{}
				err := gproto.Unmarshal([]byte(value), commitmentsProto)
				if err != nil {
					log.Errorf("[dev] failed to unmarshal commitments from etcd: %v", err)
					return
				}

				commitments := make([]*bls.G1, len(commitmentsProto.Commitments))
				for i, v := range commitmentsProto.GetCommitments() {
					commitments[i] = new(bls.G1)
					err = commitments[i].SetBytes(v.GetPoint())
					if err != nil {
						log.Errorf("error setting commitments[%d]: %v", i, err)
					}
				}

				pp.Commitments = commitments
			}
		}

		kcs.pp = pp
		kcs.kc = rbe.NewKeyCurator(kcs.pp) // reinitialize KeyCurator with restored public params
		log.Infof("[dev] restored public params from etcd")
	} else {
		log.Infof("[dev] no public params found in etcd, storing current public params")
		_, err := etcdutil.SavePublicParamsToEtcd(kcs.EtcdClient, kcs.pp, false)
		if err != nil {
			log.Errorf("[dev] failed to store public params in etcd: %v", err)
			return
		}
	}
}

func (kcs *KeyCuratorServer) fetchExistingUsers() int64 {
	getRes, err := kcs.EtcdClient.Get(context.Background(), kconstants.RBE_USER_PREFIX, clientv3.WithPrefix())
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
	rch := kcs.EtcdClient.Watch(context.Background(), kconstants.RBE_USER_PREFIX, clientv3.WithPrefix(), clientv3.WithRev(currentRevision+1))
	for wresp := range rch {
		if wresp.Canceled {
			log.Warnf("[dev] etcd watch canceled: %v", wresp.Err())
			return
		}

		log.Infof("[dev] etcd watch response count: %d", len(wresp.Events))
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

	key := fmt.Sprintf("%s/%d", kconstants.RBE_USER_PREFIX, id)
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

func NewKeyCuratorServer(maxUsers int, podName string) *KeyCuratorServer {
	pp := rbe.NewPublicParams(maxUsers)
	kc := rbe.NewKeyCurator(pp)
	history := make([]*RegistrationEvent, 0)
	registeredIds := make(map[int]bool)
	attestations := make(map[int]*trinc.CounterAttestation)

	log.Infof("[dev] inside NewKeyCuratorServer with maxUsers: %d, podName: %s", maxUsers, podName)

	kcServer := &KeyCuratorServer{
		pp:            pp,
		kc:            kc,
		history:       history,
		registeredIds: registeredIds,
		attestations:  attestations,

		registrationQueue: make(chan UserRequest, 100),
		// pod id of istiod instance
		leaseId: podName,
	}

	go kcServer.TryAcquireLease(kcServer.leaseId)

	go kcServer.initEtcdWithRetry()

	return kcServer
}

func (kcs *KeyCuratorServer) TryAcquireLease(id string) {
	clientset, err := keycurator.GetKubeClient()
	if err != nil {
		log.Errorf("[dev] failed to get kube client: %v", err)
		return
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      "istiod-key-curator-leader",
			Namespace: "istio-system",
		},
		Client: clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	leaderelection.RunOrDie(context.Background(), leaderelection.LeaderElectionConfig{
		Lock: lock,
		// IMPORTANT: you MUST ensure that any code you have that
		// is protected by the lease must terminate **before**
		// you call cancel. Otherwise, you could have a background
		// loop still running and another process could
		// get elected before your background loop finished, violating
		// the stated goal of the lease.
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				log.Infof("[dev] acquired lease: %s", id)
				kcs.isLeader.Store(true)
			},
			OnStoppedLeading: func() {
				log.Infof("[dev] lost lease: %s", id)
				kcs.isLeader.Store(false)
			},
			OnNewLeader: func(leaderIdentity string) {
				log.Infof("[dev] new leader elected with id: %s", leaderIdentity)
				kcs.leaderPodId.Store(leaderIdentity)
			},
		},
	})
}

func (kcs *KeyCuratorServer) FetchPublicParams(_ context.Context, in *emptypb.Empty) (*pb.PublicParamsResponse, error) {
	return &pb.PublicParamsResponse{Pp: kcs.pp.ToProto()}, nil
}

// how does history change when multiple istiod instances are running?
func (kcs *KeyCuratorServer) addToHistory(token string, ip string, port string,
	id int, publicKey *bls.G1, xi []*bls.G1, in *pb.RegisterRequest, source string,
	counterAttestation *trinc.CounterAttestation) {
	kcs.history = append(kcs.history,
		&RegistrationEvent{token, ip, port, id, publicKey, xi, in, source,
			counterAttestation})
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

		id := int(v.request.Id)
		proof := kcs.kc.ProveMembership(id)
		pbProof := &proto.G1{Point: proof.Bytes()}

		history = append(history, &pb.RegistrationEvent{
			Token:     v.token,
			Ip:        v.ip,
			Port:      v.port,
			Id:        int64(v.id),
			PublicKey: &proto.G1{Point: v.publicKey.Bytes()},
			Xi:        xiProto,
			Request:   v.request,
			Proof:     pbProof,
			// CounterAttestation: counterAttestationToProto(v.counterAttestation),
			CounterAttestation: nil,
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

	// attestationProto := counterAttestationToProto(kcs.attestations[id])

	// return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments,
	// 	CounterAttestation: attestationProto}, nil
	return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments,
		CounterAttestation: nil}, nil
}

func counterAttestationToProto(counterAttestation *trinc.CounterAttestation) *pb.CounterAttestation {
	attestationProto := &pb.CounterAttestation{
		Counter: counterAttestation.Counter,
		MsgHash: counterAttestation.MsgHash,
		Signature: &pb.ECDSASignature{
			R: counterAttestation.Signature.R.Bytes(),
			S: counterAttestation.Signature.S.Bytes(),
		},
	}
	return attestationProto
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

	_, err := gproto.Marshal(in)
	if err != nil {
		log.Errorf("[dev] error marshalling register request: %v", err)
	}
	// counterAttestation, err := trincutil.DoAttestCounter(regMsg)
	// if err != nil {
	// 	log.Errorf("[dev] error generating counter attestation: %v", err)
	// }
	// kcs.attestations[id] = counterAttestation
	// log.Infof("[dev] counter attestation: %v", counterAttestation)

	kcs.kc.RegisterUser(id, publicKey, xi)
	// kcs.addToHistory(in.Token, in.Ip, in.Port, int(in.Id), publicKey, xi, in,
	// 	source, counterAttestation)
	kcs.addToHistory(in.Token, in.Ip, in.Port, int(in.Id), publicKey, xi, in,
		source, nil)

	opening := []*proto.G1{}
	for _, v := range kcs.kc.UserOpenings[id] {
		opening = append(opening, &proto.G1{Point: v.Bytes()})
	}

	commitments := []*proto.G1{}
	for _, v := range kcs.kc.PP.Commitments {
		commitments = append(commitments, &proto.G1{Point: v.Bytes()})
	}

	// attestationProto := counterAttestationToProto(counterAttestation)

	kcs.registeredIds[id] = true
	if source == "api" {
		// only send to etcd if registering a new user via API
		// this means only this instance of istiod received this request
		// so we need to sent it to etcd so that other instances can pick it up
		kcs.StoreAtEtcd(id, in)
		// save to history also stores the user info in etcd
		kcs.SaveToHistory(id, in)
	}
	// send updates on every registration
	if kcs.isLeader.Load() {
		log.Infof("[dev] I'm the leader, updating system params in etcd")
		kcs.UpdateSystemParamsInEtcd()
	} else {
		log.Infof("[dev] skip updating system params in etcd, not the leader")
	}

	proof := kcs.kc.ProveMembership(id)
	pbProof := &proto.G1{Point: proof.Bytes()}

	// return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments,
	// 	CounterAttestation: attestationProto, Proof: pbProof}, nil
	return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments,
		CounterAttestation: nil, Proof: pbProof}, nil
}

func (kcs *KeyCuratorServer) UpdateSystemParamsInEtcd() {
	// serialize pp and store it in etcd
	rev, err := etcdutil.SavePublicParamsToEtcd(kcs.EtcdClient, kcs.pp, true)
	if err != nil {
		log.Errorf("[dev] failed to store public params in etcd: %v", err)
		return
	}

	// serialize user openings and store it in etcd under the new commitments' revision
	openings := kcs.kc.UserOpenings
	err = etcdutil.SaveUserOpeningsToEtcd(kcs.EtcdClient, kcs.registeredIds, openings, rev)
	if err != nil {
		log.Errorf("[dev] failed to store user openings in etcd: %v", err)
		return
	}
}

func (kcs *KeyCuratorServer) SaveToHistory(id int, req *pb.RegisterRequest) {
	// TODO: store user into etcd history
	log.Infof("[dev] stored user %d in etcd", id)
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
