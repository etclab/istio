package keycurator

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
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
	trincutil "istio.io/istio/security/pkg/trinc/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	clientv3 "go.etcd.io/etcd/client/v3"
	gproto "google.golang.org/protobuf/proto"
	kconstants "istio.io/istio/security/pkg/key-curator/constants"
	kceval "istio.io/istio/security/pkg/key-curator/eval"
	kcUtil "istio.io/istio/security/pkg/key-curator/util"
)

// for lack of a better name using the prefix "history"
// the idea is as new services register themselves with the key curator server
// they get added under this prefix in etcd
// client then watch for new updates under this prefix
// key format: history/<hash-of-token>
// value: serialized(token,id,IP,pk,registration_proof,attest_counter)
const HISTORY = "history"

type RegistrationEvent struct {
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
	id           int
	req          *pb.RegisterRequest
	source       string
	registerTime int64

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

	history              []*RegistrationEvent
	EtcdClient           *clientv3.Client
	registeredIds        map[int]bool                      // used to track registered user ids
	attestations         map[int]*trinc.CounterAttestation // track attestations for each id
	registrationResponse map[int]*pb.UserOpeningResponse

	registrationQueue chan UserRequest

	// todo: see how authenticators are used
	Authenticators []security.Authenticator

	logWriter *kceval.MLogWriter

	amIReady atomic.Bool

	subscribersMu sync.RWMutex
	subscribers   map[int64]*subscriber // keyed by subscriber's RBE user ID

	// notificationLog is an ordered log of all registration notifications.
	// New subscribers receive unseen entries before switching to live updates.
	notificationLogMu sync.RWMutex
	notificationLog   []*pb.RegistrationNotification

	// subscriberCursors tracks how far each subscriber (by RBE ID) has read
	// into the notificationLog. Persists across reconnects so we don't resend.
	subscriberCursorsMu sync.RWMutex
	subscriberCursors   map[int64]int // rbeId -> index of last sent notification + 1
}

func (kcs *KeyCuratorServer) ListWatchRBEUsers() {
	currentRevision := kcs.fetchExistingUsers()
	if currentRevision < 0 {
		log.Errorf("Failed to fetch existing users, cannot start watch")
		return
	} else {
		log.Infof("[dev] current revision is %d", currentRevision)
	}

	go kcs.watchForNewUsers(currentRevision)
}

func (kcs *KeyCuratorServer) initEtcdWithRetry(wg *sync.WaitGroup) {
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
			// NOTE: do not restore system params from etcd because we're
			// reading it from a file/configmap during startup
			kcs.restoreSystemParams()

			kcs.listenRegistrationRequests()

			// get existing RBE users and then start watching for new users
			kcs.ListWatchRBEUsers()

			wg.Done()
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

// TODO: if I'm not the leader, I should always restore public params from etcd
// if there's existing public params in etcd, restore them
// if not update the public params in etcd with the current ones
func (kcs *KeyCuratorServer) restoreSystemParams() {
	ppRes, err := kcs.EtcdClient.Get(context.Background(), kconstants.RBE_PP_COMMITMENTS_KEY, clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByModRevision, clientv3.SortAscend))
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

			log.Infof("[dev] received key: %s, len(value): %d, modRevision: %d", key, len(value), kv.ModRevision)

			/*
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
			*/

			// Do we not need to handle commitments here anymore?
			// as we discover new users from etcd or API, the commitments get
			// updated accordingly --> unsure if this is true in every case
			if keyStr == kconstants.RBE_PP_COMMITMENTS_KEY {
				// we don't handle commitments as a whole anymore
				// not really necessary if we're not storing them at etcd anyway
				continue
			}

			if strings.HasPrefix(keyStr, kconstants.RBE_PP_COMMITMENTS_KEY) {
				log.Infof("[dev] this is a commitment update for a single block: %s, with size: %d", key, len(value))

				// rbe-system/pp/commitments/27
				parts := strings.Split(keyStr, "/")

				blockIndexStr := parts[3]
				blockIndex, err := strconv.Atoi(blockIndexStr)
				if err != nil {
					log.Errorf("[dev] invalid block index in commitments key: %s", key)
				}

				commitmentsProto := &proto.G1{}
				err = gproto.Unmarshal([]byte(value), commitmentsProto)
				if err != nil {
					log.Errorf("[dev] failed to unmarshal commitments from etcd: %v", err)
				}

				commitment := new(bls.G1)
				err = commitment.SetBytes(commitmentsProto.GetPoint())
				if err != nil {
					log.Errorf("error setting commitment for block %d: %v", blockIndex, err)
				}

				// ordering is preserved here so we can directly set at the index
				if pp.Commitments == nil {
					// reuse the existing commitments
					pp.Commitments = kcs.pp.Commitments
				}
				pp.Commitments[blockIndex] = commitment
			}
		}
		kcs.pp.Commitments = pp.Commitments

		kcs.kc = rbe.NewKeyCurator(kcs.pp) // reinitialize KeyCurator with restored public params
		log.Infof("[dev] restored public params from etcd")
	} else {
		// we don't need to send commitments here as there's a separate mechanism
		// that sends commitments to etcd
		log.Infof("[dev] no commitments found in etcd, skipping")
	}
}

func (kcs *KeyCuratorServer) fetchExistingUsers() int64 {
	getRes, err := kcs.EtcdClient.Get(context.Background(), kconstants.RBE_USER_PREFIX, clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByModRevision, clientv3.SortAscend))
	if err != nil {
		log.Errorf("[dev] failed to fetch existing users from etcd: %v", err)
		return -1
	}

	log.Infof("[dev] fetched %d existing users from etcd", len(getRes.Kvs))
	for _, kv := range getRes.Kvs {
		value := kv.Value

		regUserWithProofReq := &keycurator.RegisteredUserWithProof{}
		err := json.Unmarshal([]byte(value), regUserWithProofReq)
		if err == nil {
			// user request
			regRequestBytes := regUserWithProofReq.RequestBytes

			regRequest := &pb.RegisterRequest{}
			err := gproto.Unmarshal([]byte(regRequestBytes), regRequest)
			if err != nil {
				log.Errorf("[dev] error unmarshalling RegisterRequest for user %d: %v", regRequest.GetId(), err)
				continue
			}

			id := int(regRequest.Id)
			userReq := UserRequest{
				id:       id,
				req:      regRequest,
				source:   "etcd",
				respChan: make(chan *pb.UserOpeningResponse, 1),
			}

			// node agent will verify the proof and counter attestation

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

func (kcs *KeyCuratorServer) watchForNewUsers(currentRevision int64) {
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
						regUserWithProofReq := &keycurator.RegisteredUserWithProof{}
						err := json.Unmarshal([]byte(value), regUserWithProofReq)
						if err == nil {
							// user request
							regRequestBytes := regUserWithProofReq.RequestBytes
							regRequest := &pb.RegisterRequest{}
							err := gproto.Unmarshal([]byte(regRequestBytes), regRequest)
							if err != nil {
								log.Errorf("[dev] error unmarshalling RegisterRequest for user %d: %v", regRequest.GetId(), err)
								continue
							}

							userReq := UserRequest{
								id:       id,
								req:      regRequest,
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
			result, err := kcs.registerUserUtil(request.id, request.req,
				request.source, request.registerTime)
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
func (kcs *KeyCuratorServer) StoreAtEtcd(id int, req *keycurator.RegisteredUserWithProof) {
	if kcs.EtcdClient == nil {
		log.Warnf("[dev] etcd client is not initialized, cannot store user")
		return
	}

	key := fmt.Sprintf("%s/%d", kconstants.RBE_USER_PREFIX, id)
	value, err := json.Marshal(req)
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
	// check if we have existing public params in /var/run/rbe-pp file
	// and we can restore them
	pp, err := keycurator.TryParseRbePpFromFile()
	if err != nil {
		log.Infof("[dev] could not parse RBE public params from file: %v, generating new params", err)
		pp = rbe.NewPublicParams(maxUsers)
	}
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
		leaseId:           podName,
		logWriter:         kceval.NewMLogWriter(""),
		subscribers:       make(map[int64]*subscriber),
		subscriberCursors: make(map[int64]int),
	}

	// channel to receive signals when lease is acquired/ready and when etcd is
	// connected and initial system params have been received
	var wg sync.WaitGroup

	wg.Add(1)
	go kcServer.TryAcquireLease(kcServer.leaseId, &wg)

	wg.Add(1)
	go kcServer.initEtcdWithRetry(&wg)

	wg.Wait()

	kcServer.amIReady.Store(true)
	log.Infof("[dev] KeyCuratorServer is ready")

	return kcServer
}

func (kcs *KeyCuratorServer) TryAcquireLease(id string, wg *sync.WaitGroup) {
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
				// wg.Done()
			},
			OnStoppedLeading: func() {
				log.Infof("[dev] lost lease: %s", id)
				kcs.isLeader.Store(false)
			},
			OnNewLeader: func(leaderIdentity string) {
				log.Infof("[dev] new leader elected with id: %s", leaderIdentity)
				kcs.leaderPodId.Store(leaderIdentity)

				if kcs.amIReady.Load() == false {
					wg.Done()
				}
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
// func (kcs *KeyCuratorServer) FetchAllUpdates(_ context.Context, in *emptypb.Empty) (*pb.AllUpdatesResponse, error) {
// 	allOpenings := []*pb.Opening{}
// 	allCommitments := []*proto.G1{}

// 	for _, v := range kcs.kc.UserOpenings {
// 		openings := []*proto.G1{}
// 		for _, u := range v {
// 			openings = append(openings, &proto.G1{Point: u.Bytes()})
// 		}
// 		allOpenings = append(allOpenings, &pb.Opening{Opening: openings})
// 	}

// 	for _, v := range kcs.kc.PP.Commitments {
// 		allCommitments = append(allCommitments, &proto.G1{Point: v.Bytes()})
// 	}

// 	// TODO: how would this change on sending proof of membership instead?
// 	history := []*pb.RegistrationEvent{}
// 	for _, v := range kcs.history {

// 		xiProto := make([]*proto.G1, len(v.xi))
// 		for i, v := range v.xi {
// 			if v == nil {
// 				xiProto[i] = nil
// 			} else {
// 				xiProto[i] = &proto.G1{Point: v.Bytes()}
// 			}
// 		}

// 	id := int(v.request.Id)
// 	proof := kcs.kc.ProveMembership(id)
// 	pbProof := &proto.G1{Point: proof.Bytes()}

// 	history = append(history, &pb.RegistrationEvent{
// 		Token:              v.token,
// 		Ip:                 v.ip,
// 		Port:               v.port,
// 		Id:                 int64(v.id),
// 		PublicKey:          &proto.G1{Point: v.publicKey.Bytes()},
// 		Xi:                 xiProto,
// 		Request:            v.request,
// 		Proof:              pbProof,
// 		CounterAttestation: counterAttestationToProto(v.counterAttestation),
// 	})
// }

// 	return &pb.AllUpdatesResponse{
// 		AllOpenings:    allOpenings,
// 		AllCommitments: allCommitments,
// 		History:        history,
// 	}, nil
// }

// unused
// func (kcs *KeyCuratorServer) FetchUpdate(_ context.Context, in *pb.UpdateRequest) (*pb.UserOpeningResponse, error) {
// 	id := int(in.GetId())
// 	opening := []*proto.G1{}
// 	for _, v := range kcs.kc.UserOpenings[id] {
// 		opening = append(opening, &proto.G1{Point: v.Bytes()})
// 	}

// 	blockId := kcs.kc.PP.IdToBlock(id)
// 	blockCommitment := &proto.G1{Point: kcs.kc.PP.Commitments[blockId].Bytes()}

// attestationProto := counterAttestationToProto(kcs.attestations[id])

// return &pb.UserOpeningResponse{Opening: opening, Commitments: commitments,
// 	CounterAttestation: attestationProto}, nil

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

func (kcs *KeyCuratorServer) MarkReady(_ context.Context, in *pb.ReadyRequest) (*emptypb.Empty, error) {
	userId := in.GetId()
	log.Infof("[dev] received MarkReady request for user with id: %d", userId)

	eventString := fmt.Sprintf("%s,%d", in.GetPrefix(), time.Now().UnixMicro())
	go func() {
		err := kcs.logWriter.Append(eventString)
		if err != nil {
			log.Errorf("[dev] failed to append READY event for user %d: %v", userId, err)
		}
	}()

	return &emptypb.Empty{}, nil
}

func (kcs *KeyCuratorServer) registerUserUtil(id int, in *pb.RegisterRequest,
	source string, registerTime int64) (*pb.UserOpeningResponse, error) {
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

	var usersBeforeMe []int64
	// for registeredId := range kcs.registeredIds {
	// 	usersBeforeMe = append(usersBeforeMe, int64(registeredId))
	// }

	// usersBeforeMeStringArr := make([]string, len(usersBeforeMe))
	// for i, v := range usersBeforeMe {
	// 	usersBeforeMeStringArr[i] = fmt.Sprintf("%d", v)
	// }

	// usersBeforeMeJoined := strings.Join(usersBeforeMeStringArr, "|")

	// eventString := fmt.Sprintf("REGISTER,%d,%s,%d", in.GetId(),
	// 	usersBeforeMeJoined, registerTime)
	// the wait time a user experienced before registering can be high if many users
	// are registering at the same time
	// usersBeforeMeJoined, time.Now().UnixMicro())
	// go func() {
	// 	err := kcs.logWriter.Append(eventString)
	// 	if err != nil {
	// 		log.Errorf("[dev] failed to append REGISTER event for user %d: %v", in.GetId(), err)
	// 	}
	// }()

	registerStart := time.Now()
	kcs.kc.RegisterUser(id, publicKey, xi)
	log.Infof("[dev] kcs.kc.RegisterUser(%d) took %v", id, time.Since(registerStart))

	//
	isRbeProofEnabled := kcUtil.IsRbeProofEnabled()
	isAttestationEnabled := kcUtil.IsAttestationEnabled()

	var pbProofBytes []byte
	var proof *bls.G1
	var err error
	var pbProof *proto.G1

	if isRbeProofEnabled || isAttestationEnabled {
		log.Infof("[dev] RBE proof generation is enabled")

		proof = kcs.kc.ProveMembership(id)
		pbProof = &proto.G1{Point: proof.Bytes()}
		pbProofBytes, err = gproto.Marshal(pbProof)
		if err != nil {
			log.Errorf("[dev] error marshalling proof: %v", err)
		}
	}

	var regMsg []byte
	regMsg, err = gproto.Marshal(in)
	if err != nil {
		log.Errorf("[dev] error marshalling register request: %v", err)
	}

	// var attestationProtoBytes []byte
	var counterAttestation *trinc.CounterAttestation
	var attestationProto *pb.CounterAttestation

	if isAttestationEnabled {
		log.Infof("[dev] counter attestation generation is enabled")

		attestUserData := append(regMsg, pbProofBytes...)

		counterAttestation, err = trincutil.DoAttestCounter(attestUserData)
		if err != nil {
			log.Errorf("[dev] error generating counter attestation: %v", err)
		}
		kcs.attestations[id] = counterAttestation
		log.Infof("[dev] counter attestation: %v", counterAttestation)

		attestationProto = counterAttestationToProto(counterAttestation)

		// attestationProtoBytes, err = gproto.Marshal(attestationProto)
		_, err = gproto.Marshal(attestationProto)
		if err != nil {
			log.Errorf("[dev] error marshalling counter attestation: %v", err)
		}
	} else {
		log.Infof("[dev] counter attestation generation is disabled")
	}

	// registeredUserWithProof := &keycurator.RegisteredUserWithProof{
	// 	ProofBytes:       pbProofBytes,
	// 	AttestationBytes: attestationProtoBytes,
	// 	RequestBytes:     regMsg,
	// }
	//

	// kcs.addToHistory(in.Token, in.Ip, in.Port, int(in.Id), publicKey, xi, in,
	// 	source, counterAttestation)

	// opening := []*proto.G1{}
	opening := []*proto.G1{}
	// for _, v := range kcs.kc.UserOpenings[id] {
	// 	opening = append(opening, &proto.G1{Point: v.Bytes()})
	// }

	// blockId := kcs.kc.PP.IdToBlock(id)
	// blockCommitment := &proto.G1{Point: kcs.kc.PP.Commitments[blockId].Bytes()}
	blockCommitment := &proto.G1{Point: []byte{}}

	kcs.registeredIds[id] = true
	kcs.notifySubscribers(id, pbProof, attestationProto, regMsg)
	// if source == "api" {
	// 	// only send to etcd if registering a new user via API
	// 	// this means only this instance of istiod received this request
	// 	// so we need to sent it to etcd so that other instances can pick it up
	// 	kcs.StoreAtEtcd(id, registeredUserWithProof)
	// }
	// // send updates on every registration
	// if kcs.isLeader.Load() {
	// 	log.Infof("[dev] I'm the leader, updating system params in etcd")
	// 	kcs.UpdateSystemParamsInEtcd(id)
	// } else {
	// 	log.Infof("[dev] skip updating system params in etcd, not the leader")
	// }

	return &pb.UserOpeningResponse{Opening: opening, Commitment: blockCommitment,
		CounterAttestation: attestationProto, Proof: pbProof, UsersBeforeMe: usersBeforeMe}, nil
}

func (kcs *KeyCuratorServer) UpdateSystemParamsInEtcd(id int) {
	// only need to send commitments for the specific block to which id belongs
	k := kcs.pp.IdToBlock(id)
	commitmentForBlock := kcs.pp.Commitments[k]

	rev, err := etcdutil.SaveCommitmentBlockToEtcd(kcs.EtcdClient, k, commitmentForBlock)
	if err != nil {
		log.Errorf("[dev] failed to store commitment for block %d in etcd: %v", k, err)
		return
	}

	// serialize user openings and store it in etcd under the new commitments' revision
	openings := kcs.kc.UserOpenings
	pp := kcs.kc.PP
	err = etcdutil.SaveUserOpeningsToEtcd(kcs.EtcdClient, id, pp, kcs.registeredIds, openings, rev)
	if err != nil {
		log.Errorf("[dev] failed to store user openings in etcd: %v", err)
		return
	}
}

func (kcs *KeyCuratorServer) RegisterUser(_ context.Context, in *pb.RegisterRequest) (*pb.UserOpeningResponse, error) {
	log.Infof("[dev] received register request for user with id: %d", in.GetId())

	registerTime := time.Now().UnixMicro()

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
		id:           id,
		req:          in,
		source:       "api",
		registerTime: registerTime,
		respChan:     make(chan *pb.UserOpeningResponse, 1),
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

// subscriber represents a connected stream subscriber identified by RBE user ID.
type subscriber struct {
	ch chan *pb.RegistrationNotification
}

func (kcs *KeyCuratorServer) StreamRegistrations(req *pb.StreamRegistrationsRequest, stream pb.KeyCurator_StreamRegistrationsServer) error {
	subId := req.GetSubscriberId()

	// If the request carries a RegisterRequest, process it synchronously before
	// taking the cursor snapshot. This ensures the caller's own registration
	// notification appears in the replay batch.
	if regReq := req.GetRegisterRequest(); regReq != nil {
		id := int(regReq.GetId())
		if _, registered := kcs.registeredIds[id]; !registered {
			userReq := UserRequest{
				id:           id,
				req:          regReq,
				source:       "api",
				registerTime: time.Now().UnixMicro(),
				respChan:     make(chan *pb.UserOpeningResponse, 1),
			}
			kcs.registrationQueue <- userReq
			resp := <-userReq.respChan
			close(userReq.respChan)
			if resp == nil {
				return fmt.Errorf("registration failed for user %d", id)
			}
			log.Infof("[dev] StreamRegistrations: registered user %d before starting stream", id)
		} else {
			log.Infof("[dev] StreamRegistrations: user %d already registered, skipping", id)
		}
	}

	// Determine how far this subscriber has already read, and subscribe atomically.
	// notifySubscribers() holds notificationLogMu(write) while appending and fanning out,
	// so holding notificationLogMu(read) here ensures a notification either appears in
	// the unsent slice OR is delivered to the channel — never both, never neither.
	kcs.notificationLogMu.RLock()

	kcs.subscriberCursorsMu.RLock()
	cursor := kcs.subscriberCursors[subId] // 0 if first time
	kcs.subscriberCursorsMu.RUnlock()

	unsent := kcs.notificationLog[cursor:]
	newCursor := len(kcs.notificationLog)

	kcs.subscribersMu.Lock()
	sub := &subscriber{ch: make(chan *pb.RegistrationNotification, 64)}
	kcs.subscribers[subId] = sub
	kcs.subscribersMu.Unlock()

	kcs.notificationLogMu.RUnlock()

	log.Infof("[dev] StreamRegistrations: subscriber rbeId=%d connected, cursor=%d, replaying %d unsent registrations",
		subId, cursor, len(unsent))

	defer func() {
		kcs.subscribersMu.Lock()
		delete(kcs.subscribers, subId)
		kcs.subscribersMu.Unlock()
		log.Infof("[dev] StreamRegistrations: subscriber rbeId=%d disconnected", subId)
	}()

	// Replay unsent notifications in order.
	for _, notif := range unsent {
		if err := stream.Send(notif); err != nil {
			log.Errorf("[dev] StreamRegistrations: error replaying notification to subscriber rbeId=%d: %v", subId, err)
			return err
		}
	}

	// Update cursor after successful replay.
	kcs.subscriberCursorsMu.Lock()
	kcs.subscriberCursors[subId] = newCursor
	kcs.subscriberCursorsMu.Unlock()

	// Switch to live updates.
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case notif := <-sub.ch:
			if err := stream.Send(notif); err != nil {
				log.Errorf("[dev] StreamRegistrations: error sending notification to subscriber rbeId=%d: %v", subId, err)
				return err
			}
			// Advance cursor on each successful send.
			kcs.subscriberCursorsMu.Lock()
			kcs.subscriberCursors[subId]++
			kcs.subscriberCursorsMu.Unlock()
		}
	}
}

func (kcs *KeyCuratorServer) FetchRegistration(_ context.Context,
	req *pb.FetchRegistrationRequest) (*pb.RegistrationNotification, error) {
	id := req.GetId()

	kcs.notificationLogMu.RLock()
	defer kcs.notificationLogMu.RUnlock()

	for _, notif := range kcs.notificationLog {
		if notif.GetId() == id {
			return notif, nil
		}
	}

	return nil, fmt.Errorf("registration not found for id=%d", id)
}

func (kcs *KeyCuratorServer) notifySubscribers(id int, proof *proto.G1,
	attestation *pb.CounterAttestation, registerRequestBytes []byte) {
	notif := &pb.RegistrationNotification{
		Id:                   int64(id),
		Proof:                proof,
		CounterAttestation:   attestation,
		RegisterRequestBytes: registerRequestBytes,
	}

	// Append to the log and fan out while holding the log lock.
	// StreamRegistrations holds this same lock (read) while snapshotting
	// and subscribing, so a notification either appears in the unsent slice
	// OR is delivered to the channel — never both, never neither.
	kcs.notificationLogMu.Lock()
	kcs.notificationLog = append(kcs.notificationLog, notif)

	kcs.subscribersMu.RLock()
	for _, sub := range kcs.subscribers {
		select {
		case sub.ch <- notif:
		default:
			// drop if subscriber is slow
		}
	}
	kcs.subscribersMu.RUnlock()

	kcs.notificationLogMu.Unlock()
}
