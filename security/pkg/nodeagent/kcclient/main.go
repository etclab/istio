package kcclient

// maybe call this rbeclient?

import (
	"context"
	"fmt"
	"strconv"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"github.com/etclab/trinc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"

	rbeproto "github.com/etclab/rbe/proto"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	"istio.io/istio/security/pkg/nodeagent/caclient"
	trincutil "istio.io/istio/security/pkg/trinc/util"
)

var kcClientLog = log.RegisterScope("kcclient", "key curator client debugging")

const CTR_ATTESTATION_PATH = "/etc/istio/proxy/counter-attestation"

// note: using the same structure as citadel client
type KCClient struct {
	// It means enable tls connection to key curator if this is not nil.
	tlsOpts  *TLSOptions
	client   pb.KeyCuratorClient
	conn     *grpc.ClientConn
	provider credentials.PerRPCCredentials
	opts     *security.Options
}

type TLSOptions struct {
	RootCert string
	Key      string
	Cert     string
}

func (c *KCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *KCClient) getTLSOptions() *istiogrpc.TLSOptions {
	if c.tlsOpts != nil {
		return &istiogrpc.TLSOptions{
			RootCert:      c.tlsOpts.RootCert,
			Key:           c.tlsOpts.Key,
			Cert:          c.tlsOpts.Cert,
			ServerAddress: c.opts.KCEndpoint,
			SAN:           c.opts.KCEndpointSAN,
		}
	}
	return nil
}

func (c *KCClient) buildConnection() (*grpc.ClientConn, error) {
	// handle configs for the grpc server --
	tlsOpts := c.getTLSOptions()
	opts, err := istiogrpc.ClientOptions(nil, tlsOpts)
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		grpc.WithPerRPCCredentials(c.provider),
		security.CARetryInterceptor(),
	)
	conn, err := grpc.Dial(c.opts.KCEndpoint, opts...)
	if err != nil {
		kcClientLog.Errorf("Failed to connect to endpoint %s: %v", c.opts.KCEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", c.opts.KCEndpoint)
	}

	return conn, nil
}

// TODO: if there's an error rebuild the connection -- see how errors are handled in Citadel client
func (c *KCClient) reconnect() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("failed to close connection: %v", err)
	}

	conn, err := c.buildConnection()
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = pb.NewKeyCuratorClient(conn)
	kcClientLog.Info("recreated connection")
	return nil
}

func NewKCClient(opts *security.Options, tlsOpts *TLSOptions) (security.KeyCuratorClient, error) {
	c := &KCClient{
		tlsOpts:  tlsOpts,
		opts:     opts,
		provider: caclient.NewDefaultTokenProvider(opts),
	}

	conn, err := c.buildConnection()
	if err != nil {
		kcClientLog.Errorf("Failed to connect to endpoint %s: %v", opts.KCEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", opts.KCEndpoint)
	}
	c.conn = conn
	c.client = pb.NewKeyCuratorClient(conn)
	return c, nil
}

func (c *KCClient) MarkReady(id int64, prefix string) error {
	req := &pb.ReadyRequest{
		Id:     id,
		Prefix: prefix,
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	_, err := c.client.MarkReady(ctx, req)
	if err != nil {
		return fmt.Errorf("[dev] err on MarkReady(): %v", err)
	}

	return nil
}

// func (c *KCClient) FetchAllUpdates(pp *rbe.PublicParams) ([]*bls.G1, [][]*bls.G1, []*security.RbeId, error) {
// 	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
// 	updResp, err := c.client.FetchAllUpdates(ctx, &emptypb.Empty{})
// 	if err != nil {
// 		log.Errorf("[dev] err on FetchAllUpdates(): %v", err)
// 		return nil, nil, nil, err
// 	}
// 	openings := make([][]*bls.G1, 0)
// 	commitments := make([]*bls.G1, 0)

// 	for _, v := range updResp.GetAllCommitments() {
// 		g1 := new(bls.G1)
// 		g1.SetBytes(v.GetPoint())
// 		commitments = append(commitments, g1)
// 	}

// 	for _, v := range updResp.GetAllOpenings() {
// 		userOpening := make([]*bls.G1, 0)
// 		for _, u := range v.GetOpening() {
// 			g1 := new(bls.G1)
// 			g1.SetBytes(u.GetPoint())
// 			userOpening = append(userOpening, g1)
// 		}
// 		openings = append(openings, userOpening)
// 	}

// pp.Commitments = commitments

// history := updResp.GetHistory() // history is like a append only log
// allRbeIds := make([]*security.RbeId, 0)
// // var prevCounter uint64 = 0
// for _, registrationEvent := range history {
// 	// TODO: make everything string
// 	port, err := strconv.Atoi(registrationEvent.GetPort())
// 	if err != nil {
// 		log.Infof("[dev] err on converting port to int: %v", err)
// 		continue
// 	}

// 	rbeId := &security.RbeId{
// 		Token: registrationEvent.GetToken(),
// 		Ip:    registrationEvent.GetIp(),
// 		Port:  port,
// 	}
// 	allRbeIds = append(allRbeIds, rbeId)

// 	_, err = proto.Marshal(registrationEvent.Request)
// 	if err != nil {
// 		log.Errorf("[dev] error marshalling register request: %v", err)
// 	}

// 	proof := &bls.G1{}
// 	proof.SetBytes(registrationEvent.GetProof().GetPoint())
// 	pubKey := &bls.G1{}
// 	pubKey.SetBytes(registrationEvent.GetPublicKey().GetPoint())

// 	if rbe.VerifyMembership(pp, int(registrationEvent.Id), pubKey, proof) {
// 		log.Infof("[dev] membership verified successfully")
// 	} else {
// 		errMsg := fmt.Sprintf("[dev] membership verification failed for %s:%d", registrationEvent.GetIp(), port)
// 		log.Errorf(errMsg)
// 		return nil, nil, nil, fmt.Errorf("%s", errMsg)
// 	}

// ctrAttestation := trincutil.AttestationFromProto(registrationEvent.CounterAttestation)
// if trincutil.DoVerifyCounter(regMsg, ctrAttestation) && ctrAttestation.Counter > prevCounter {
// 	log.Infof("[dev] attestation verified successfully")
// 	prevCounter = ctrAttestation.Counter
// } else {
// 	log.Errorf("[dev] failure: attestation has an invalid signature")
// 	return nil, nil, nil, fmt.Errorf("[dev] attestation has an invalid signature")
// }
// save the index upto which last successful verification was done
// save the counter upto which last successful verification was don
// save the index upto which the registration history was fetched
// }
// 	return commitments, openings, allRbeIds, nil
// }

// func (c *KCClient) FetchUpdate(id int64) ([]*bls.G1, []*bls.G1, *bls.G1, error) {
// 	updReq := &pb.UpdateRequest{
// 		Id: id,
// 	}

// 	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
// 	updResp, err := c.client.FetchUpdate(ctx, updReq)
// 	if err != nil {
// 		log.Errorf("[dev] err on FetchUpdate(): %v", err)
// 		return nil, nil, nil, err
// 	}

// 	commitments, opening, _, proof := parseUserRegistrationResponse(updResp)

// 	return commitments, opening, proof, nil
// }

func parseUserRegistrationResponse(uoResp *pb.UserOpeningResponse) (*bls.G1,
	[]*bls.G1, *trinc.CounterAttestation, *bls.G1) {

	commitment := &bls.G1{}
	commitment.SetBytes(uoResp.GetCommitment().GetPoint())

	opening := []*bls.G1{}
	for _, v := range uoResp.GetOpening() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		opening = append(opening, g1)
	}

	attestation := new(trinc.CounterAttestation)
	if uoResp.GetCounterAttestation() != nil {
		attestation = trincutil.AttestationFromProto(uoResp.GetCounterAttestation())
	}

	proof := &bls.G1{}
	proof.SetBytes(uoResp.GetProof().GetPoint())

	return commitment, opening, attestation, proof
}

// BuildRegisterRequest constructs a RegisterRequest proto from an rbe.User and
// RbeId. This can be used both by RegisterUser (direct RPC) and by
// StreamRegistrations (inline registration).
func BuildRegisterRequest(user *rbe.User, rbeId *security.RbeId) *pb.RegisterRequest {
	xi := user.Xi()
	xiProto := make([]*rbeproto.G1, len(xi))
	for i, v := range xi {
		if v == nil {
			xiProto[i] = nil
		} else {
			xiProto[i] = &rbeproto.G1{Point: v.Bytes()}
		}
	}
	return &pb.RegisterRequest{
		Id:        rbeId.ToNumber(),
		PublicKey: &rbeproto.G1{Point: user.PublicKey().Bytes()},
		Xi:        xiProto,
		Ip:        rbeId.Ip,
		Port:      strconv.Itoa(rbeId.Port),
		Token:     rbeId.Token,
	}
}

// return values: commitments, opening, user-ids-before-me, error
func (c *KCClient) RegisterUser(user *rbe.User, rbeId *security.RbeId) (*bls.G1,
	[]*bls.G1, *bls.G1, []int64, error) {
	regReq := BuildRegisterRequest(user, rbeId)

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	// register user and fetch openings
	regR, err := c.client.RegisterUser(ctx, regReq)
	if err != nil {
		log.Errorf("[dev] err on RegisterUser(): %v", err)
		return nil, nil, nil, nil, err
	}
	commitment, opening, ctrAttestation, proof := parseUserRegistrationResponse(regR)

	if ctrAttestation.MsgHash != nil {
		// verifying counter attestation here
		regMsg, err := proto.Marshal(regReq)
		if err != nil {
			log.Errorf("[dev] error marshalling register request: %v", err)
		}

		pbProof := regR.GetProof()
		proofBytes, err := proto.Marshal(pbProof)
		if err != nil {
			log.Errorf("[dev] error marshalling proof: %v", err)
		}

		attestUserData := append(regMsg, proofBytes...)
		if trincutil.DoVerifyCounter(attestUserData, ctrAttestation) {
			log.Infof("[dev] attestation verified successfully")
		} else {
			return nil, nil, nil, nil, fmt.Errorf("[dev] attestation has an invalid signature")
		}
	}

	userIdsBeforeMe := regR.GetUsersBeforeMe()
	return commitment, opening, proof, userIdsBeforeMe, nil
}

func (c *KCClient) FetchPublicParams() (*rbe.PublicParams, error) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	ppr, err := c.client.FetchPublicParams(ctx, &emptypb.Empty{})
	if err != nil {
		log.Errorf("[dev] err on FetchPublicParams: %v", err)
		return nil, err
	}

	pp := new(rbe.PublicParams)
	pp.FromProto(ppr.GetPp())
	return pp, nil
}
