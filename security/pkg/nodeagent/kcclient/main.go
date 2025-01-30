package kcclient

// maybe call this rbeclient?

import (
	"context"
	"fmt"
	"strconv"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"istio.io/istio/pkg/log"

	rbeproto "github.com/etclab/rbe/proto"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	"istio.io/istio/pkg/security"
	pb "istio.io/istio/security/pkg/key-curator/key-curator"
	"istio.io/istio/security/pkg/nodeagent/caclient"
)

var kcClientLog = log.RegisterScope("kcclient", "key curator client debugging")

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

func (c *KCClient) FetchAllUpdates() ([]*bls.G1, [][]*bls.G1, []*security.RbeId, error) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	updResp, err := c.client.FetchAllUpdates(ctx, &emptypb.Empty{})
	if err != nil {
		log.Errorf("[dev] err on FetchAllUpdates(): %v", err)
		return nil, nil, nil, err
	}

	openings := make([][]*bls.G1, 0)
	commitments := make([]*bls.G1, 0)

	for _, v := range updResp.GetAllCommitments() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		commitments = append(commitments, g1)
	}

	for _, v := range updResp.GetAllOpenings() {
		userOpening := make([]*bls.G1, 0)
		for _, u := range v.GetOpening() {
			g1 := new(bls.G1)
			g1.SetBytes(u.GetPoint())
			userOpening = append(userOpening, g1)
		}
		openings = append(openings, userOpening)
	}

	history := updResp.GetHistory()
	allRbeIds := make([]*security.RbeId, len(history))
	for _, registrationEvent := range history {
		// TODO: make everything string
		port, err := strconv.Atoi(registrationEvent.GetPort())
		if err != nil {
			log.Infof("[dev] err on converting port to int: %v", err)
			continue
		}

		rbeId := &security.RbeId{
			Token: registrationEvent.GetToken(),
			Ip:    registrationEvent.GetIp(),
			Port:  port,
		}
		allRbeIds = append(allRbeIds, rbeId)
	}

	return commitments, openings, allRbeIds, nil
}

func (c *KCClient) FetchUpdate(id int32) ([]*bls.G1, []*bls.G1, error) {
	updReq := &pb.UpdateRequest{
		Id: id,
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	updResp, err := c.client.FetchUpdate(ctx, updReq)
	if err != nil {
		log.Errorf("[dev] err on FetchUpdate(): %v", err)
		return nil, nil, err
	}

	commitments, opening := getCommitmentsOpenings(updResp)

	return commitments, opening, nil
}

func getCommitmentsOpenings(uoResp *pb.UserOpeningResponse) ([]*bls.G1, []*bls.G1) {

	commitments := []*bls.G1{}
	for _, v := range uoResp.GetCommitments() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		commitments = append(commitments, g1)
	}

	opening := []*bls.G1{}
	for _, v := range uoResp.GetOpening() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		opening = append(opening, g1)
	}

	return commitments, opening
}

// func (c *KCClient) RegisterUser(user *rbe.User, id int32) ([]*bls.G1, []*bls.G1, error) {
func (c *KCClient) RegisterUser(user *rbe.User, rbeId *security.RbeId) ([]*bls.G1, []*bls.G1, error) {
	xi := user.Xi()

	xiProto := make([]*rbeproto.G1, len(xi))
	for i, v := range xi {
		if v == nil {
			xiProto[i] = nil
		} else {
			xiProto[i] = &rbeproto.G1{Point: v.Bytes()}
		}
	}

	id := rbeId.ToNumber()
	regReq := &pb.RegisterRequest{
		Id:        int32(id),
		PublicKey: &rbeproto.G1{Point: user.PublicKey().Bytes()},
		Xi:        xiProto,
		Ip:        rbeId.Ip,
		Port:      strconv.Itoa(rbeId.Port),
		Token:     rbeId.Token,
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	// register user and fetch openings
	regR, err := c.client.RegisterUser(ctx, regReq)
	if err != nil {
		log.Errorf("[dev] err on RegisterUser(): %v", err)
		return nil, nil, err
	}
	commitments, opening := getCommitmentsOpenings(regR)

	return commitments, opening, nil
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
