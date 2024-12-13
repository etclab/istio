package kcclient

// maybe call this rbeclient?

import (
	"context"
	"fmt"

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
	// It means enable tls connection to Citadel if this is not nil.
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

// NewCitadelClient create a CA client for Citadel.
func NewCitadelClient(opts *security.Options, tlsOpts *TLSOptions) (*KCClient, error) {
	c := &KCClient{
		tlsOpts:  tlsOpts,
		opts:     opts,
		provider: caclient.NewDefaultTokenProvider(opts),
	}

	conn, err := c.buildConnection()
	if err != nil {
		kcClientLog.Errorf("Failed to connect to endpoint %s: %v", opts.CAEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", opts.CAEndpoint)
	}
	c.conn = conn
	c.client = pb.NewKeyCuratorClient(conn)
	return c, nil
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

func (c *KCClient) RegisterUser(user *rbe.User, id int32) ([]*bls.G1, []*bls.G1, error) {
	xi := user.Xi()

	log.Infof("[dev] user xi: %v", user.Xi())
	log.Infof("[dev] user public key: %v", user.PublicKey())

	xiProto := make([]*rbeproto.G1, len(xi))
	for i, v := range xi {
		if v == nil {
			xiProto[i] = nil
		} else {
			xiProto[i] = &rbeproto.G1{Point: v.Bytes()}
		}
	}

	regReq := &pb.RegisterRequest{
		Id:        int32(id),
		PublicKey: &rbeproto.G1{Point: user.PublicKey().Bytes()},
		Xi:        xiProto,
	}
	log.Infof("[dev] register request: %v\n", regReq)

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	// register user and fetch openings
	regR, err := c.client.RegisterUser(ctx, regReq)
	if err != nil {
		log.Errorf("[dev] err on RegisterUser(): %v", err)
		return nil, nil, err
	}

	commitments := []*bls.G1{}
	for _, v := range regR.GetCommitments() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		commitments = append(commitments, g1)
	}

	opening := []*bls.G1{}
	for _, v := range regR.GetOpening() {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		opening = append(opening, g1)
	}

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
