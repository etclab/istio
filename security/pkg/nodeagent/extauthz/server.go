package extauthz

import (
	"context"
	"net"
	"time"

	"go.uber.org/atomic"
	"google.golang.org/grpc"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/uds"
)

const (
	socketPath    = "./etc/istio/proxy/ext-authz.sock"
	maxRetryTimes = 5
)

var extAuthzLog = log.RegisterScope("ext-authz", "ext_authz gRPC server")

// ExtAuthzServer is an always-allow ext_authz gRPC server that listens on a UDS.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	listener   net.Listener
	stopped    *atomic.Bool
}

// Check implements the envoy ext_authz v3 AuthorizationServer interface.
// It always returns OK (code 0).
func (s *ExtAuthzServer) Check(_ context.Context, _ *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	extAuthzLog.Infof("Received Check request, allowing by default")
	return &authv3.CheckResponse{
		Status: &status.Status{Code: 0},
	}, nil
}

// NewExtAuthzServer creates and starts the ext_authz gRPC server on a UDS.
func NewExtAuthzServer() *ExtAuthzServer {
	s := &ExtAuthzServer{
		stopped: atomic.NewBool(false),
	}

	s.grpcServer = grpc.NewServer()
	authv3.RegisterAuthorizationServer(s.grpcServer, s)

	var err error
	s.listener, err = uds.NewListener(socketPath)

	go func() {
		extAuthzLog.Infof("Starting ext_authz gRPC server, will listen on %q", socketPath)
		waitTime := time.Second
		started := false
		for i := 0; i < maxRetryTimes; i++ {
			if s.stopped.Load() {
				return
			}
			if s.listener == nil {
				if s.listener, err = uds.NewListener(socketPath); err != nil {
					extAuthzLog.Errorf("ext_authz server failed to set up UDS: %v", err)
					time.Sleep(waitTime)
					waitTime *= 2
					continue
				}
			}
			if err = s.grpcServer.Serve(s.listener); err != nil {
				extAuthzLog.Errorf("ext_authz gRPC server failed to start: %v", err)
				s.listener = nil
				time.Sleep(waitTime)
				waitTime *= 2
				continue
			}
			started = true
			break
		}
		if !started {
			extAuthzLog.Warn("ext_authz gRPC server could not be started")
		}
	}()

	return s
}

// Stop gracefully shuts down the ext_authz server.
func (s *ExtAuthzServer) Stop() {
	if s == nil {
		return
	}
	s.stopped.Store(true)
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
	if s.listener != nil {
		s.listener.Close()
	}
}
