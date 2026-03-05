package extauthz

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/uds"
	"istio.io/istio/security/pkg/nodeagent/kcclient"
	"istio.io/istio/security/pkg/nodeagent/regstate"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	socketPath    = "./etc/istio/proxy/ext-authz.sock"
	maxRetryTimes = 5

	// tokenCacheTTL is the TTL for cached TokenReview results. Must be ≤ the
	// smallest delay in the K8s token revocation path (~1s kubelet watch delay
	// + terminationGracePeriodSeconds). We use 1s because the K8s control plane
	// cannot propagate revocation faster than this.
	tokenCacheTTL = 1 * time.Second
)

var extAuthzLog = log.RegisterScope("ext-authz", "ext_authz gRPC server")

// tokenCacheEntry holds a cached TokenReview result.
type tokenCacheEntry struct {
	err       error
	expiresAt time.Time
}

// ExtAuthzServer is an ext_authz gRPC server that listens on a UDS.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	listener   net.Listener
	stopped    *atomic.Bool
	regStore   *regstate.Store
	kubeClient kubernetes.Interface

	kcClient *kcclient.KCClient      // for on-demand registration queries
	rbeState *regstate.LocalRBEState // for verifying on-demand results

	onDemandEnabled bool // feature flag: when false, ext_authz denies unknown users
	onDemandMu      sync.RWMutex
	onDemandCache   map[int]*regstate.UserRegistration // separate from regStore

	tokenCacheMu sync.RWMutex
	tokenCache   map[[32]byte]tokenCacheEntry // sha256(token) -> cached result
}

// Check implements the envoy ext_authz v3 AuthorizationServer interface.
func (s *ExtAuthzServer) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := req.GetAttributes()

	// --- Log source (downstream caller) info ---
	src := attrs.GetSource()
	extAuthzLog.Infof("Check: source.principal=%q, source.service=%q",
		src.GetPrincipal(), src.GetService())
	if src.GetAddress() != nil {
		if sa := src.GetAddress().GetSocketAddress(); sa != nil {
			extAuthzLog.Infof("Check: source.address=%s:%d", sa.GetAddress(), sa.GetPortValue())
		}
	}

	// --- Log destination info ---
	dst := attrs.GetDestination()
	extAuthzLog.Infof("Check: destination.principal=%q, destination.service=%q",
		dst.GetPrincipal(), dst.GetService())
	if dst.GetAddress() != nil {
		if sa := dst.GetAddress().GetSocketAddress(); sa != nil {
			extAuthzLog.Infof("Check: destination.address=%s:%d", sa.GetAddress(), sa.GetPortValue())
		}
	}

	// --- Log TLS session ---
	if tls := attrs.GetTlsSession(); tls != nil {
		extAuthzLog.Infof("Check: tls_session.sni=%q", tls.GetSni())
	} else {
		extAuthzLog.Infof("Check: tls_session=nil (is IncludeTlsSession enabled?)")
	}

	// --- Parse and inspect the source peer certificate ---
	certRaw := src.GetCertificate()
	var cert *x509.Certificate
	if certRaw != "" {
		extAuthzLog.Infof("Check: source.certificate present (%d bytes)", len(certRaw))

		var err error
		cert, err = parsePeerCertificate(certRaw)
		if err != nil {
			extAuthzLog.Errorf("Check: failed to parse source certificate: %v", err)
		} else {
			logCertDetails(cert)

			// Allow ingress gateway traffic through
			for _, uri := range cert.URIs {
				if strings.Contains(uri.String(), "/sa/istio-ingressgateway") ||
					strings.Contains(uri.String(), "/sa/istio-gateway") {
					extAuthzLog.Infof("Check: source is ingress gateway, allowing")
					return allow(), nil
				}
			}
		}
	} else {
		extAuthzLog.Infof("Check: source.certificate is empty (is IncludePeerCertificate enabled?)")
	}

	// --- RBE validation ---
	// Fail closed: if no source cert is available, deny.
	if cert == nil {
		return deny("source certificate missing or unparseable"), nil
	}

	// Extract the RBE admin token from the cert's custom extension
	token, err := extractRbeToken(cert)
	if err != nil {
		return deny(fmt.Sprintf("RBE token extraction failed: %v", err)), nil
	}

	// Verify the token via the Kubernetes TokenReview API (in parallel with RBE checks)
	tokenErrCh := make(chan error, 1)
	go func() {
		tokenErrCh <- s.verifyToken(context.Background(), token)
	}()

	// Compute the RBE user ID from the token
	rbeId := &security.RbeId{Token: token}
	id := int(rbeId.ToNumber())
	extAuthzLog.Infof("Check: extracted RBE token, computed id=%d", id)

	// Look up the source user in the registration store
	reg, ok := s.regStore.Get(id)
	if !ok {
		if s.onDemandEnabled {
			// Fallback: query KC directly and cache the result
			reg, ok = s.fetchAndCacheRegistration(id)
			if !ok {
				return deny(fmt.Sprintf("source RBE registration not found for id=%d", id)), nil
			}
		} else {
			return deny(fmt.Sprintf("source RBE registration not found for id=%d, waiting for stream", id)), nil
		}
	}

	if !reg.PodValid {
		return deny(fmt.Sprintf("source RBE pod validation failed for id=%d", id)), nil
	}

	// Wait for TokenReview result before allowing
	if err := <-tokenErrCh; err != nil {
		return deny(fmt.Sprintf("token verification failed: %v", err)), nil
	}

	extAuthzLog.Infof("Check: RBE validation passed for id=%d", id)
	return allow(), nil
}

func allow() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func deny(reason string) *authv3.CheckResponse {
	extAuthzLog.Infof("Check: DENIED — %s", reason)
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.Unauthenticated), Message: reason},
	}
}

// AdminTokenOID is the custom X.509 extension OID used to embed the RBE admin token.
// Matches the OID defined in secretcache.go.
var AdminTokenOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 33}

// extractRbeToken extracts the RBE admin token from a custom X.509 certificate extension.
func extractRbeToken(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AdminTokenOID) {
			return string(ext.Value), nil
		}
	}
	return "", fmt.Errorf("AdminTokenOID extension %v not found in certificate", AdminTokenOID)
}

// verifyToken checks a cached TokenReview result first, falling back to the
// Kubernetes TokenReview API only when the cache entry is missing or expired.
func (s *ExtAuthzServer) verifyToken(ctx context.Context, token string) error {
	if s.kubeClient == nil {
		return fmt.Errorf("kubernetes client not available")
	}

	key := sha256.Sum256([]byte(token))

	// Check cache under read lock.
	s.tokenCacheMu.RLock()
	entry, ok := s.tokenCache[key]
	s.tokenCacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.err
	}

	// Cache miss or expired — call TokenReview.
	reviewErr := s.doTokenReview(ctx, token)

	s.tokenCacheMu.Lock()
	s.tokenCache[key] = tokenCacheEntry{
		err:       reviewErr,
		expiresAt: time.Now().Add(tokenCacheTTL),
	}
	s.tokenCacheMu.Unlock()

	return reviewErr
}

// doTokenReview calls the Kubernetes TokenReview API.
func (s *ExtAuthzServer) doTokenReview(ctx context.Context, token string) error {
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := s.kubeClient.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("TokenReview API call failed: %w", err)
	}

	if !result.Status.Authenticated {
		return fmt.Errorf("token not authenticated (error=%q)", result.Status.Error)
	}

	extAuthzLog.Infof("Check: TokenReview passed for user=%q", result.Status.User.Username)
	return nil
}

// fetchAndCacheRegistration queries the KC for a registration and caches the result.
// Returns the UserRegistration and true if successful, nil and false otherwise.
func (s *ExtAuthzServer) fetchAndCacheRegistration(id int) (*regstate.UserRegistration, bool) {
	// Check on-demand cache first
	s.onDemandMu.RLock()
	if reg, ok := s.onDemandCache[id]; ok {
		s.onDemandMu.RUnlock()
		extAuthzLog.Infof("[dev] on-demand cache hit for id=%d", id)
		return reg, true
	}
	s.onDemandMu.RUnlock()

	if s.kcClient == nil || s.rbeState == nil {
		extAuthzLog.Infof("[dev] on-demand fallback unavailable (kcClient=%v, rbeState=%v)", s.kcClient != nil, s.rbeState != nil)
		return nil, false
	}

	extAuthzLog.Infof("[dev] on-demand fetch for id=%d", id)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	notif, err := s.kcClient.FetchRegistration(ctx, int64(id))
	if err != nil {
		extAuthzLog.Errorf("[dev] on-demand FetchRegistration failed for id=%d: %v", id, err)
		return nil, false
	}

	// Process as on-demand: skips proof verification (relies on challenge-response).
	// Proof will be verified later when the stream delivers this registration.
	if !regstate.ProcessRegistration(s.regStore, s.rbeState, notif, regstate.SourceOnDemand) {
		extAuthzLog.Errorf("[dev] on-demand verification failed for id=%d", id)
		return nil, false
	}

	// VerifyAndStore already put it in regStore; also cache in onDemandCache
	reg, ok := s.regStore.Get(id)
	if !ok {
		return nil, false
	}

	s.onDemandMu.Lock()
	s.onDemandCache[id] = reg
	s.onDemandMu.Unlock()

	extAuthzLog.Infof("[dev] on-demand fetch and verification succeeded for id=%d", id)
	return reg, true
}

// NewExtAuthzServer creates and starts the ext_authz gRPC server on a UDS.
func NewExtAuthzServer(store *regstate.Store, kcCl *kcclient.KCClient, rbeState *regstate.LocalRBEState, onDemandEnabled bool) *ExtAuthzServer {
	// Create a kubernetes client for TokenReview API calls.
	var kubeClient kubernetes.Interface
	config, err := rest.InClusterConfig()
	if err != nil {
		extAuthzLog.Errorf("failed to get in-cluster config for TokenReview: %v", err)
	} else {
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			extAuthzLog.Errorf("failed to create kubernetes client for TokenReview: %v", err)
		} else {
			kubeClient = clientset
		}
	}

	s := &ExtAuthzServer{
		stopped:         atomic.NewBool(false),
		regStore:        store,
		kubeClient:      kubeClient,
		kcClient:        kcCl,
		rbeState:        rbeState,
		onDemandEnabled: onDemandEnabled,
		onDemandCache:   make(map[int]*regstate.UserRegistration),
		tokenCache:      make(map[[32]byte]tokenCacheEntry),
	}

	s.grpcServer = grpc.NewServer()
	authv3.RegisterAuthorizationServer(s.grpcServer, s)

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

// parsePeerCertificate URL-decodes and PEM-decodes the certificate string from envoy,
// then parses it as an X.509 certificate.
func parsePeerCertificate(certRaw string) (*x509.Certificate, error) {
	certPEM, err := url.QueryUnescape(certRaw)
	if err != nil {
		return nil, fmt.Errorf("URL-decode: %w", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		preview := certPEM
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("PEM-decode failed, preview: %s", preview)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 parse: %w", err)
	}
	return cert, nil
}

// logCertDetails logs all relevant fields and extensions from an X.509 certificate.
func logCertDetails(cert *x509.Certificate) {
	extAuthzLog.Infof("Check: cert.SerialNumber=%s", cert.SerialNumber)
	extAuthzLog.Infof("Check: cert.NotBefore=%s, cert.NotAfter=%s", cert.NotBefore, cert.NotAfter)
	extAuthzLog.Infof("Check: cert.URIs=%v", cert.URIs)

	// Log all X.509 extensions (both standard and custom)
	for _, ext := range cert.Extensions {
		logExtension("Extension", ext)
	}
	for _, ext := range cert.ExtraExtensions {
		logExtension("ExtraExtension", ext)
	}
}

// logExtension logs a single X.509 extension with its OID, criticality, and value.
func logExtension(label string, ext pkix.Extension) {
	name := oidName(ext.Id)
	extAuthzLog.Infof("Check: cert.%s: OID=%s (%s), critical=%v, value(%d bytes)=%s",
		label, ext.Id, name, ext.Critical, len(ext.Value), hex.EncodeToString(ext.Value))

	// Try to decode as UTF8String or PrintableString for readable extensions
	var str string
	if _, err := asn1.Unmarshal(ext.Value, &str); err == nil {
		extAuthzLog.Infof("Check: cert.%s: OID=%s decoded_string=%q", label, ext.Id, str)
	}
}

// oidName returns a human-readable name for well-known X.509 extension OIDs.
func oidName(oid asn1.ObjectIdentifier) string {
	known := map[string]string{
		"2.5.29.14":               "SubjectKeyIdentifier",
		"2.5.29.15":               "KeyUsage",
		"2.5.29.17":               "SubjectAlternativeName",
		"2.5.29.19":               "BasicConstraints",
		"2.5.29.35":               "AuthorityKeyIdentifier",
		"2.5.29.37":               "ExtendedKeyUsage",
		"2.5.29.31":               "CRLDistributionPoints",
		"2.5.29.32":               "CertificatePolicies",
		"1.3.6.1.4.1.11129.2.4.2": "SCTList",
	}
	if name, ok := known[oid.String()]; ok {
		return name
	}
	return "unknown"
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
