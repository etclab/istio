// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cache is the in-memory secret store.
package cache

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/etclab/rbe"
	"github.com/fsnotify/fsnotify"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"istio.io/istio/pkg/backoff"
	"istio.io/istio/pkg/file"
	"istio.io/istio/pkg/log"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/queue"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
	kcUtil "istio.io/istio/security/pkg/key-curator/util"
	"istio.io/istio/security/pkg/monitoring"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
)

var (
	cacheLog = istiolog.RegisterScope("cache", "cache debugging")
	// The total timeout for any credential retrieval process, default value of 10s is used.
	totalTimeout = time.Second * 10
)

const (
	// firstRetryBackOffDuration is the initial backoff time interval when hitting
	// non-retryable error in CSR request or while there is an error in reading file mounts.
	firstRetryBackOffDuration = 50 * time.Millisecond
)

// --> what is this security.Client?
// spiffe vs regular certificate??
// SecretManagerClient a SecretManager that signs CSRs using a provided security.Client. The primary
// usage is to fetch the two specially named resources: `default`, which refers to the workload's
// spiffe certificate, and ROOTCA, which contains just the root certificate for the workload
// certificates.
// okay upto here

// These are separated only due to the fact that Envoy has them separated.
// Additionally, arbitrary certificates may be fetched from local files to support DestinationRule
// and Gateway. Note that certificates stored externally will be sent from Istiod directly; the
// in-agent SecretManagerClient has low privileges and cannot read Kubernetes Secrets or other
// storage backends.
// okay it is limited to talking with Istiod?

// Istiod is in charge of determining whether the agent (ie SecretManagerClient) or
// Istiod will serve an SDS response, by selecting the appropriate cluster in the SDS configuration
// it serves.
//

// SecretManagerClient supports two modes of retrieving certificate (potentially at the same time):
//   - File based certificates. If certs are mounted under well-known path /etc/certs/{key,cert,root-cert.pem},
//     requests for `default` and `ROOTCA` will automatically read from these files. Additionally,
//     certificates from Gateway/DestinationRule can also be served. This is done by parsing resource
//     names in accordance with security.SdsCertificateConfig (file-cert: and file-root:).
//   - On demand CSRs. This is used only for the `default` certificate. When this resource is
//     requested, a CSR will be sent to the configured caClient.
// okay the on demand CSRs are used for workload certificates

// Callers are expected to only call GenerateSecret when a new certificate is required. Generally,
// this should be done a single time at startup, then repeatedly when the certificate is near
// expiration. To help users handle certificate expiration, any certificates created by the caClient
// will be monitored; when they are near expiration the secretHandler function is triggered,
// prompting the client to call GenerateSecret again, if they still care about the certificate. For
// files, this callback is instead triggered on any change to the file (triggering on expiration
// would not be helpful, as all we can do is re-read the same file).
type SecretManagerClient struct {
	caClient security.Client

	kcClient security.KeyCuratorClient

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// callback function to invoke when detecting secret change.
	secretHandler func(resourceName string)

	// Cache of workload certificate and root certificate. File based certs are never cached, as
	// lookup is cheap.
	cache            secretCache
	rbeCache         rbeSecretCache
	rbeSecretHandler func(resourceName string)
	rbeUpdateHandler func(resourceName string)
	rbeCertMutex     sync.RWMutex

	// generateMutex ensures we do not send concurrent requests to generate a certificate
	generateMutex sync.Mutex

	// The paths for an existing certificate chain, key and root cert files. Istio agent will
	// use them as the source of secrets if they exist.
	existingCertificateFile security.SdsCertificateConfig

	// certWatcher watches the certificates for changes and triggers a notification to proxy.
	certWatcher *fsnotify.Watcher
	// certs being watched with file watcher.
	fileCerts map[FileCert]struct{}
	certMutex sync.RWMutex

	// outputMutex protects writes of certificates to disk
	outputMutex sync.Mutex

	// Dynamically configured Trust Bundle Mutex
	configTrustBundleMutex sync.RWMutex
	// Dynamically configured Trust Bundle
	configTrustBundle []byte

	// queue maintains all certificate rotation events that need to be triggered when they are about to expire
	queue queue.Delayed
	stop  chan struct{}

	caRootPath string
}

type secretCache struct {
	mu       sync.RWMutex
	workload *security.SecretItem
	certRoot []byte
}

type rbeSecretCache struct {
	mu       sync.RWMutex
	workload *security.RbeSecretItem

	pmu              sync.RWMutex
	podValidationMap map[string]bool
}

func (s *rbeSecretCache) GetPodValidationmap() map[string]bool {
	s.pmu.RLock()
	defer s.pmu.RUnlock()
	log.Infof("[dev] getting pod validation map - why wasn't this saved in the first place? %v", s.podValidationMap)
	if s.podValidationMap == nil {
		return nil
	}
	return s.podValidationMap
}

func (s *rbeSecretCache) SetPodValidationmap(value map[string]bool) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	s.podValidationMap = value
}

func (s *rbeSecretCache) GetWorkload() *security.RbeSecretItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.workload == nil {
		return nil
	}
	return s.workload
}

func (s *rbeSecretCache) SetWorkload(value *security.RbeSecretItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workload = value
}

// GetRoot returns cached root cert and cert expiration time. This method is thread safe.
func (s *secretCache) GetRoot() (rootCert []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certRoot
}

// SetRoot sets root cert into cache. This method is thread safe.
func (s *secretCache) SetRoot(rootCert []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certRoot = rootCert
}

func (s *secretCache) GetWorkload() *security.SecretItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.workload == nil {
		return nil
	}
	return s.workload
}

func (s *secretCache) SetWorkload(value *security.SecretItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workload = value
}

var _ security.SecretManager = &SecretManagerClient{}

// FileCert stores a reference to a certificate on disk
type FileCert struct {
	ResourceName string
	Filename     string
}

// NewSecretManagerClient creates a new SecretManagerClient.
func NewSecretManagerClient(caClient security.Client, options *security.Options) (*SecretManagerClient, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	ret := &SecretManagerClient{
		queue:         queue.NewDelayed(queue.DelayQueueBuffer(0)),
		caClient:      caClient,
		configOptions: options,
		existingCertificateFile: security.SdsCertificateConfig{
			CertificatePath:   options.CertChainFilePath,
			PrivateKeyPath:    options.KeyFilePath,
			CaCertificatePath: options.RootCertFilePath,
		},
		certWatcher: watcher,
		fileCerts:   make(map[FileCert]struct{}),
		stop:        make(chan struct{}),
		caRootPath:  options.CARootPath,
	}

	go ret.queue.Run(ret.stop)
	go ret.handleFileWatch()
	return ret, nil
}

// TODO: find alt way to do this
func (sc *SecretManagerClient) SetKCClient(skc security.KeyCuratorClient) {
	sc.kcClient = skc
}

func (sc *SecretManagerClient) Close() {
	_ = sc.certWatcher.Close()
	if sc.caClient != nil {
		sc.caClient.Close()
	}
	if sc.kcClient != nil {
		sc.kcClient.Close()
	}
	close(sc.stop)
}

func (sc *SecretManagerClient) RegisterSecretHandler(h func(resourceName string)) {
	sc.certMutex.Lock()
	defer sc.certMutex.Unlock()
	sc.secretHandler = h
}

// registers a function to fetch updates from the key curator
func (sc *SecretManagerClient) RegisterRbeUpdateHandler(h func(resourceName string)) {
	sc.rbeCertMutex.Lock()
	defer sc.rbeCertMutex.Unlock()

	sc.rbeUpdateHandler = h
}

func (sc *SecretManagerClient) RegisterRbeSecretHandler(h func(resourceName string)) {
	sc.rbeCertMutex.Lock()
	defer sc.rbeCertMutex.Unlock()

	sc.rbeSecretHandler = h
}

func (sc *SecretManagerClient) OnRbeOpeningsUpdate(resourceName string) {
	sc.rbeCertMutex.RLock()
	defer sc.rbeCertMutex.RUnlock()

	if sc.rbeUpdateHandler != nil {
		sc.rbeUpdateHandler(resourceName)
	}
}

func (sc *SecretManagerClient) OnRbeSecretUpdate(resourceName string) {
	sc.rbeCertMutex.RLock()
	defer sc.rbeCertMutex.RUnlock()

	if sc.rbeSecretHandler != nil {
		sc.rbeSecretHandler(resourceName)
	}
}

func (sc *SecretManagerClient) OnSecretUpdate(resourceName string) {
	sc.certMutex.RLock()
	defer sc.certMutex.RUnlock()
	if sc.secretHandler != nil {
		sc.secretHandler(resourceName)
	}
}

// getCachedSecret: retrieve cached Secret Item (workload-certificate/workload-root) from secretManager client
func (sc *SecretManagerClient) getCachedSecret(resourceName string) (secret *security.SecretItem) {
	var rootCertBundle []byte
	var ns *security.SecretItem

	if c := sc.cache.GetWorkload(); c != nil {
		if resourceName == security.RootCertReqResourceName {
			rootCertBundle = sc.mergeTrustAnchorBytes(c.RootCert) // why merge trust anchor bytes? only for ROOTCA -- okay
			// let's see what this looks like
			ns = &security.SecretItem{
				ResourceName: resourceName,
				RootCert:     rootCertBundle,
			}
			cacheLog.WithLabels("ttl", time.Until(c.ExpireTime)).Info("returned workload trust anchor from cache")

		} else {
			ns = &security.SecretItem{
				ResourceName:     resourceName,
				CertificateChain: c.CertificateChain,
				PrivateKey:       c.PrivateKey,
				ExpireTime:       c.ExpireTime,
				CreatedTime:      c.CreatedTime,
			}
			cacheLog.WithLabels("ttl", time.Until(c.ExpireTime)).Info("returned workload certificate from cache")
		}

		return ns
	}
	return nil
}

func (sc *SecretManagerClient) GetRbeCachedSecret(resourceName string) (secret *security.RbeSecretItem) {
	if resourceName == security.RbePodValidationMap {
		if c := sc.rbeCache.GetPodValidationmap(); c != nil {
			ns := &security.RbeSecretItem{
				ResourceName:     resourceName,
				PodValidationMap: c,
				CreatedTime:      time.Now(),
			}
			return ns
		}
		return nil
	}

	var ns *security.RbeSecretItem

	if c := sc.rbeCache.GetWorkload(); c != nil {
		ns = &security.RbeSecretItem{
			Certificate: c.Certificate,
			PrivateKey:  c.PrivateKey,
			User:        c.User,
			Pp:          c.Pp,
			Openings:    c.Openings,
			Commitments: c.Commitments,

			ResourceName: resourceName,
			CreatedTime:  c.CreatedTime,
			ExpireTime:   c.ExpireTime,
		}

		cacheLog.WithLabels("ttl", time.Until(c.ExpireTime)).Info("returned workload rbe secret/certificate from cache")

		return ns
	}
	return nil
}

func (sc *SecretManagerClient) RegisterPodValidityMap(pValidity map[string]bool) {
	log.Infof("[dev] registering pod validity map with value: %v", pValidity)
	sc.rbeCache.SetPodValidationmap(pValidity)
}

func (sc *SecretManagerClient) UpdateUserOpenings() {
	rbeSecret := sc.GetRbeCachedSecret(security.WorkloadRbeIdentityCertResourceName)

	if rbeSecret != nil {
		id := int32(rbeSecret.User.Id())

		pp, err := sc.kcClient.FetchPublicParams()
		if err != nil {
			log.Errorf("[dev] err on FetchPublicParams: %v", err)
		}

		// for single user
		timeBeforeFAU := time.Now()

		commitments, userOpening, err := sc.kcClient.FetchUpdate(id)
		if err != nil {
			log.Errorf("[dev] err on FetchUpdate: %v", err)
		}
		rbeSecret.User.Update(commitments, userOpening)

		totalTimeFAU := float64(time.Since(timeBeforeFAU).Nanoseconds()) / float64(time.Millisecond)

		keyUpdateTimeSingle.With(RequestType.Value(monitoring.MAZU)).Record(totalTimeFAU)
		log.Infof("[dev] Key Update Time (Single): %f", totalTimeFAU)

		totalSizeFAU := 0

		for _, g := range commitments {
			totalSizeFAU += len(g.Bytes())
		}

		for _, row := range userOpening {
			totalSizeFAU += len(row.Bytes())
		}

		keyUpdateSizeSingle.With(RequestType.Value(monitoring.MAZU)).Record(float64(totalSizeFAU))
		log.Infof("[dev] Key Update Size (Single): %d", totalSizeFAU)

		log.Infof("[dev] Got the commitments (%d) and opening (%d) for user: %d", len(commitments), len(userOpening), id)

		// for all users
		timeBeforeFAU = time.Now()

		commitments, allOpenings, allRbeIds, err := sc.kcClient.FetchAllUpdates()
		if err != nil {
			log.Errorf("[dev] err on FetchAllUpdates(): %v", err)
		}
		userOpening = allOpenings[id]

		totalTimeFAU = float64(time.Since(timeBeforeFAU).Nanoseconds()) / float64(time.Millisecond)

		keyUpdateTimeAll.With(RequestType.Value(monitoring.MAZU)).Record(totalTimeFAU)
		log.Infof("[dev] Key Update Time (All): %f", totalTimeFAU)

		totalSizeFAU = 0

		for _, g := range commitments {
			totalSizeFAU += len(g.Bytes())
		}

		for _, row := range allOpenings {
			for _, g := range row {
				totalSizeFAU += len(g.Bytes())
			}
		}

		keyUpdateSizeAll.With(RequestType.Value(monitoring.MAZU)).Record(float64(totalSizeFAU))
		log.Infof("[dev] Key Update Size (All): %d", totalSizeFAU)

		// rbeSecret.User.Update(commitments, userOpening)
		rbeSecret.Pp = pp
		rbeSecret.Openings = allOpenings
		rbeSecret.Commitments = commitments

		sc.rbeCache.SetWorkload(rbeSecret)

		podsValidity := map[string]bool{}

		log.Infof("[dev] all rbe ids: %+v", allRbeIds)

		for _, rbeId := range allRbeIds {
			if rbeId == nil {
				continue
			}
			key := fmt.Sprintf("%s|%d|%s", rbeId.Ip, rbeId.Port, rbeId.Token)
			podsValidity[key] = kcUtil.CheckPodValidity(rbeId, rbeSecret)
		}

		log.Infof("[dev] printing pod validity map for all pods")
		log.Infof("%+v", podsValidity)

		jsonString, err := json.Marshal(podsValidity)
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println(string(jsonString))
		}
		err = os.WriteFile("/etc/istio/proxy/pod_validity_data.json", jsonString, 0644)
		if err != nil {
			log.Errorf("[dev] err on WriteFile: %v", err)
		}

		sc.RegisterPodValidityMap(podsValidity)
	} else {
		log.Infof("[dev] no cached rbe secret\n")
	}

	// fetch updates once new nodes register with key curator (or k8s)
	delaySeconds := 10
	delay := time.Duration(delaySeconds) * time.Second
	log.Infof("[dev] inside UpdateUserOpenings() -- will call again in %d seconds", delaySeconds)

	sc.queue.PushDelayed(func() error {
		if cached := sc.rbeCache.GetWorkload(); cached != nil {
			sc.OnRbeOpeningsUpdate(cached.ResourceName)
		}
		return nil
	}, delay)
}

// 1.3.6.1.4.1.9901
var (
	AdminTokenOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 33}
	SpiffeIdOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 34}
	SerialOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 35}
	SignatureOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 36}
	PodUidOID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 9901, 37}
)

// this function does a few things -- based on RBE
// generates a key pair for a workload
// registers the workload's identity with the key curator
// save the key pair, pp to the secret cache
// TODO: what happens if a pod restarts due to error and have the same identity?
func (sc *SecretManagerClient) GenerateWorkloadRbeSecrets(rbeId *security.RbeId,
	isCertRenewal bool) (secret *security.RbeSecretItem, err error) {
	cacheLog.Infof("[dev] generating workload rbe secrets")

	cachedSecret := sc.rbeCache.GetWorkload()

	log.Infof("[dev] cached secret: %+v\n", cachedSecret)

	var cachedId int
	user := new(rbe.User)
	pp := new(rbe.PublicParams)

	if cachedSecret != nil {
		user = cachedSecret.User
		cachedId = user.Id()
		pp = cachedSecret.Pp
	}

	id := rbeId.ToNumber()
	expireTime := rbeId.ExpireTime

	log.Infof("[dev] cert renewal %v", isCertRenewal)
	log.Infof("[dev] cached is %d and new is %d", cachedId, id)
	if cachedId == int(id) && isCertRenewal {
		// no need to re-register the id if it's a cert renewal
		log.Infof("[dev] cert renewal for id %d", id)
	} else {
		log.Infof("[dev] registering user with id %d for the first time", id)

		// register the user with id
		pp, err = sc.kcClient.FetchPublicParams()
		if err != nil {
			log.Errorf("[dev] err on FetchPublicParams: %v", err)
		}

		sk := new(bls.Scalar)
		sk.SetUint64(uint64(rbeId.SecretKey()))

		// create user
		user = rbe.NewUserWithSecret(pp, int(id), sk)

		// TODO: during registration send the ip, port, token, id, and public key (user includes th public key?)
		commitments, opening, err := sc.kcClient.RegisterUser(user, rbeId)
		if err != nil {
			log.Errorf("[dev] err on RegisterUser(): %v", err)
			return nil, err
		}

		user.Update(commitments, opening)
	}

	adminToken, err := kcUtil.GetPlatformCredential()
	if err != nil {
		log.Errorf("[dev] err on GetPlatformCredential(): %v", err)
		return nil, err
	}

	// note: k8s TokenReview API to verify the token
	// log.Infof("[dev] admin token %v", adminToken)
	// kcUtil.VerifyServiceAccountToken(adminToken)

	extensions := []pkix.Extension{
		{
			Id:    AdminTokenOID,
			Value: []byte(adminToken),
		},
	}

	// TODO: what other information do I need within the cert?
	options := pkiutil.CertOptions{
		Host:       rbeId.SpiffeId.String(),
		RSAKeySize: sc.configOptions.WorkloadRSAKeySize,
		PKCS8Key:   sc.configOptions.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(sc.configOptions.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(sc.configOptions.ECCCurve),

		IsSelfSigned: true,
		IsClient:     true,
		IsServer:     true,

		Extensions: extensions,
	}

	pemCert, pemKey, err := pkiutil.GenCertKeyFromOptions(options)
	if err != nil {
		log.Errorf("[dev] err on GenCertKeyFromOptions(): %v", err)
		return nil, err
	}

	log.Infof("[dev] certificate bytes:\n%s", string(pemCert[:]))
	log.Infof("[dev] key bytes:\n%s", string(pemKey[:]))

	// TODO: can I store these in a file and access them in envoy?
	rsi := &security.RbeSecretItem{
		Certificate: pemCert,
		PrivateKey:  pemKey, // private key for certificate
		User:        user,   // user includes the rbe public-private key pair
		Pp:          pp,

		ResourceName: security.WorkloadRbeIdentityCertResourceName,
		CreatedTime:  time.Now(),
		ExpireTime:   time.Unix(expireTime, 0),
	}

	sc.registerRbeSecret(*rsi)

	return rsi, nil
}

// GenerateSecret passes the cached secret to SDS.StreamSecrets and SDS.FetchSecret.
func (sc *SecretManagerClient) GenerateSecret(resourceName string) (secret *security.SecretItem, err error) {
	cacheLog.Debugf("generate secret %q", resourceName)
	// Setup the call to store generated secret to disk
	defer func() {
		if secret == nil || err != nil {
			return
		}
		// We need to hold a mutex here, otherwise if two threads are writing the same certificate,
		// we may permanently end up with a mismatch key/cert pair. We still make end up temporarily
		// with mismatched key/cert pair since we cannot atomically write multiple files. It may be
		// possible by keeping the output in a directory with clever use of symlinks in the future,
		// if needed.
		sc.outputMutex.Lock()
		defer sc.outputMutex.Unlock()
		if resourceName == security.RootCertReqResourceName || resourceName == security.WorkloadKeyCertResourceName {
			if err := nodeagentutil.OutputKeyCertToDir(sc.configOptions.OutputKeyCertToDir, secret.PrivateKey,
				secret.CertificateChain, secret.RootCert); err != nil {
				cacheLog.Errorf("error when output the resource: %v", err)
			} else if sc.configOptions.OutputKeyCertToDir != "" {
				resourceLog(resourceName).Debugf("output the resource to %v", sc.configOptions.OutputKeyCertToDir)
			}
		}
	}()

	// First try to generate secret from file.
	if sdsFromFile, ns, err := sc.generateFileSecret(resourceName); sdsFromFile {
		if err != nil {
			return nil, err
		}
		return ns, nil
	}

	ns := sc.getCachedSecret(resourceName)
	if ns != nil {
		return ns, nil
	}

	t0 := time.Now()
	sc.generateMutex.Lock()
	defer sc.generateMutex.Unlock()

	// Now that we got the lock, look at cache again before sending request to avoid overwhelming CA
	ns = sc.getCachedSecret(resourceName)
	if ns != nil {
		return ns, nil
	}

	if ts := time.Since(t0); ts > time.Second {
		cacheLog.Warnf("slow generate secret lock: %v", ts)
	}

	// send request to CA to get new workload certificate
	ns, err = sc.generateNewSecret(resourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate workload certificate: %v", err)
	}

	// Store the new secret in the secretCache and trigger the periodic rotation for workload certificate
	sc.registerSecret(*ns)

	if resourceName == security.RootCertReqResourceName {
		ns.RootCert = sc.mergeTrustAnchorBytes(ns.RootCert)
	} else {
		// If periodic cert refresh resulted in discovery of a new root, trigger a ROOTCA request to refresh trust anchor
		oldRoot := sc.cache.GetRoot()
		if !bytes.Equal(oldRoot, ns.RootCert) {
			cacheLog.Info("Root cert has changed, start rotating root cert")
			// We store the oldRoot only for comparison and not for serving
			sc.cache.SetRoot(ns.RootCert)
			sc.OnSecretUpdate(security.RootCertReqResourceName)
		}
	}

	return ns, nil
}

func (sc *SecretManagerClient) addFileWatcher(file string, resourceName string) {
	// Try adding file watcher and if it fails start a retry loop.
	if err := sc.tryAddFileWatcher(file, resourceName); err == nil {
		return
	}
	// RetryWithContext file watcher as some times it might fail to add and we will miss change
	// notifications on those files. For now, retry for ever till the watcher is added.
	// TODO(ramaraochavali): Think about tieing these failures to liveness probe with a
	// reasonable threshold (when the problem is not transient) and restart the pod.
	go func() {
		b := backoff.NewExponentialBackOff(backoff.DefaultOption())
		_ = b.RetryWithContext(context.TODO(), func() error {
			err := sc.tryAddFileWatcher(file, resourceName)
			return err
		})
	}()
}

func (sc *SecretManagerClient) tryAddFileWatcher(file string, resourceName string) error {
	// Check if this file is being already watched, if so ignore it. This check is needed here to
	// avoid processing duplicate events for the same file.
	sc.certMutex.Lock()
	defer sc.certMutex.Unlock()
	file, err := filepath.Abs(file)
	if err != nil {
		cacheLog.Errorf("%v: error finding absolute path of %s, retrying watches: %v", resourceName, file, err)
		return err
	}
	key := FileCert{
		ResourceName: resourceName,
		Filename:     file,
	}
	if _, alreadyWatching := sc.fileCerts[key]; alreadyWatching {
		cacheLog.Debugf("already watching file for %s", file)
		// Already watching, no need to do anything
		return nil
	}
	sc.fileCerts[key] = struct{}{}
	// File is not being watched, start watching now and trigger key push.
	cacheLog.Infof("adding watcher for file certificate %s", file)
	if err := sc.certWatcher.Add(file); err != nil {
		cacheLog.Errorf("%v: error adding watcher for file %v, retrying watches: %v", resourceName, file, err)
		numFileWatcherFailures.Increment()
		return err
	}
	return nil
}

// If there is existing root certificates under a well known path, return true.
// Otherwise, return false.
func (sc *SecretManagerClient) rootCertificateExist(filePath string) bool {
	b, err := os.ReadFile(filePath)
	if err != nil || len(b) == 0 {
		return false
	}
	return true
}

// If there is an existing private key and certificate under a well known path, return true.
// Otherwise, return false.
func (sc *SecretManagerClient) keyCertificateExist(certPath, keyPath string) bool {
	b, err := os.ReadFile(certPath)
	if err != nil || len(b) == 0 {
		return false
	}
	b, err = os.ReadFile(keyPath)
	if err != nil || len(b) == 0 {
		return false
	}

	return true
}

// Generate a root certificate item from the passed in rootCertPath
// doesn't generate but sets the root cert in the cache
func (sc *SecretManagerClient) generateRootCertFromExistingFile(rootCertPath, resourceName string, workload bool) (*security.SecretItem, error) {
	var rootCert []byte
	var err error
	o := backoff.DefaultOption()
	o.InitialInterval = sc.configOptions.FileDebounceDuration
	b := backoff.NewExponentialBackOff(o)
	certValid := func() error {
		rootCert, err = os.ReadFile(rootCertPath)
		if err != nil {
			return err
		}
		_, _, err := pkiutil.ParsePemEncodedCertificateChain(rootCert)
		if err != nil {
			return err
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	if err := b.RetryWithContext(ctx, certValid); err != nil {
		return nil, err
	}

	// Set the rootCert only if it is workload root cert.
	if workload {
		// confused: what cache is the root cert being saved to?
		sc.cache.SetRoot(rootCert)
	}
	return &security.SecretItem{
		ResourceName: resourceName,
		RootCert:     rootCert,
	}, nil
}

// Generate a key and certificate item from the existing key certificate files from the passed in file paths.
// reads from the file and adds to the cache
func (sc *SecretManagerClient) generateKeyCertFromExistingFiles(certChainPath, keyPath, resourceName string) (*security.SecretItem, error) {
	// There is a remote possibility that key is written and cert is not written yet.
	// To handle that case, check if cert and key are valid if they are valid then only send to proxy.
	// woah where did sending to proxy come from? - we were only reading certs/keys
	o := backoff.DefaultOption()
	o.InitialInterval = sc.configOptions.FileDebounceDuration
	b := backoff.NewExponentialBackOff(o)
	secretValid := func() error {
		_, err := tls.LoadX509KeyPair(certChainPath, keyPath)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()
	if err := b.RetryWithContext(ctx, secretValid); err != nil {
		return nil, err
	}
	return sc.keyCertSecretItem(certChainPath, keyPath, resourceName)
}

func (sc *SecretManagerClient) keyCertSecretItem(cert, key, resource string) (*security.SecretItem, error) {
	certChain, err := sc.readFileWithTimeout(cert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := sc.readFileWithTimeout(key)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var certExpireTime time.Time
	if certExpireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		cacheLog.Errorf("failed to extract expiration time in the certificate loaded from file: %v", err)
		return nil, fmt.Errorf("failed to extract expiration time in the certificate loaded from file: %v", err)
	}

	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     resource,
		CreatedTime:      now,
		ExpireTime:       certExpireTime,
	}, nil
}

// readFileWithTimeout reads the given file with timeout. It returns error
// if it is not able to read file after timeout.
func (sc *SecretManagerClient) readFileWithTimeout(path string) ([]byte, error) {
	retryBackoff := firstRetryBackOffDuration
	timeout := time.After(totalTimeout)
	for {
		cert, err := os.ReadFile(path)
		if err == nil {
			return cert, nil
		}
		select {
		case <-time.After(retryBackoff):
			retryBackoff *= 2
		case <-timeout:
			return nil, err
		case <-sc.stop:
			return nil, err
		}
	}
}

// are we able to read secrets from file? for the given resourceName
func (sc *SecretManagerClient) generateFileSecret(resourceName string) (bool, *security.SecretItem, error) {
	logPrefix := cacheLogPrefix(resourceName)

	cf := sc.existingCertificateFile // okay defined somewhere in the config beforehand; has three different paths
	// outputToCertificatePath handles a special case where we have configured to output certificates
	// to the special /etc/certs directory. In this case, we need to ensure we do *not* read from
	// these files, otherwise we would never rotate.
	outputToCertificatePath, ferr := file.DirEquals(filepath.Dir(cf.CertificatePath), sc.configOptions.OutputKeyCertToDir)
	if ferr != nil {
		return false, nil, ferr
	}
	// When there are existing root certificates, or private key and certificate under
	// a well known path, they are used in the SDS response.
	sdsFromFile := false
	var err error
	var sitem *security.SecretItem

	switch {
	// Default root certificate.
	// requesting root certificate
	case resourceName == security.RootCertReqResourceName && sc.rootCertificateExist(cf.CaCertificatePath) && !outputToCertificatePath:
		sdsFromFile = true
		if sitem, err = sc.generateRootCertFromExistingFile(cf.CaCertificatePath, resourceName, true); err == nil {
			// If retrieving workload trustBundle, then merge other configured trustAnchors in ProxyConfig
			sitem.RootCert = sc.mergeTrustAnchorBytes(sitem.RootCert)
			sc.addFileWatcher(cf.CaCertificatePath, resourceName)
		}
	// Default workload certificate.
	case resourceName == security.WorkloadKeyCertResourceName && sc.keyCertificateExist(cf.CertificatePath, cf.PrivateKeyPath) && !outputToCertificatePath:
		sdsFromFile = true
		if sitem, err = sc.generateKeyCertFromExistingFiles(cf.CertificatePath, cf.PrivateKeyPath, resourceName); err == nil {
			// Adding cert is sufficient here as key can't change without changing the cert.
			sc.addFileWatcher(cf.CertificatePath, resourceName)
		}
	case resourceName == security.FileRootSystemCACert: // the default root certs in linux
		sdsFromFile = true
		if sc.caRootPath != "" {
			if sitem, err = sc.generateRootCertFromExistingFile(sc.caRootPath, resourceName, false); err == nil {
				sc.addFileWatcher(sc.caRootPath, resourceName)
			}
		} else {
			sdsFromFile = false
		}
	default:
		// Check if the resource name refers to a file mounted certificate. --> what does a file mounted cert resource name look like?
		// Currently used in destination rules and server certs (via metadata).
		// Based on the resource name, we need to read the secret from a file encoded in the resource name.
		// okay file will be encoded in the resource name
		cfg, ok := security.SdsCertificateConfigFromResourceName(resourceName)
		sdsFromFile = ok
		switch {
		case ok && cfg.IsRootCertificate():
			if sitem, err = sc.generateRootCertFromExistingFile(cfg.CaCertificatePath, resourceName, false); err == nil {
				sc.addFileWatcher(cfg.CaCertificatePath, resourceName)
			}
		case ok && cfg.IsKeyCertificate():
			if sitem, err = sc.generateKeyCertFromExistingFiles(cfg.CertificatePath, cfg.PrivateKeyPath, resourceName); err == nil {
				// Adding cert is sufficient here as key can't change without changing the cert.
				sc.addFileWatcher(cfg.CertificatePath, resourceName)
			}
		}
	}

	if sdsFromFile {
		if err != nil {
			cacheLog.Errorf("%s failed to generate secret for proxy from file: %v",
				logPrefix, err)
			numFileSecretFailures.Increment()
			return sdsFromFile, nil, err
		}
		cacheLog.WithLabels("resource", resourceName).Info("read certificate from file")
		// We do not register the secret. Unlike on-demand CSRs, there is nothing we can do if a file
		// cert expires; there is no point sending an update when its near expiry. Instead, a
		// separate file watcher will ensure if the file changes we trigger an update.
		// we're interested in on-demand CSRs-- yes
		return sdsFromFile, sitem, nil
	}
	return sdsFromFile, nil, nil
}

func (sc *SecretManagerClient) generateNewSecret(resourceName string) (*security.SecretItem, error) {
	trustBundlePEM := []string{}
	var rootCertPEM []byte

	if sc.caClient == nil {
		return nil, fmt.Errorf("attempted to fetch secret, but ca client is nil")
	}
	t0 := time.Now()
	logPrefix := cacheLogPrefix(resourceName)

	csrHostName := &spiffe.Identity{
		TrustDomain:    sc.configOptions.TrustDomain,
		Namespace:      sc.configOptions.WorkloadNamespace,
		ServiceAccount: sc.configOptions.ServiceAccount,
	}

	cacheLog.Debugf("%s constructed host name for CSR: %s", logPrefix, csrHostName.String())
	options := pkiutil.CertOptions{
		Host:       csrHostName.String(),
		RSAKeySize: sc.configOptions.WorkloadRSAKeySize,
		PKCS8Key:   sc.configOptions.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(sc.configOptions.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(sc.configOptions.ECCCurve),
	}

	log.Infof("[dev] options for GenCSR %+v", options)

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		cacheLog.Errorf("%s failed to generate key and certificate for CSR: %v", logPrefix, err)
		return nil, err
	}

	numOutgoingRequests.With(RequestType.Value(monitoring.CSR)).Increment()
	timeBeforeCSR := time.Now()
	certChainPEM, err := sc.caClient.CSRSign(csrPEM, int64(sc.configOptions.SecretTTL.Seconds()))
	if err == nil {
		trustBundlePEM, err = sc.caClient.GetRootCertBundle()
	}
	csrLatency := float64(time.Since(timeBeforeCSR).Nanoseconds()) / float64(time.Millisecond)
	outgoingLatency.With(RequestType.Value(monitoring.CSR)).Record(csrLatency)
	if err != nil {
		numFailedOutgoingRequests.With(RequestType.Value(monitoring.CSR)).Increment()
		cacheLog.Errorf("%s failed to sign: %v", logPrefix, err)
		return nil, err
	}

	certChain := concatCerts(certChainPEM)

	var expireTime time.Time
	// Cert expire time by default is createTime + sc.configOptions.SecretTTL.
	// Istiod respects SecretTTL that passed to it and use it decide TTL of cert it issued.
	// Some customer CA may override TTL param that's passed to it.
	if expireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		cacheLog.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
			logPrefix, certChainPEM, err)
		return nil, fmt.Errorf("failed to extract expire time from server certificate in CSR response: %v", err)
	}

	cacheLog.WithLabels("resourceName", resourceName,
		"latency", time.Since(t0),
		"ttl", time.Until(expireTime)).
		Info("generated new workload certificate")

	if len(trustBundlePEM) > 0 {
		rootCertPEM = concatCerts(trustBundlePEM)
	} else {
		// If CA Client has no explicit mechanism to retrieve CA root, infer it from the root of the certChain
		rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])
	}

	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     resourceName,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
}

var rotateTimeUtil = func(createdTime, expireTime time.Time, graceRatio float64, graceRatioJitter float64) time.Duration {
	// stagger rotation times to prevent large fleets of clients from renewing at the same moment.
	jitter := (rand.Float64() * graceRatioJitter) * float64(rand.IntN(2)*2-1) // #nosec G404 -- crypto/rand not worth the cost
	jitterGraceRatio := graceRatio + jitter
	if jitterGraceRatio > 1 {
		jitterGraceRatio = 1
	}
	if jitterGraceRatio < 0 {
		jitterGraceRatio = 0
	}
	secretLifeTime := expireTime.Sub(createdTime)
	gracePeriod := time.Duration((jitterGraceRatio) * float64(secretLifeTime))
	delay := time.Until(expireTime.Add(-gracePeriod))
	if delay < 0 {
		delay = 0
	}
	return delay
}

var rotateTime = func(secret security.SecretItem, graceRatio float64, graceRatioJitter float64) time.Duration {
	return rotateTimeUtil(secret.CreatedTime, secret.ExpireTime, graceRatio, graceRatioJitter)
}

var rotateRbeTime = func(secret security.RbeSecretItem, graceRatio float64, graceRatioJitter float64) time.Duration {
	return rotateTimeUtil(secret.CreatedTime, secret.ExpireTime, graceRatio, graceRatioJitter)
}

// how does rotation work? - there's a rotation handler function
// how do I customize the rotation? -- is it going to call the same method for rotation: GenerateRbe
func (sc *SecretManagerClient) registerRbeSecret(item security.RbeSecretItem) {
	delay := rotateRbeTime(item, sc.configOptions.SecretRotationGracePeriodRatio, sc.configOptions.SecretRotationGracePeriodRatioJitter)

	item.ResourceName = security.WorkloadRbeIdentityCertResourceName
	// In case there are two calls to GenerateSecret at once, we don't want both to be concurrently registered
	if sc.rbeCache.GetWorkload() != nil {
		resourceLog(item.ResourceName).Infof("skip scheduling certificate rotation, already scheduled")
		return
	}
	sc.rbeCache.SetWorkload(&item)
	resourceLog(item.ResourceName).Debugf("scheduled certificate for rotation in %v", delay)
	certExpirySeconds.ValueFrom(func() float64 { return time.Until(item.ExpireTime).Seconds() }, ResourceName.Value(item.ResourceName))
	sc.queue.PushDelayed(func() error {
		// In case `UpdateConfigTrustBundle` called, it will resign workload cert.
		// Check if this is a stale scheduled rotating task.
		log.Infof("[dev] inside sc.queue.PushDelayed -- will call this every %d seconds", delay)
		if cached := sc.rbeCache.GetWorkload(); cached != nil {
			if cached.CreatedTime == item.CreatedTime {
				resourceLog(item.ResourceName).Debugf("rotating certificate")
				// do not clear the cache - we do generate the cert again but
				// we read the info about id and cert from old cert before replacing it
				// sc.rbeCache.SetWorkload(nil)
				sc.OnRbeSecretUpdate(item.ResourceName)
			}
		}
		return nil
	}, delay)
}

// mark
func (sc *SecretManagerClient) registerSecret(item security.SecretItem) {
	delay := rotateTime(item, sc.configOptions.SecretRotationGracePeriodRatio, sc.configOptions.SecretRotationGracePeriodRatioJitter)
	item.ResourceName = security.WorkloadKeyCertResourceName
	// In case there are two calls to GenerateSecret at once, we don't want both to be concurrently registered
	if sc.cache.GetWorkload() != nil {
		resourceLog(item.ResourceName).Infof("skip scheduling certificate rotation, already scheduled")
		return
	}
	sc.cache.SetWorkload(&item) // workload is the secret item, why?
	resourceLog(item.ResourceName).Debugf("scheduled certificate for rotation in %v", delay)
	certExpirySeconds.ValueFrom(func() float64 { return time.Until(item.ExpireTime).Seconds() }, ResourceName.Value(item.ResourceName))
	sc.queue.PushDelayed(func() error {
		// In case `UpdateConfigTrustBundle` called, it will resign workload cert.
		// Check if this is a stale scheduled rotating task.
		if cached := sc.cache.GetWorkload(); cached != nil {
			if cached.CreatedTime == item.CreatedTime {
				resourceLog(item.ResourceName).Debugf("rotating certificate")
				// Clear the cache so the next call generates a fresh certificate
				sc.cache.SetWorkload(nil)
				sc.OnSecretUpdate(item.ResourceName)
			}
		}
		return nil
	}, delay)
}

func (sc *SecretManagerClient) handleFileWatch() {
	for {
		select {
		case event, ok := <-sc.certWatcher.Events:
			// Channel is closed.
			if !ok {
				return
			}
			// We only care about updates that change the file content
			if !(isWrite(event) || isRemove(event) || isCreate(event)) {
				continue
			}
			sc.certMutex.RLock()
			resources := make(map[FileCert]struct{})
			for k, v := range sc.fileCerts {
				resources[k] = v
			}
			sc.certMutex.RUnlock()
			cacheLog.Infof("event for file certificate %s : %s, pushing to proxy", event.Name, event.Op.String())
			// If it is remove event - cleanup from file certs so that if it is added again, we can watch.
			// The cleanup should happen first before triggering callbacks, as the callbacks are async and
			// we may get generate call before cleanup is done and we will end up not watching the file.
			if isRemove(event) {
				sc.certMutex.Lock()
				for fc := range sc.fileCerts {
					if fc.Filename == event.Name {
						cacheLog.Debugf("removing file %s from file certs", event.Name)
						delete(sc.fileCerts, fc)
						break
					}
				}
				sc.certMutex.Unlock()
			}
			// Trigger callbacks for all resources referencing this file. This is practically always
			// a single resource.
			for k := range resources {
				if k.Filename == event.Name {
					sc.OnSecretUpdate(k.ResourceName)
				}
			}
		case err, ok := <-sc.certWatcher.Errors:
			// Channel is closed.
			if !ok {
				return
			}
			numFileWatcherFailures.Increment()
			cacheLog.Errorf("certificate watch error: %v", err)
		}
	}
}

func isWrite(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write)
}

func isCreate(event fsnotify.Event) bool {
	return event.Has(fsnotify.Create)
}

func isRemove(event fsnotify.Event) bool {
	return event.Has(fsnotify.Remove)
}

// concatCerts concatenates PEM certificates, making sure each one starts on a new line
func concatCerts(certsPEM []string) []byte {
	if len(certsPEM) == 0 {
		return []byte{}
	}
	var certChain bytes.Buffer
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return certChain.Bytes()
}

// UpdateConfigTrustBundle : Update the Configured Trust Bundle in the secret Manager client
func (sc *SecretManagerClient) UpdateConfigTrustBundle(trustBundle []byte) error {
	sc.configTrustBundleMutex.Lock()
	if bytes.Equal(sc.configTrustBundle, trustBundle) {
		cacheLog.Debugf("skip for same trust bundle")
		sc.configTrustBundleMutex.Unlock()
		return nil
	}
	sc.configTrustBundle = trustBundle
	sc.configTrustBundleMutex.Unlock()
	cacheLog.Debugf("update new trust bundle")
	sc.OnSecretUpdate(security.RootCertReqResourceName)
	sc.cache.SetWorkload(nil)
	sc.OnSecretUpdate(security.WorkloadKeyCertResourceName)
	return nil
}

// what is a trustanchor here?
// mergeTrustAnchorBytes: Merge cert bytes with the cached TrustAnchors.
func (sc *SecretManagerClient) mergeTrustAnchorBytes(caCerts []byte) []byte {
	return sc.mergeConfigTrustBundle(pkiutil.PemCertBytestoString(caCerts))
}

// hmm trustanchor is just bytes converted to string? why?
// mergeConfigTrustBundle: merge rootCerts trustAnchors provided in args with proxyConfig trustAnchors
// ensure dedup and sorting before returning trustAnchors
func (sc *SecretManagerClient) mergeConfigTrustBundle(rootCerts []string) []byte {
	sc.configTrustBundleMutex.RLock()
	existingCerts := pkiutil.PemCertBytestoString(sc.configTrustBundle)
	sc.configTrustBundleMutex.RUnlock()
	anchors := sets.New[string]()
	for _, cert := range existingCerts {
		anchors.Insert(cert)
	}
	for _, cert := range rootCerts {
		anchors.Insert(cert)
	}
	anchorBytes := []byte{}
	for _, cert := range sets.SortedList(anchors) { // why sort the string (converted from bytes)?
		anchorBytes = pkiutil.AppendCertByte(anchorBytes, []byte(cert))
	}
	return anchorBytes
}
