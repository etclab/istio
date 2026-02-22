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
	"crypto/md5"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/etclab/rbe"
	"github.com/etclab/trinc"
	"github.com/fsnotify/fsnotify"
	clientv3 "go.etcd.io/etcd/client/v3"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe/proto"
	gproto "google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/backoff"
	"istio.io/istio/pkg/file"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/queue"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
	etcdutil "istio.io/istio/security/pkg/etcd/util"
	kconstants "istio.io/istio/security/pkg/key-curator/constants"
	kproto "istio.io/istio/security/pkg/key-curator/key-curator"
	kcUtil "istio.io/istio/security/pkg/key-curator/util"
	keycurator "istio.io/istio/security/pkg/key-curator/util"
	"istio.io/istio/security/pkg/monitoring"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	trincutil "istio.io/istio/security/pkg/trinc/util"
)

var (
	cacheLog = log.RegisterScope("cache", "cache debugging")
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

	lastCommitmentsUpdate atomic.Value
	lastCounterValue      atomic.Value
	// tracks the last revision for each block's commitments
	// data for old revisions are discarded
	lastRevisionForBlock   map[int]int64
	muLastRevisionForBlock sync.RWMutex

	// new map for user openings
	// map[user-id]map[commitment-mod-revision]opening
	userOpenings2   map[int64]map[int64][]*bls.G1
	muUserOpenings2 sync.RWMutex

	lastRevisionForUser   map[string]int64
	muLastRevisionForUser sync.RWMutex

	lastCommitmentModRevisionForOpening   map[string]int64
	muLastCommitmentModRevisionForOpening sync.RWMutex

	resetOpeningsChan chan bool

	rbePp   *rbe.PublicParams
	muRbePp sync.RWMutex

	// this is done because we need past commitments to verify proofs later
	// commitmentsHistory   map[int][]*bls.G1
	// tracks the history of commitments for blocks
	// map[block-id]map[commitment-mod-revision]commitment
	commitmentsHistory   map[int64]map[int64]*bls.G1
	muCommitmentsHistory sync.RWMutex

	recentCommitments   map[int64][]*bls.G1
	muRecentCommitments sync.RWMutex

	userOpenings   map[string]map[string][]*bls.G1
	muUserOpenings sync.RWMutex

	// new map for pods validity
	podsValidityMap2   map[string]bool
	muPodsValidityMap2 sync.RWMutex

	podsValidityMap   map[string]map[string]bool
	muPodsValidityMap sync.RWMutex

	// commRevision -> userId -> whether error occurred when processing this opening
	// if yes we'll check at the end of processing each opening and if there are
	// any errors left we'll requeue thems
	erroredWaiting   map[string]map[string]bool
	muErroredWaiting sync.RWMutex

	receivedOpeningKeyChan chan string
	receivedUserKeyChan    chan string

	regUsers   map[string]*RegisteredUser
	muRegUsers sync.RWMutex

	// holds the `rbe-user/<user-id>` keys that needs proofs to be verified
	userVerificationChan chan string
	// proof verification for multiple users can fail so track them
	// hold keys here until proof is verified
	// since a single function is going to process these, no mutex is needed
	unverifiedUsersList []string
	isUserVerified      map[string]bool
	muIsUserVerified    sync.RWMutex

	userRegProofs   map[string]*bls.G1
	muUserRegProofs sync.RWMutex

	userRegAttestations   map[string]*trinc.CounterAttestation
	muUserRegAttestations sync.RWMutex

	usersFromLog   []int64
	muUsersFromLog sync.RWMutex

	etcdClient *clientv3.Client

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

	// userIdsBeforeMe tracks user ids that were registered before this user
	userIdsBeforeMe   []int64
	muUserIdsBeforeMe sync.RWMutex
	// validUsersMap tracks user ids created before the new user
	validUsersMap   map[int64]bool
	muValidUsersMap sync.RWMutex

	readyChan          chan bool
	areOthersReadyChan chan bool

	amIReady       atomic.Value
	areOthersReady atomic.Value
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
		certWatcher:            watcher,
		fileCerts:              make(map[FileCert]struct{}),
		stop:                   make(chan struct{}),
		caRootPath:             options.CARootPath,
		receivedOpeningKeyChan: make(chan string, 100),
		receivedUserKeyChan:    make(chan string, 100),

		userVerificationChan: make(chan string, 100),
		lastRevisionForBlock: make(map[int]int64),
	}

	go ret.queue.Run(ret.stop)
	go ret.handleFileWatch()
	return ret, nil
}

func (sc *SecretManagerClient) SetKCClient(skc security.KeyCuratorClient) {
	sc.kcClient = skc
}

func (sc *SecretManagerClient) GetKCClientConcrete() security.KeyCuratorClient {
	return sc.kcClient
}

func (sc *SecretManagerClient) GetPublicParams() *rbe.PublicParams {
	sc.muRbePp.RLock()
	defer sc.muRbePp.RUnlock()
	return sc.rbePp
}

func (sc *SecretManagerClient) GetRbeWorkload() *security.RbeSecretItem {
	return sc.rbeCache.GetWorkload()
}

func (sc *SecretManagerClient) SetReadyChannel(readyChan chan bool) {
	sc.readyChan = readyChan
}

func (sc *SecretManagerClient) SetAreOthersReadyChannel(areOthersReadyChan chan bool) {
	sc.areOthersReadyChan = areOthersReadyChan
}

func (sc *SecretManagerClient) SetupEtcdClient() {
	client, err := etcdutil.TryConnectToEtcdWithRetry()
	if err != nil {
		log.Errorf("[dev] unable to connect to etcd: %v", err)
		return
	}

	sc.etcdClient = client
	log.Infof("[dev] etcd client set in secret manager client")
}

func (sc *SecretManagerClient) Close() {
	_ = sc.certWatcher.Close()
	if sc.caClient != nil {
		sc.caClient.Close()
	}
	if sc.kcClient != nil {
		sc.kcClient.Close()
	}
	if sc.etcdClient != nil {
		sc.etcdClient.Close()
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

type RegisteredUser struct {
	Id        int64
	PublicKey *bls.G1
	Xi        []*bls.G1
	Ip        string
	Port      string
	Token     string
}

// fetches and listens for updates to registered users from etcd
func (sc *SecretManagerClient) GetWatchRegisteredUsers() {
	userRes, err := sc.etcdClient.Get(context.Background(), kconstants.RBE_USER_PREFIX,
		clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByModRevision, clientv3.SortAscend))
	if err != nil {
		log.Errorf("[dev] failed to fetch existing users from etcd: %v", err)
	}

	log.Infof("[dev] fetched %d existing users from etcd with revision: %d", len(userRes.Kvs), userRes.Header.Revision)
	for _, kv := range userRes.Kvs {
		value := kv.Value
		keyStr := string(kv.Key)

		err := sc.handleRegisteredUserUpdate(keyStr, value)
		if err != nil {
			log.Errorf("[dev] failed to handle registered user update: %v", err)
		}
	}

	currentRevision := userRes.Header.Revision
	log.Infof("current revision is %d", currentRevision)

	// watch for updates to registered users
	go func() {
		uch := sc.etcdClient.Watch(context.Background(), kconstants.RBE_USER_PREFIX,
			clientv3.WithPrefix(), clientv3.WithRev(currentRevision+1))
		for newUserResp := range uch {
			if newUserResp.Canceled {
				log.Warnf("[dev] etcd watch canceled: %v", newUserResp.Err())
				return
			}

			for _, ev := range newUserResp.Events {
				log.Infof("[dev] type: %s, key: %q\n", ev.Type, ev.Kv.Key)

				if ev.Type == clientv3.EventTypePut {
					key := string(ev.Kv.Key)
					value := ev.Kv.Value

					err := sc.handleRegisteredUserUpdate(key, value)
					if err != nil {
						log.Errorf("[dev] failed to handle registered user update: %v", err)
					}
				}
			}
		}
	}()
}

// after receiving an opening for user and validating it successfully
// a service saves a key: rbe-log/<received-user-id>/verified-by/<my-user-id>
// this tells everyone that the opening for received-user-id has been verified by my-user-id
func (sc *SecretManagerClient) GetWatchLog(myUserId int64) {
	key := fmt.Sprintf("%s/%d", kconstants.RBE_LOG_KEY, myUserId)
	logRes, err := sc.etcdClient.Get(context.Background(), key, clientv3.WithPrefix())
	if err != nil {
		log.Errorf("[dev] failed to fetch existing logs from etcd: %v", err)
	}

	log.Infof("[dev] fetched %d existing logs from etcd with revision: %d", len(logRes.Kvs), logRes.Header.Revision)
	for _, kv := range logRes.Kvs {
		keyStr := string(kv.Key)

		err := sc.handleRbeLogUpdate(keyStr)
		if err != nil {
			log.Errorf("[dev] failed to handle rbe-log update: %v", err)
		}
	}

	currentRevision := logRes.Header.Revision
	log.Infof("current revision is %d", currentRevision)

	// watch for new logs
	go func() {
		uch := sc.etcdClient.Watch(context.Background(), key, clientv3.WithPrefix(), clientv3.WithRev(currentRevision+1))
		for newUserResp := range uch {
			if newUserResp.Canceled {
				log.Warnf("[dev] etcd watch canceled: %v", newUserResp.Err())
				return
			}

			for _, ev := range newUserResp.Events {
				log.Infof("[dev] type: %s, key: %q\n", ev.Type, ev.Kv.Key)

				if ev.Type == clientv3.EventTypePut {
					key := string(ev.Kv.Key)

					err := sc.handleRbeLogUpdate(key)
					if err != nil {
						log.Errorf("[dev] failed to handle rbe-log update: %v", err)
					}
				}

				// check if areOthersReady so that you can break out of this loop
				if sc.areOthersReady.Load() != nil && sc.areOthersReady.Load().(bool) {
					log.Infof("[dev] Others are already ready, skipping check")
					return
				}
			}
		}
	}()
}

func (sc *SecretManagerClient) UpdatePodValidationWithUser() {
	for keyStr := range sc.receivedUserKeyChan {
		log.Infof("[dev] UpdatePodValidationWithUser: received key: %s from channel", keyStr)

		// keyStr has format: rbe-user/<user-id>
		parts := strings.Split(keyStr, "/")
		if len(parts) != 2 {
			log.Errorf("[dev] invalid key format for user key: %s", keyStr)
			continue
		}
		userId := parts[1]
		log.Infof("[dev] updating validation map for user with id: %s", userId)

		// keyStr has format: rbe-system/openings/<commitments-revision>/<user-id>
		// get all commitments revisions
		// get all registered users
		// sc.muRecentCommitments.RLock()
		// sc.muRegUsers.RLock()
		// for commRev, _ := range sc.recentCommitments {
		// 	commRevStr := strconv.FormatInt(commRev, 10)

		// 	for _, regUser := range sc.regUsers {
		// 		userId := strconv.FormatInt(regUser.Id, 10)

		// 		openingKey := fmt.Sprintf("%s/%s", commRevStr, userId)
		// 		sc.receivedOpeningKeyChan <- fmt.Sprintf("%s/%s", kconstants.RBE_USER_PREFIX, openingKey)
		// 	}
		// }
		// existingKeys := []string{}
		// sc.muUserOpenings.RLock()
		// for commRev, _ := range sc.userOpenings {
		// 	if sc.userOpenings[commRev] != nil {
		// 		for id, _ := range sc.userOpenings[commRev] {
		// 			openingKey := fmt.Sprintf("%s/%s", commRev, id)
		// 			existingKeys = append(existingKeys, openingKey)
		// 		}
		// 	}
		// }
		// sc.muUserOpenings.RUnlock()

		// for _, openingKey := range existingKeys {
		// 	sc.receivedOpeningKeyChan <- fmt.Sprintf("%s/%s", kconstants.RBE_OPENINGS_KEY, openingKey)
		// }
		go sc.retryAllOpeningsForUser(userId)

		// sc.muRegUsers.RUnlock()
		// sc.muRecentCommitments.RUnlock()
	}
}

// keeps track if we fail to process an opening for user due to missing data
// anything can be missing: rbeSecret, other user's rbeId, commitments, userOpening, myOpening
func (sc *SecretManagerClient) trackErroredWaiting(userId string, commRevision string) {
	log.Infof("[dev] tracking errored waiting for userId: %s, commRevision: %s", userId, commRevision)
	sc.muErroredWaiting.Lock()
	defer sc.muErroredWaiting.Unlock()
	if sc.erroredWaiting == nil {
		sc.erroredWaiting = make(map[string]map[string]bool)
	}
	if sc.erroredWaiting[commRevision] == nil {
		sc.erroredWaiting[commRevision] = make(map[string]bool)
	}
	sc.erroredWaiting[commRevision][userId] = true

	log.Infof("[dev] errored waiting map now: %+v", sc.erroredWaiting)

	defer func() {
		time.AfterFunc(1*time.Second, sc.retryOneFromErroredWaiting)
	}()
}

func (sc *SecretManagerClient) retryAllOpeningsForUser(newUserId string) {
	log.Infof("[dev] retrying all openings for userId: %s", newUserId)

	sc.muErroredWaiting.Lock()
	defer sc.muErroredWaiting.Unlock()
	for commRevision, userMap := range sc.erroredWaiting {
		for userId := range userMap {
			if userId == newUserId && userMap[userId] {
				// found one to retry
				log.Infof("[dev] retrying for userId: %s, commRevision: %s", userId, commRevision)
				// add to the queue
				sc.receivedOpeningKeyChan <- fmt.Sprintf("%s/%s/%s", kconstants.RBE_OPENINGS_KEY, commRevision, userId)
				// remove from the map - if this fails again it'll be added back
				sc.erroredWaiting[commRevision][userId] = false
			}
		}
	}
}

func (sc *SecretManagerClient) retryOneFromErroredWaiting() {
	log.Infof("[dev] retrying one from errored waiting map")
	var keyToRetry string

	sc.muErroredWaiting.Lock()
	for commRevision, userMap := range sc.erroredWaiting {
		for userId := range userMap {
			if userMap[userId] {
				// found one to retry
				log.Infof("[dev] retrying for userId: %s, commRevision: %s", userId, commRevision)
				// add to the queue
				keyToRetry = fmt.Sprintf("%s/%s/%s", kconstants.RBE_OPENINGS_KEY, commRevision, userId)
				// remove from the map - if this fails again it'll be added back
				sc.erroredWaiting[commRevision][userId] = false

				break
			}
		}
		// only retry one at a time
		if keyToRetry != "" {
			break
		}
	}
	sc.muErroredWaiting.Unlock()

	if keyToRetry != "" {
		sc.receivedOpeningKeyChan <- keyToRetry
	} else {
		log.Infof("[dev] no more errored waiting entries to retry, erroredWaiting map: %+v", sc.erroredWaiting)
	}
}

func (sc *SecretManagerClient) getIfRbeSecretExists(userId string, commRevision string) (*security.RbeSecretItem, error) {
	rbeSecret := sc.GetRbeCachedSecret(security.WorkloadRbeIdentityCertResourceName)
	if rbeSecret == nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("rbeSecret is nil")
	} else {
		return rbeSecret, nil
	}
}

func (sc *SecretManagerClient) getIfOtherUserExists(userId string, commRevision string) (*security.RbeId, error) {
	sc.muRegUsers.RLock()
	defer sc.muRegUsers.RUnlock()

	otherUserRbeId := &security.RbeId{}
	otherUser, exists := sc.regUsers[fmt.Sprintf("%s/%s", kconstants.RBE_USER_PREFIX, userId)]

	if !exists {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("other user rbeId not found for user id: %s", userId)
	} else {
		port, err := strconv.Atoi(otherUser.Port)
		if err != nil {
			// unlikely error so not tracking in erroredWaiting map
			return nil, fmt.Errorf("err on converting port to int: %v", err)
		}
		otherUserRbeId = &security.RbeId{
			Token: otherUser.Token,
			Ip:    otherUser.Ip,
			Port:  port,
		}
	}
	return otherUserRbeId, nil
}

func (sc *SecretManagerClient) getIfMyOpeningExists(userId string, commRevision string) ([]*bls.G1, error) {
	sc.muUserOpenings2.RLock()
	defer sc.muUserOpenings2.RUnlock()

	userIdInt, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("error converting userId to int64: %v", err)
	}

	userOpenings, exists := sc.userOpenings2[userIdInt]
	if !exists {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("user openings not found for user id: %s", userId)
	}

	commRevInt, err := strconv.ParseInt(commRevision, 10, 64)
	if err != nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("error converting commRevision to int64: %v", err)
	}

	opening, exists := userOpenings[commRevInt]
	if !exists {
		// try and get the opening with the latest revision
		var maxRev int64 = -1
		for rev := range userOpenings {
			if rev > maxRev {
				maxRev = rev
			}
		}
		if maxRev != -1 {
			opening, exists = userOpenings[maxRev]
			if !exists {
				go sc.trackErroredWaiting(userId, commRevision)
				return nil, fmt.Errorf("opening not found for user id: %s, commRevision: %s", userId, commRevision)
			}
			log.Warnf("[dev] opening not found for user id: %s, commRevision: %s, using latest revision: %d instead",
				userId, commRevision, maxRev)
		} else {
			go sc.trackErroredWaiting(userId, commRevision)
			return nil, fmt.Errorf("opening not found for user id: %s, commRevision: %s", userId, commRevision)
		}
	}

	defer func() {
		// print all the openings history for this user in a single line
		revisions := []string{}
		for rev := range userOpenings {
			revisions = append(revisions, fmt.Sprintf("%d", rev))
		}
		log.Infof("[dev] my openings revisions for userId: %s: %s", userId, strings.Join(revisions, ","))
	}()

	return opening, nil
}

func (sc *SecretManagerClient) getIfOpeningExists(userId string, commRevision string) ([]*bls.G1, error) {
	sc.muUserOpenings2.RLock()
	defer sc.muUserOpenings2.RUnlock()

	userIdInt, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("error converting userId to int64: %v", err)
	}

	userOpenings, exists := sc.userOpenings2[userIdInt]
	if !exists {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("user openings not found for user id: %s", userId)
	}

	commRevInt, err := strconv.ParseInt(commRevision, 10, 64)
	if err != nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("error converting commRevision to int64: %v", err)
	}

	opening, exists := userOpenings[commRevInt]
	if !exists {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("opening not found for user id: %s, commRevision: %s", userId, commRevision)
	}

	defer func() {
		// print the entire openings history for this user in a single line
		revisions := []string{}
		for rev := range userOpenings {
			revisions = append(revisions, fmt.Sprintf("%d", rev))
		}
		log.Infof("[dev] openings revisions for userId: %s: %s", userId, strings.Join(revisions, ","))
	}()

	return opening, nil
}

func (sc *SecretManagerClient) getCommitmentForUser(blockId int, userId string,
	commRevision string) (*bls.G1, error) {
	sc.muCommitmentsHistory.RLock()
	defer sc.muCommitmentsHistory.RUnlock()

	commitmentRevs, exists := sc.commitmentsHistory[int64(blockId)]
	if !exists {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("no commitments found for block id: %d", blockId)
	}

	commRevInt, err := strconv.ParseInt(commRevision, 10, 64)
	if err != nil {
		go sc.trackErroredWaiting(userId, commRevision)
		return nil, fmt.Errorf("error converting commRevision to int64: %v", err)
	}

	commitment, exists := commitmentRevs[commRevInt]
	if !exists {
		// try and get the commitment with the latest revision
		var maxRev int64 = -1
		for rev := range commitmentRevs {
			if rev > maxRev {
				maxRev = rev
			}
		}
		if maxRev != -1 {
			commitment, exists = commitmentRevs[maxRev]
			if !exists {
				go sc.trackErroredWaiting(userId, commRevision)
				return nil, fmt.Errorf("no commitment found for block id: %d, commRevision: %s", blockId, commRevision)
			}
			log.Warnf("[dev] commitment not found for block id: %d, commRevision: %s, using latest revision: %d instead",
				blockId, commRevision, maxRev)
		} else {
			go sc.trackErroredWaiting(userId, commRevision)
			return nil, fmt.Errorf("no commitment found for block id: %d, commRevision: %s", blockId, commRevision)
		}
	}

	defer func() {
		// print the entire commitments history for this block in a single line
		revisions := []string{}
		for rev := range commitmentRevs {
			revisions = append(revisions, fmt.Sprintf("%d", rev))
		}
		log.Infof("[dev] commitment revisions for userId: %s blockId %d: %s", userId, blockId, strings.Join(revisions, ","))
	}()

	return commitment, nil
}

func (sc *SecretManagerClient) updatePodValidationWithOpeningUtil(userId string,
	commRevision string, commRevInt int64) {
	// get current user from rbeSecret
	rbeSecret, err := sc.getIfRbeSecretExists(userId, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}
	thisUser := rbeSecret.User
	idThisUser := strconv.Itoa(thisUser.Id())

	otherUserRbeId, err := sc.getIfOtherUserExists(userId, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}
	idOtherUser := int(otherUserRbeId.ToNumber())

	// get the userOpenings
	otherUserOpening, err := sc.getIfOpeningExists(userId, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}

	myOpening, err := sc.getIfMyOpeningExists(idThisUser, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}

	// derive the key from rbeId (ip|tokenHash)
	tokenBytes := []byte(otherUserRbeId.Token)
	tokenHex := fmt.Sprintf("%x", md5.Sum(tokenBytes))

	key := fmt.Sprintf("%s|%s", otherUserRbeId.Ip, tokenHex)

	// now for the commitments
	commitments := []*bls.G1{}
	pp := new(rbe.PublicParams)

	sc.muRbePp.RLock()
	if sc.rbePp != nil {
		pp = sc.rbePp
		commitments = sc.rbePp.Commitments
	}
	defer sc.muRbePp.RUnlock()

	thisUserBlock := pp.IdToBlock(thisUser.Id())
	commitmentThisUser, err := sc.getCommitmentForUser(thisUserBlock, idThisUser, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}
	commitments[thisUserBlock] = commitmentThisUser

	otherUserBlock := pp.IdToBlock(idOtherUser)
	commitmentOtherUser, err := sc.getCommitmentForUser(otherUserBlock, userId, commRevision)
	if err != nil {
		log.Errorf("[dev] cannot update pod validity map, %v", err)
		return
	}
	commitments[otherUserBlock] = commitmentOtherUser

	thisUser = rbeSecret.User
	thisUser.Update(commitments, myOpening)

	pp.Commitments = commitments

	// encrypt and decrypt a random nonce
	nonce := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	nonceHash := kcUtil.HashToGt(nonce)

	result := false
	if idOtherUser == thisUser.Id() {
		result = true
	} else {
		log.Infof("[dev] id of this user: %d vs id of other user: %d", thisUser.Id(), idOtherUser)

		cipherText := thisUser.Encrypt(idOtherUser, nonceHash)

		sk := new(bls.Scalar)
		sk.SetUint64(uint64(otherUserRbeId.SecretKey()))

		otherUser := rbe.NewUserWithSecret(pp, idOtherUser, sk)

		otherUser.Update(commitments, otherUserOpening)

		decryptedNonce, err := otherUser.Decrypt(cipherText)
		if err != nil {
			log.Warnf("[dev] failed to decrypt nonce for user %d: %v", idOtherUser, err)
			go sc.trackErroredWaiting(userId, commRevision)
		} else {
			result = nonceHash.IsEqual(decryptedNonce)
		}
	}

	sc.muPodsValidityMap2.Lock()
	defer sc.muPodsValidityMap2.Unlock()
	if sc.podsValidityMap2 == nil {
		sc.podsValidityMap2 = make(map[string]bool)
	}
	sc.podsValidityMap2[key] = result

	go sc.addOtherUserAsVerified(result, int64(idOtherUser), thisUser.Id())
	go sc.ackOpeningProcessed(result, int64(idOtherUser), thisUser.Id())

	log.Infof("[dev] updated pod validity map2 with key: %s, result: %v", key, result)

	// jsonString, err := json.Marshal(mergedPodValidityMap)
	jsonString, err := json.Marshal(sc.podsValidityMap2)
	if err != nil {
		log.Errorf("[dev] err on marshalling pod validity map to json: %v", err)
		return
	} else {
		log.Infof("[dev] pod validity map json string: %s", string(jsonString))
	}

	err = os.WriteFile("/etc/istio/proxy/pod_validity_data.json", jsonString, 0644)
	if err != nil {
		log.Errorf("[dev] err on WriteFile: %v", err)
		return
	}

	go sc.retryOneFromErroredWaiting()
}

// other services also verify my update and let me know once they are ready
func (sc *SecretManagerClient) AreOthersReady(myUserId int) {
	if sc.areOthersReady.Load() != nil && sc.areOthersReady.Load().(bool) {
		log.Infof("[dev] Others are already ready, skipping check")
		return
	}

	sc.muUserIdsBeforeMe.RLock()
	defer sc.muUserIdsBeforeMe.RUnlock()

	sc.muUsersFromLog.RLock()
	defer sc.muUsersFromLog.RUnlock()

	log.Infof("[dev] checking if others are ready")

	ready := true
	loggedUsersMap := map[int64]bool{}
	for _, userId := range sc.usersFromLog {
		loggedUsersMap[userId] = true
	}

	for _, userId := range sc.userIdsBeforeMe {
		_, exists := loggedUsersMap[userId]
		if !exists {
			ready = false
			log.Infof("[dev] Others aren't ready for me yet, user id %d is not in the log", userId)
			break
		}
	}

	if ready {
		log.Infof("[dev] Other services are ready for me now!")
		sc.areOthersReady.Store(true)
		sc.areOthersReadyChan <- true
	}
}

// user is ready once it verifies openings from all existing old users
func (sc *SecretManagerClient) AmIReady(myUserId int) {
	if sc.amIReady.Load() != nil && sc.amIReady.Load().(bool) {
		log.Infof("[dev] I am already ready, skipping check")
		return
	}

	sc.muUserIdsBeforeMe.RLock()
	defer sc.muUserIdsBeforeMe.RUnlock()

	sc.muValidUsersMap.RLock()
	defer sc.muValidUsersMap.RUnlock()

	log.Infof("[dev] checking if I am ready")

	ready := true
	for _, userId := range sc.userIdsBeforeMe {
		valid, exists := sc.validUsersMap[userId]
		if !valid || !exists {
			ready = false
			log.Infof("[dev] I am not ready yet, user id %d is not verified yet", userId)
			break
		}
	}

	if ready {
		log.Infof("[dev] I am ready now!")
		sc.amIReady.Store(true)
		sc.readyChan <- true

		prefixString := fmt.Sprintf("READY,%d", myUserId)
		err := sc.kcClient.MarkReady(int64(myUserId), prefixString)
		if err != nil {
			log.Errorf("[dev] failed to mark myself as ready in key curator: %v", err)
		} else {
			log.Infof("[dev] marked myself as ready in key curator")
		}
	} else {
		log.Infof("[dev] current valid users map: %+v", sc.validUsersMap)
	}
}

func (sc *SecretManagerClient) addOtherUserAsVerified(result bool, otherUserId int64,
	myUserId int) {
	// if the pod is already ready, skip
	if sc.amIReady.Load() != nil && sc.amIReady.Load().(bool) {
		log.Infof("[dev] I am already ready, skipping adding user %d as verified", otherUserId)
		return
	}

	// if result is false, skip
	if !result {
		log.Infof("[dev] user %d is not ready, result is false", otherUserId)
		return
	}

	sc.muUserIdsBeforeMe.RLock()

	if len(sc.userIdsBeforeMe) == 0 {
		log.Infof("[dev] user %d is ready, no other users before it", otherUserId)
	} else {
		if slices.Contains(sc.userIdsBeforeMe, otherUserId) {
			log.Infof("[dev] user %d is ready, it is in the list of users before it", otherUserId)
			sc.muValidUsersMap.Lock()

			log.Infof("[dev] adding user id %d to valid users map", otherUserId)
			sc.validUsersMap[otherUserId] = true

			sc.muValidUsersMap.Unlock()
		} else {
			log.Infof("[dev] user %d is ready, it is not in the list of users before it", otherUserId)
		}
	}
	sc.muUserIdsBeforeMe.RUnlock()

	defer func() {
		go sc.AmIReady(myUserId)
	}()
}

// sends a notification to key curator that opening for otherUserId has been processed
// by this user (myUserId)
func (sc *SecretManagerClient) ackOpeningProcessed(result bool, otherUserId int64,
	myUserId int) {
	// if result is false, skip
	if !result {
		log.Infof("[dev] user %d is not ready, result is false", otherUserId)
		return
	}

	prefixString := fmt.Sprintf("ACK_OPENING,%d,%d", otherUserId, myUserId)
	err := sc.kcClient.MarkReady(int64(myUserId), prefixString)
	if err != nil {
		log.Errorf("[dev] failed to send ACK_OPENING in key curator: %v", err)
	} else {
		log.Infof("[dev] send ACK_OPENING key curator")
	}

	// also store ack for processed opening in etcd
	key := fmt.Sprintf("%s/%d/verified-by/%d", kconstants.RBE_LOG_KEY, otherUserId, myUserId)
	_, err = etcdutil.PutKVToEtcd(sc.etcdClient, key, []byte("true"))
	if err != nil {
		log.Errorf("[dev] failed to store etcd log: %v", err)
	} else {
		log.Infof("[dev] stored to etcd log: otherUserId(%d) was verified by userId(%d)",
			otherUserId, myUserId)
	}
}

func (sc *SecretManagerClient) UpdatePodValidationWithOpening() {
	for keyStr := range sc.receivedOpeningKeyChan {
		log.Infof("[dev] UpdatePodValidationWithOpening: received key: %s from channel", keyStr)

		// keyStr has format: rbe-system/openings/<commitments-revision>/<user-id>
		parts := strings.Split(keyStr, "/")
		if len(parts) != 4 {
			log.Errorf("[dev] invalid key format for user openings: %s", keyStr)
			continue
		}
		userId := parts[3]
		commRevision := parts[2]

		commRevInt, err := strconv.ParseInt(commRevision, 10, 64)
		if err != nil {
			log.Errorf("[dev] invalid commitments revision: %s", commRevision)
			continue
		}

		sc.updatePodValidationWithOpeningUtil(userId, commRevision, commRevInt)
	}
}

func (sc *SecretManagerClient) updatePodValidationMap() error {
	// first key is commitments revision
	// second key is pod identifier (ip|tokenHash)
	podsValidity := map[string]map[string]bool{}
	jsonString := []byte{}

	allRevisions := []int64{}
	sc.muRecentCommitments.RLock()
	for rev := range sc.recentCommitments {
		allRevisions = append(allRevisions, rev)
	}
	sc.muRecentCommitments.RUnlock()

	log.Infof("[dev] all commitments revisions in recentCommitments map: %+v", allRevisions)

	// for each commitments revision, we compute the pod validity map
	for _, rev := range allRevisions {
		podsValidityRev := map[string]bool{}

		rbeSecret := sc.GetRbeCachedSecret(security.WorkloadRbeIdentityCertResourceName)

		if rbeSecret != nil {
			allRbeIds := []*security.RbeId{}

			sc.muRegUsers.RLock()
			for _, v := range sc.regUsers {
				port, err := strconv.Atoi(v.Port)
				if err != nil {
					return fmt.Errorf("[dev] err on converting port to int: %v", err)
				}

				rbeId := &security.RbeId{
					Token: v.Token,
					Ip:    v.Ip,
					Port:  port,
				}
				allRbeIds = append(allRbeIds, rbeId)
			}
			sc.muRegUsers.RUnlock()

			for _, rbeId := range allRbeIds {
				if rbeId == nil {
					continue
				}
				tokenBytes := []byte(rbeId.Token)
				tokenHex := fmt.Sprintf("%x", md5.Sum(tokenBytes))

				key := fmt.Sprintf("%s|%s", rbeId.Ip, tokenHex)
				// key := fmt.Sprintf("%s|%s", rbeId.Ip, rbeId.Token)

				// podsValidity[key] = sc.checkPodValidity(rbeId, rbeSecret, pp)
				podsValidityRev[key] = sc.checkPodValidity(rbeId, rbeSecret, rev)
			}
		} else {
			return fmt.Errorf("[dev] rbeSecret is nil, cannot update pod validity map")
		}

		podsValidity[strconv.FormatInt(rev, 10)] = podsValidityRev
	}

	log.Infof("[dev] printing pod validity map for all pods")
	log.Infof("%+v", podsValidity)

	// save the pod validity map to a json file
	jsonString, err := json.Marshal(podsValidity)
	if err != nil {
		return fmt.Errorf("[dev] err on marshalling pod validity map to json: %v", err)
	} else {
		log.Infof("[dev] pod validity map json string: %s", string(jsonString))
	}

	// even if there's an error, we save an empty map so the json file is always written
	defer func() {
		err = os.WriteFile("/etc/istio/proxy/pod_validity_data.json", jsonString, 0644)
		if err != nil {
			log.Errorf("[dev] err on WriteFile: %v", err)
		}

		// TODO: register the pod validity map in the secret cache
		// sc.RegisterPodValidityMap(podsValidity)
	}()

	return nil
}

func (sc *SecretManagerClient) checkPodValidity(rbeId *security.RbeId,
	rbeSecret *security.RbeSecretItem, rev int64) bool {
	commitments := []*bls.G1{}
	userOpening := []*bls.G1{}
	pp := new(rbe.PublicParams)

	sc.muRecentCommitments.RLock()
	if sc.rbePp != nil {
		commitments = sc.recentCommitments[rev]
		pp = sc.rbePp
		log.Infof("[dev] commitments length: %d", len(commitments))
	}
	sc.muRecentCommitments.RUnlock()

	otherRbeId := &security.RbeId{
		Ip:    rbeId.Ip,
		Port:  rbeId.Port,
		Token: rbeId.Token,
	}

	idOtherUser := int(otherRbeId.ToNumber())

	otherUserOpening := []*bls.G1{}
	sc.muUserOpenings.RLock()
	revStr := strconv.FormatInt(rev, 10)
	if sc.userOpenings != nil && sc.userOpenings[revStr] != nil {
		id := strconv.Itoa(rbeSecret.User.Id())
		userOpening = sc.userOpenings[revStr][id]
		otherUserOpening = sc.userOpenings[revStr][strconv.Itoa(idOtherUser)]
	}
	sc.muUserOpenings.RUnlock()

	if len(userOpening) != 0 {
		rbeSecret.User.Update(commitments, userOpening)
	}

	log.Infof("[dev] length of commitments: %d, length of otherUserOpening: %d",
		len(commitments), len(otherUserOpening))
	if len(commitments) == 0 || len(otherUserOpening) == 0 {
		log.Errorf("[dev] commitments or userOpening is empty, cannot update pod validity map")
		return false
	}

	thisUser := rbeSecret.User

	if len(pp.Commitments) == 0 {
		log.Errorf("[dev] commitments is empty cannot check pod validity")
		return false
	}

	nonce := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	nonceHash := kcUtil.HashToGt(nonce)

	if idOtherUser == thisUser.Id() {
		return true
	}

	log.Infof("[dev] id of this user: %d vs id of other user: %d", thisUser.Id(), idOtherUser)

	cipherText := thisUser.Encrypt(idOtherUser, nonceHash)

	sk := new(bls.Scalar)
	sk.SetUint64(uint64(otherRbeId.SecretKey()))

	otherUser := rbe.NewUserWithSecret(pp, idOtherUser, sk)

	otherUser.Update(commitments, otherUserOpening)

	decryptedNonce, err := otherUser.Decrypt(cipherText)
	if err != nil {
		log.Errorf("[dev] failed to decrypt nonce: %v", err)
		return false
	}

	return nonceHash.IsEqual(decryptedNonce)
}

func (sc *SecretManagerClient) isPPAvailable() bool {
	sc.muRbePp.RLock()
	defer sc.muRbePp.RUnlock()
	return sc.rbePp != nil
}

func (sc *SecretManagerClient) userExists(keyStr string) bool {
	sc.muRegUsers.RLock()
	defer sc.muRegUsers.RUnlock()

	_, exists := sc.regUsers[keyStr]
	return exists
}

func (sc *SecretManagerClient) proofExists(keyStr string) bool {
	sc.muUserRegProofs.RLock()
	defer sc.muUserRegProofs.RUnlock()

	_, exists := sc.userRegProofs[keyStr]
	return exists
}

func (sc *SecretManagerClient) attestationExists(keyStr string) bool {
	sc.muUserRegAttestations.RLock()
	defer sc.muUserRegAttestations.RUnlock()

	_, exists := sc.userRegAttestations[keyStr]
	return exists
}

func (sc *SecretManagerClient) verifyRbeUser(keyStr string, userId string) (bool, error) {

	// check if we have required data
	if !sc.isPPAvailable() {
		return false, fmt.Errorf("[dev] public parameters not available yet")
	}

	if !sc.userExists(keyStr) {
		return false, fmt.Errorf("[dev] user with key %s not found in registered users", keyStr)
	}

	isRbeProofEnabled := kcUtil.IsRbeProofEnabled()
	if isRbeProofEnabled && !sc.proofExists(keyStr) {
		return false, fmt.Errorf("[dev] proof for user with key %s not found in registered user proofs", keyStr)
	}

	isAttestationEnabled := kcUtil.IsAttestationEnabled()
	if isAttestationEnabled && !sc.attestationExists(keyStr) {
		return false, fmt.Errorf("[dev] attestation for user with key %s not found in registered user attestations", keyStr)
	}

	sc.muRbePp.RLock()
	defer sc.muRbePp.RUnlock()

	sc.muRegUsers.RLock()
	defer sc.muRegUsers.RUnlock()

	sc.muUserRegProofs.RLock()
	defer sc.muUserRegProofs.RUnlock()

	sc.muUserRegAttestations.RLock()
	defer sc.muUserRegAttestations.RUnlock()

	sc.muCommitmentsHistory.RLock()
	defer sc.muCommitmentsHistory.RUnlock()

	proof := sc.userRegProofs[keyStr]
	user := sc.regUsers[keyStr]
	pubKey := user.PublicKey
	id := int(user.Id)

	// membership proof verification
	if isRbeProofEnabled {
		isVerified := rbe.VerifyMembership(sc.rbePp, id, pubKey, proof)
		if isVerified {
			log.Infof("[dev] membership verified successfully for %s", keyStr)
		} else {
			// if verification fails, we go test with old commitments
			log.Infof("[dev] membership verification failed for user %d with current commitments, trying with older commitments", id)

			block := sc.rbePp.IdToBlock(id)
			currentCommitment := sc.rbePp.Commitments[block]

			isVerifiedWithOldCommitments := false
			blockCommitments, exists := sc.commitmentsHistory[int64(block)]
			if exists {
				for _, oldCommitment := range blockCommitments {
					if oldCommitment == nil {
						continue
					}
					sc.rbePp.Commitments[block] = oldCommitment
					isVerifiedWithOldCommitments = rbe.VerifyMembership(sc.rbePp, id, pubKey, proof)
					if isVerifiedWithOldCommitments {
						log.Infof("[dev] membership verified successfully for %s with older commitments", keyStr)
						break
					} else {
						log.Infof("[dev] membership verification failed for %s with older commitments", keyStr)
					}
				}
			} else {
				// we don't yet have older commitments for this block, so we simply fail
				log.Errorf("[dev] no older commitments found for block %d", block)
			}
			// restore current commitment for this block
			sc.rbePp.Commitments[block] = currentCommitment

			if isVerifiedWithOldCommitments {
				log.Infof("[dev] membership verified successfully for %s with older commitments", keyStr)
			} else {
				return false, fmt.Errorf("[dev] membership verification failed for %s", keyStr)
			}
		}
	} else {
		log.Infof("[dev] RBE proof verification for %s is disabled", keyStr)
	}

	// attestation verification
	if isAttestationEnabled {
		pbProof := &proto.G1{Point: proof.Bytes()}
		pbProofBytes, err := gproto.Marshal(pbProof)
		if err != nil {
			log.Errorf("[dev] error marshalling proof: %v", err)
		}
		regMsg := &kproto.RegisterRequest{
			Id:        user.Id,
			Ip:        user.Ip,
			Port:      user.Port,
			Token:     user.Token,
			PublicKey: &proto.G1{Point: pubKey.Bytes()},
		}

		xiProto := []*proto.G1{}
		for _, xiElem := range user.Xi {
			if xiElem == nil {
				xiProto = append(xiProto, nil)
			} else {
				xiProto = append(xiProto, &proto.G1{Point: xiElem.Bytes()})
			}
		}
		regMsg.Xi = xiProto

		regMsgBytes, err := gproto.Marshal(regMsg)
		if err != nil {
			log.Errorf("[dev] error marshalling RegisterRequest: %v", err)
		}

		attestUserData := append(regMsgBytes, pbProofBytes...)

		attestation := sc.userRegAttestations[keyStr]
		if trincutil.DoVerifyCounter(attestUserData, attestation) {
			if sc.lastCounterValue.Load() != nil &&
				attestation.Counter <= sc.lastCounterValue.Load().(uint64) {
				log.Errorf("[dev] attestation has a stale counter value: %d, last counter: %d",
					attestation.Counter, sc.lastCounterValue.Load().(uint64))
			} else {
				sc.lastCounterValue.Store(attestation.Counter)
			}
		} else {
			return false, fmt.Errorf("[dev] attestation has an invalid signature")
		}
	} else {
		log.Infof("[dev] attestation verification for %s is disabled", keyStr)
	}

	return true, nil
}

// validates the RBE proof and attestation info of a registered user
func (sc *SecretManagerClient) VerifyRegisteredUser() {
	for keyStr := range sc.userVerificationChan {
		log.Infof("[dev] VerifyRegisteredUser: received key: %s from channel", keyStr)

		// keyStr has format: rbe-user/<user-id>
		parts := strings.Split(keyStr, "/")
		if len(parts) != 2 {
			log.Errorf("[dev] invalid key format for user key: %s", keyStr)
			continue
		}
		userId := parts[1]
		log.Infof("[dev] verifying user with id: %s", userId)

		verified, err := sc.verifyRbeUser(keyStr, userId)
		if err != nil {
			log.Errorf("[dev] error verifying RBE user %s: %v", userId, err)
			sc.unverifiedUsersList = append(sc.unverifiedUsersList, keyStr)
		}
		if verified {
			log.Infof("[dev] RBE user %s verified successfully", userId)
			go sc.markUserAsVerified(userId)
			go sc.retryOneUnverifiedUser()
		} else {
			log.Infof("[dev] RBE user %s verification failed", userId)
		}
	}
}

func (sc *SecretManagerClient) retryOneUnverifiedUser() {
	if len(sc.unverifiedUsersList) > 0 {
		first, rest := sc.unverifiedUsersList[0], sc.unverifiedUsersList[1:]
		sc.unverifiedUsersList = rest
		log.Infof("[dev] re-queuing unverified user key: %s for verification", first)
		sc.userVerificationChan <- first
	} else {
		log.Infof("[dev] all users verified now!")
	}
}

func (sc *SecretManagerClient) markUserAsVerified(userId string) {
	sc.muIsUserVerified.Lock()
	defer sc.muIsUserVerified.Unlock()

	if sc.isUserVerified == nil {
		sc.isUserVerified = make(map[string]bool)
	}
	sc.isUserVerified[userId] = true

	log.Infof("[dev] isUserVerified map: %+v", sc.isUserVerified)
}

// value is irrelevant, we're only interested if the key was created
func (sc *SecretManagerClient) handleRbeLogUpdate(keyStr string) error {

	// keyStr has format: rbe-log/<my-user-id>/verified-by/<other-user-id>
	parts := strings.Split(keyStr, "/")
	if len(parts) != 4 {
		return fmt.Errorf("[dev] invalid key format for rbe-log key: %s", keyStr)
	}

	myUserIdStr := parts[1]
	myUserId, err := strconv.ParseInt(myUserIdStr, 10, 64)
	if err != nil {
		return fmt.Errorf("[dev] invalid my user id in rbe-log key: %s", myUserIdStr)
	}

	otherUserIdStr := parts[3]
	otherUserId, err := strconv.ParseInt(otherUserIdStr, 10, 64)
	if err != nil {
		return fmt.Errorf("[dev] invalid other user id in rbe-log key: %s", otherUserIdStr)
	}

	log.Infof("[dev] received rbe-log update: my-user-id(%s) was verified by other-user-id(%d)",
		parts[1], otherUserId)

	sc.muUsersFromLog.Lock()
	if sc.usersFromLog == nil {
		sc.usersFromLog = make([]int64, 0)
	}
	sc.usersFromLog = append(sc.usersFromLog, otherUserId)
	sc.muUsersFromLog.Unlock()

	defer func() {
		go sc.AreOthersReady(int(myUserId))
	}()

	return nil
}

func (sc *SecretManagerClient) handleRegisteredUserUpdate(keyStr string, value []byte) error {
	regUserWithProofReq := &kcUtil.RegisteredUserWithProof{}
	err := json.Unmarshal([]byte(value), regUserWithProofReq)
	if err == nil {
		regRequestBytes := regUserWithProofReq.RequestBytes

		req := &kproto.RegisterRequest{}
		err := gproto.Unmarshal([]byte(regRequestBytes), req)
		if err != nil {
			return fmt.Errorf("[dev] error unmarshalling RegisterRequest for user %d: %v", req.GetId(), err)
		}

		publicKey := new(bls.G1)
		err = publicKey.SetBytes(req.PublicKey.GetPoint())
		if err != nil {
			return fmt.Errorf("[dev] error setting public key for user %d: %v", req.Id, err)
		}

		xi := make([]*bls.G1, len(req.GetXi()))
		for i, v := range req.GetXi() {
			if len(v.GetPoint()) == 0 {
				xi[i] = nil
			} else {
				xg1 := new(bls.G1)
				xg1.SetBytes(v.GetPoint())
				xi[i] = xg1
			}
		}

		registeredUser := &RegisteredUser{
			Id:        req.Id,
			Ip:        req.Ip,
			Port:      req.Port,
			Token:     req.Token,
			Xi:        xi,
			PublicKey: publicKey,
		}

		sc.muRegUsers.Lock()
		defer sc.muRegUsers.Unlock()

		if sc.regUsers == nil {
			sc.regUsers = make(map[string]*RegisteredUser)
		}
		sc.regUsers[keyStr] = registeredUser

		// proof
		proofBytes := regUserWithProofReq.ProofBytes
		proofProto := &proto.G1{}
		err = gproto.Unmarshal([]byte(proofBytes), proofProto)
		if err != nil {
			return fmt.Errorf("[dev] error unmarshalling proof for user %s: %v", keyStr, err)
		}
		proof := new(bls.G1)
		err = proof.SetBytes(proofProto.GetPoint())
		if err != nil {
			return fmt.Errorf("[dev] error setting proof for user %s: %v", keyStr, err)
		}
		// save proof
		sc.muUserRegProofs.Lock()
		if sc.userRegProofs == nil {
			sc.userRegProofs = make(map[string]*bls.G1)
		}
		sc.userRegProofs[keyStr] = proof
		sc.muUserRegProofs.Unlock()

		// attestation
		attestationBytes := regUserWithProofReq.AttestationBytes
		attestationProto := &kproto.CounterAttestation{}
		err = gproto.Unmarshal([]byte(attestationBytes), attestationProto)
		if err != nil {
			return fmt.Errorf("[dev] error unmarshalling attestation for user %s: %v", keyStr, err)
		}
		attestation := trincutil.AttestationFromProto(attestationProto)

		// save attestation data
		sc.muUserRegAttestations.Lock()
		if sc.userRegAttestations == nil {
			sc.userRegAttestations = make(map[string]*trinc.CounterAttestation)
		}
		sc.userRegAttestations[keyStr] = attestation
		sc.muUserRegAttestations.Unlock()

		log.Infof("[dev] saved registered user for key: %s", keyStr)

		go sc.retryAllOpeningsForUser(strconv.FormatInt(req.Id, 10))

		// enqueue the user for verifying RBE proof and attestation
		sc.userVerificationChan <- keyStr
	} else {
		return fmt.Errorf("[dev] error unmarshalling request for user %s: %v", keyStr, err)
	}

	return nil
}

func (sc *SecretManagerClient) readPublicParamsFromFile() error {
	pp, err := keycurator.TryParseRbePpFromFile()
	if err != nil {
		return err
	} else {
		sc.muRbePp.Lock()
		defer sc.muRbePp.Unlock()

		sc.rbePp = pp
		log.Infof("[dev] restored rbe public params from file before fetching from etcd")
	}
	return nil
}

// fetches and listens for updates to commitments and user openings from etcd
func (sc *SecretManagerClient) GetWatchSystemParams() {
	err := sc.readPublicParamsFromFile()
	if err != nil {
		log.Fatalf("[dev] failed to read public params from file: %v", err)
	}

	sysParamsRes, err := sc.etcdClient.Get(context.Background(), kconstants.RBE_PP_COMMITMENTS_KEY, clientv3.WithPrefix(),
		clientv3.WithSort(clientv3.SortByModRevision, clientv3.SortAscend))
	if err != nil {
		log.Errorf("[dev] failed to fetch commitments from etcd: %v", err)
		return
	}

	currentRevision := sysParamsRes.Header.Revision

	log.Infof("[dev] fetched %d keys from etcd", len(sysParamsRes.Kvs))
	for _, kv := range sysParamsRes.Kvs {
		value := kv.Value
		key := kv.Key
		keyStr := string(key)

		log.Infof("[dev] received key: %s, len(value): %d", key, len(value))
		log.Infof("[dev] revisions for commitment key (%s): CreateRevision %d, ModRevision: %d", key, kv.CreateRevision, kv.ModRevision)

		if strings.HasPrefix(keyStr, kconstants.RBE_PP_COMMITMENTS_KEY) {
			// we're using WithSort above, so commitments should arrive after
			// we've received the initial public params and setup the commitments slice

			err := sc.handleCommitmentsUpdate(keyStr, value, kv.ModRevision)
			if err != nil {
				log.Errorf("[dev] failed to handle commitments update: %v", err)
			} else {
				// now use updates after this ModRevision only
				currentRevision = kv.ModRevision
			}
		}
		// openings will be handled separately
	}

	log.Infof("current revision for system params is %d", currentRevision)

	// watch for updates to commitments
	go func() {
		rch := sc.etcdClient.Watch(context.Background(), kconstants.RBE_PP_COMMITMENTS_KEY,
			clientv3.WithPrefix(), clientv3.WithRev(currentRevision+1))
		for commitResp := range rch {
			if commitResp.Canceled {
				log.Warnf("[dev] etcd watch canceled: %v", commitResp.Err())
				return
			}

			log.Infof("[dev] revision for commitments? %d", commitResp.Header.Revision)
			for _, ev := range commitResp.Events {
				log.Infof("[dev] type: %s, key: %q\n", ev.Type, ev.Kv.Key)

				if ev.Type == clientv3.EventTypePut {
					key := string(ev.Kv.Key)
					value := ev.Kv.Value

					log.Infof("[dev] revisions for commitment key (%s): CreateRevision %d, ModRevision: %d", key, ev.Kv.CreateRevision, ev.Kv.ModRevision)
					err := sc.handleCommitmentsUpdate(key, value, ev.Kv.ModRevision)
					if err != nil {
						log.Errorf("[dev] failed to handle commitments update: %v", err)
					}
				}
			}
		}
	}()

	// updates to openings are handled separately
}

func (sc *SecretManagerClient) ListWatchOpeningsUpdate(currentRevision int64) {
	openingsRes, err := sc.etcdClient.Get(context.Background(), fmt.Sprintf("%s/%d", kconstants.RBE_OPENINGS_KEY, currentRevision),
		clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByModRevision, clientv3.SortAscend))
	if err != nil {
		log.Errorf("[dev] failed to fetch openings from etcd: %v", err)
		return
	}

	log.Infof("[dev] fetched %d openings from etcd, currently the revision is: %d", len(openingsRes.Kvs), openingsRes.Header.Revision)

	revision := openingsRes.Header.Revision
	for _, kv := range openingsRes.Kvs {
		value := kv.Value
		key := kv.Key
		keyStr := string(key)

		log.Infof("[dev] handling openings with key: %s, modRevision: %d", key, kv.ModRevision)
		err := sc.handleOpeningsUpdate(keyStr, value, kv.ModRevision, currentRevision)
		if err != nil {
			log.Errorf("[dev] failed to handle user opening update: %v", err)
		}
		revision = kv.ModRevision
	}

	// err = sc.updatePodValidationMap()
	// if err != nil {
	// 	log.Errorf("[dev] failed to update pod validation map: %v", err)
	// }

	// watch for updates to openings under: rbe-system/openings/<commitment-mod-revision>/<user-id>
	go func() {
		opch := sc.etcdClient.Watch(context.Background(), fmt.Sprintf("%s/%d", kconstants.RBE_OPENINGS_KEY, currentRevision),
			clientv3.WithPrefix(), clientv3.WithRev(revision+1))
		for newOpenResp := range opch {
			if newOpenResp.Canceled {
				log.Warnf("[dev] etcd watch canceled: %v", newOpenResp.Err())
				return
			}

			for _, ev := range newOpenResp.Events {
				log.Infof("[dev] type: %s, key: %q\n", ev.Type, ev.Kv.Key)

				if ev.Type == clientv3.EventTypePut {
					keyStr := string(ev.Kv.Key)
					value := ev.Kv.Value

					log.Infof("[dev] handling openings with key: %s, len: %d, modRevision: %d", keyStr, len(value), ev.Kv.ModRevision)
					err := sc.handleOpeningsUpdate(keyStr, value, ev.Kv.ModRevision, currentRevision)
					if err != nil {
						log.Errorf("[dev] failed to handle user opening update: %v", err)
					}
				}
			}
		}
	}()
}

func (sc *SecretManagerClient) handleOpeningsUpdate(keyStr string, value []byte, modRevision int64, commitmentRevision int64) error {

	// parse user id from key
	// key format: rbe-system/openings/<commitment-mod-revision>/<user-id>
	parts := strings.Split(keyStr, "/")
	if len(parts) != 4 {
		return fmt.Errorf("[dev] invalid key format for user openings: %s", keyStr)
	}
	idStr := parts[3]

	openingsProto := &kproto.Opening{}
	err := gproto.Unmarshal([]byte(value), openingsProto)
	if err != nil {
		return fmt.Errorf("[dev] failed to unmarshal user openings from etcd: %v", err)
	}

	opening := []*bls.G1{}
	for _, v := range openingsProto.Opening {
		g1 := new(bls.G1)
		g1.SetBytes(v.GetPoint())
		opening = append(opening, g1)
	}

	sc.muUserOpenings2.Lock()
	defer sc.muUserOpenings2.Unlock()

	if sc.userOpenings2 == nil {
		sc.userOpenings2 = make(map[int64]map[int64][]*bls.G1)
	}

	idInt64, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("[dev] invalid user id in user openings key: %s", idStr)
	}

	if sc.userOpenings2[idInt64] == nil {
		sc.userOpenings2[idInt64] = make(map[int64][]*bls.G1)
	}

	sc.userOpenings2[idInt64][commitmentRevision] = opening

	log.Infof("[dev] saved user openings for key: %s, len: %d, revision: %d", keyStr, len(value), modRevision)

	sc.receivedOpeningKeyChan <- keyStr
	return nil
}

// so I can just listen for new updates to blocks individually afterwards
// split this method into two: one for initial full commitments
// one for individual block updates
func (sc *SecretManagerClient) handleCommitmentsUpdate(key string, value []byte,
	revision int64) error {
	parts := strings.Split(key, "/")
	if len(parts) == 4 {
		log.Infof("[dev] this is a commitment update for a single block: %s, with size: %d", key, len(value))

		blockIndexStr := parts[3]
		blockIndex, err := strconv.Atoi(blockIndexStr)
		if err != nil {
			return fmt.Errorf("[dev] invalid block index in commitments key: %s", key)
		}

		commitmentsProto := &proto.G1{}
		err = gproto.Unmarshal([]byte(value), commitmentsProto)
		if err != nil {
			return fmt.Errorf("[dev] failed to unmarshal commitments from etcd: %v", err)
		}

		commitment := new(bls.G1)
		err = commitment.SetBytes(commitmentsProto.GetPoint())
		if err != nil {
			return fmt.Errorf("error setting commitment for block %d: %v", blockIndex, err)
		}

		sc.muCommitmentsHistory.Lock()
		defer sc.muCommitmentsHistory.Unlock()

		if sc.commitmentsHistory == nil {
			sc.commitmentsHistory = make(map[int64]map[int64]*bls.G1)
		}
		blockIndex64 := int64(blockIndex)
		if sc.commitmentsHistory[blockIndex64] == nil {
			sc.commitmentsHistory[blockIndex64] = make(map[int64]*bls.G1)
		}
		sc.commitmentsHistory[blockIndex64][revision] = commitment

		go sc.ListWatchOpeningsUpdate(revision)
		go sc.retryOneUnverifiedUser()

		return nil
	} else {
		log.Infof("[dev] invalid commitment key format: %s", key)
	}

	return nil
}

// func (sc *SecretManagerClient) UpdateUserOpenings() {
// 	rbeSecret := sc.GetRbeCachedSecret(security.WorkloadRbeIdentityCertResourceName)
// 	if rbeSecret != nil {
// 		id := int64(rbeSecret.User.Id())

// 		pp, err := sc.kcClient.FetchPublicParams()
// 		if err != nil {
// 			log.Errorf("[dev] err on FetchPublicParams: %v", err)
// 		}

// 		// for single user
// 		timeBeforeFAU := time.Now()

// commitments, userOpening, _, err := sc.kcClient.FetchUpdate(id)
// if err != nil {
// 	log.Errorf("[dev] err on FetchUpdate: %v", err)
// }
// rbeSecret.User.Update(commitments, userOpening)

// 		totalTimeFAU := float64(time.Since(timeBeforeFAU).Nanoseconds()) / float64(time.Millisecond)

// 		keyUpdateTimeSingle.With(RequestType.Value(monitoring.MAZU)).Record(totalTimeFAU)
// 		log.Infof("[dev] Key Update Time (Single): %f", totalTimeFAU)

// 		totalSizeFAU := 0

// 		for _, g := range commitments {
// 			totalSizeFAU += len(g.Bytes())
// 		}

// 		for _, row := range userOpening {
// 			totalSizeFAU += len(row.Bytes())
// 		}

// 		keyUpdateSizeSingle.With(RequestType.Value(monitoring.MAZU)).Record(float64(totalSizeFAU))
// 		log.Infof("[dev] Key Update Size (Single): %d", totalSizeFAU)

// 		log.Infof("[dev] Got the commitments (%d) and opening (%d) for user: %d", len(commitments), len(userOpening), id)

// 		// for all users
// 		timeBeforeFAU = time.Now()

// commitments, allOpenings, allRbeIds, err := sc.kcClient.FetchAllUpdates(pp)
// if err != nil {
// 	log.Errorf("[dev] err on FetchAllUpdates(): %v", err)
// }
// userOpening = allOpenings[id]

// 		totalTimeFAU = float64(time.Since(timeBeforeFAU).Nanoseconds()) / float64(time.Millisecond)

// 		keyUpdateTimeAll.With(RequestType.Value(monitoring.MAZU)).Record(totalTimeFAU)
// 		log.Infof("[dev] Key Update Time (All): %f", totalTimeFAU)

// 		totalSizeFAU = 0

// 		for _, g := range commitments {
// 			totalSizeFAU += len(g.Bytes())
// 		}

// 		for _, row := range allOpenings {
// 			for _, g := range row {
// 				totalSizeFAU += len(g.Bytes())
// 			}
// 		}

// 		for _, rbeId := range allRbeIds {
// 			if rbeId == nil {
// 				continue
// 			}

// 			totalSizeFAU += len([]byte(rbeId.Ip))
// 			totalSizeFAU += int(unsafe.Sizeof(rbeId.Port))
// 			totalSizeFAU += int(unsafe.Sizeof(rbeId.ExpireTime))
// 			totalSizeFAU += len([]byte(rbeId.Token))
// 		}

// 		keyUpdateSizeAll.With(RequestType.Value(monitoring.MAZU)).Record(float64(totalSizeFAU))
// 		log.Infof("[dev] Key Update Size (All): %d", totalSizeFAU)

// 		// rbeSecret.User.Update(commitments, userOpening)
// 		rbeSecret.Pp = pp
// 		rbeSecret.Openings = allOpenings
// 		rbeSecret.Commitments = commitments

// 		sc.rbeCache.SetWorkload(rbeSecret)

// 		podsValidity := map[string]bool{}

// 		log.Infof("[dev] all rbe ids: %+v", allRbeIds)

// 		for _, rbeId := range allRbeIds {
// 			if rbeId == nil {
// 				continue
// 			}
// 			key := fmt.Sprintf("%s|%s", rbeId.Ip, rbeId.Token)
// 			podsValidity[key] = kcUtil.CheckPodValidity(rbeId, rbeSecret)
// 		}

// 		log.Infof("[dev] printing pod validity map for all pods")
// 		log.Infof("%+v", podsValidity)

// 		jsonString, err := json.Marshal(podsValidity)
// 		if err != nil {
// 			fmt.Println("Error:", err)
// 		} else {
// 			fmt.Println(string(jsonString))
// 		}
// 		err = os.WriteFile("/etc/istio/proxy/pod_validity_data.json", jsonString, 0644)
// 		if err != nil {
// 			log.Errorf("[dev] err on WriteFile: %v", err)
// 		}

// 		sc.RegisterPodValidityMap(podsValidity)
// 	} else {
// 		log.Infof("[dev] no cached rbe secret\n")
// 	}

// 	// fetch updates once new nodes register with key curator (or k8s)
// 	delaySeconds := 10
// 	delay := time.Duration(delaySeconds) * time.Second
// 	log.Infof("[dev] inside UpdateUserOpenings() -- will call again in %d seconds", delaySeconds)

// 	sc.queue.PushDelayed(func() error {
// 		if cached := sc.rbeCache.GetWorkload(); cached != nil {
// 			sc.OnRbeOpeningsUpdate(cached.ResourceName)
// 		}
// 		return nil
// 	}, delay)
// }

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
	} else {
		// TODO: check if user and pp are stored in a well-known file location
		log.Infof("[dev] no cached secret found, checking if user and pp are stored in a file")
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

		pp := new(rbe.PublicParams)
		sc.muRbePp.RLock()
		defer sc.muRbePp.RUnlock()
		pp = sc.rbePp
		if pp == nil {
			return nil, fmt.Errorf("public params not found")
		}

		sk := new(bls.Scalar)
		sk.SetUint64(uint64(rbeId.SecretKey()))

		// create user
		user = rbe.NewUserWithSecret(pp, int(id), sk)

		_, _, _, userIdsBeforeMe, err := sc.kcClient.RegisterUser(user, rbeId)

		if err != nil {
			log.Errorf("[dev] err on RegisterUser(): %v", err)
			return nil, err
		}

		// proof verification is done later
		// if len(commitments) == 0 {
		// 	err := fmt.Errorf("received empty commitments from key curator")
		// 	return nil, err
		// }

		// // set the new commitments
		// pp.Commitments = commitments
		// user.Update(commitments, opening)

		// if rbe.VerifyMembership(pp, user.Id(), user.PublicKey(), proof) {
		// 	log.Infof("[dev] proof verified successfully")
		// } else {
		// 	log.Errorf("[dev] failure: unable to verify membership")
		// 	return nil, fmt.Errorf("[dev] proof has an invalid signature")
		// }

		log.Infof("[dev] other users before me: %+v", userIdsBeforeMe)

		sc.muUserIdsBeforeMe.Lock()
		defer sc.muUserIdsBeforeMe.Unlock()

		sc.userIdsBeforeMe = userIdsBeforeMe

		sc.muValidUsersMap.Lock()
		defer sc.muValidUsersMap.Unlock()

		if sc.validUsersMap == nil {
			sc.validUsersMap = make(map[int64]bool)
		}
		for _, uid := range userIdsBeforeMe {
			sc.validUsersMap[uid] = false
		}
	}

	adminToken, err := kcUtil.GetPlatformCredential()
	if err != nil {
		log.Errorf("[dev] err on GetPlatformCredential(): %v", err)
		return nil, err
	}

	extensions := []pkix.Extension{
		{
			Id:    AdminTokenOID,
			Value: []byte(adminToken),
		},
	}

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

		TTL: time.Duration(12) * time.Hour,
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

	sc.receivedUserKeyChan <- fmt.Sprintf("%s/%d", kconstants.RBE_USER_PREFIX, user.Id())

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
