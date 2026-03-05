package keycurator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/etclab/rbe"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe/proto"
	gproto "google.golang.org/protobuf/proto"
	cniconsts "istio.io/istio/cni/pkg/constants"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RegisteredUserWithProof struct {
	ProofBytes       []byte
	AttestationBytes []byte
	RequestBytes     []byte
}

const RBE_PP_FILE = "/var/run/rbe-pp/rbe-pp.txt"

const RBE_PP_ONLY_FILE = "/var/run/rbe-pp/rbe-pp-only.txt"
const RBE_PP_CRS_H1_FILE = "/var/run/rbe-pp/rbe-crs-h1.txt"
const RBE_PP_CRS_H2_FILE = "/var/run/rbe-pp/rbe-crs-h2.txt"

// const RBE_PP_ONLY_FILE = "/var/run/secrets/istio-dns/rbe-pp-only.txt"
// const RBE_PP_CRS_H1_FILE = "/var/run/secrets/istio-dns/rbe-crs-h1.txt"
// const RBE_PP_CRS_H2_FILE = "/var/run/secrets/istio-dns/rbe-crs-h2.txt"

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

func GetKubeClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("[dev] failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("[dev] failed to create clientset: %v", err)
	}

	return clientset, nil
}

// returns the admin token
// how do I verify the token?
// 1) with TokenReview API -- needs TokenReview:create api permission
// 2) with ca.crt placed inside /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
func GetPlatformCredential() (string, error) {
	saToken := cniconsts.ServiceAccountPath + "/token"

	tokenPlugin := plugin.CreateTokenPlugin(saToken)
	token, err := tokenPlugin.GetPlatformCredential()
	if err != nil {
		log.Errorf("[dev] failed to get token: %v", err)
		return "", err
	}
	return token, nil
}

// returns the ca.crt as []byte
func GetPlatformCert() (interface{}, error) {
	caCrt := cniconsts.ServiceAccountPath + "/ca.crt"
	cert, err := os.ReadFile(caCrt)
	if err != nil {
		log.Errorf("[dev] failed to read ca.crt: %v", err)
		return []byte{}, err
	}
	return cert, nil
}

// verifies the service account token and returns the claims
// needs TokenReview:create api permission to verify the token
// see ./dev/cluster-role.yaml and ./dev/cluster-role-binding.yaml
func VerifyServiceAccountToken(token string) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("[dev] failed to get in-cluster config: %v", err)
		return fmt.Errorf("[dev] failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("[dev] failed to create clientset: %v", err)
		return fmt.Errorf("[dev] failed to create clientset: %v", err)
	}

	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	result, err := clientset.AuthenticationV1().TokenReviews().Create(context.TODO(),
		tokenReview, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("[dev] failed to create token review: %v", err)
		return fmt.Errorf("[dev] failed to create token review: %v", err)
	}

	log.Infof("[dev] token review result: %+v", result)

	// extract service account, pod name, authenticated status, and pod uid
	activated := result.Status.Authenticated
	username := result.Status.User.Username
	podName := result.Status.User.Extra["authentication.kubernetes.io/pod-name"]
	podUid := result.Status.User.Extra["authentication.kubernetes.io/pod-uid"]

	log.Infof("[dev] token review result: activated: %t, username: %s, pod name: %s, pod uid: %s",
		activated, username, podName, podUid)

	return nil
}

// pod name is readily accessed via node.Metadata.InstanceName
func GetPodUid() (string, error) {
	tokenString, err := GetPlatformCredential()
	if err != nil {
		log.Errorf("[dev] failed to get token: %v", err)
		return "", err
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		log.Errorf("[dev] failed to parse token: %v", err)
		return "", err
	}

	k8sKey := "kubernetes.io"
	k8sMap, ok := token.Claims.(jwt.MapClaims)[k8sKey].(map[string]interface{})
	if ok {
		podMap, ok := k8sMap["pod"]
		if ok {
			uid, ok := podMap.(map[string]interface{})["uid"]
			if ok {
				return fmt.Sprintf("%s", uid), nil
			}
		}
	}

	return "", fmt.Errorf("could not get pod uid")
}

type PodDetail struct {
	IP                 string
	Port               int
	Name               string
	UID                string
	ServiceAccountName string
	Namespace          string
	SpiffId            *spiffe.Identity
}

func (pd *PodDetail) String() string {
	return fmt.Sprintf("%s|%d|%s", pd.IP, pd.Port, pd.SpiffId)
}

// requires the Role and RoleBinding on service account to list/get pods
// see files: dev/default-pod-role.yaml and dev/default-pod-role-binding.yaml
func GetPodsInDefaultNamespace() ([]PodDetail, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("[dev] failed to get in-cluster config: %v", err)
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("[dev] failed to create clientset: %v", err)
		return nil, err
	}

	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("[dev] failed to list pods: %v", err)
		return nil, err
	}

	podDetails := make([]PodDetail, 0)

	for _, pod := range pods.Items {
		// TODO: handle if any of these fields are nil
		podDetail := new(PodDetail)
		podDetail.IP = pod.Status.PodIP
		podDetail.Port = int(pod.Spec.Containers[0].Ports[0].ContainerPort)
		podDetail.Name = pod.Name
		podDetail.UID = string(pod.UID)
		podDetail.ServiceAccountName = pod.Spec.ServiceAccountName
		podDetail.Namespace = pod.Namespace

		podDetail.SpiffId = &spiffe.Identity{
			TrustDomain:    "cluster.local", // default trust domain
			Namespace:      podDetail.Namespace,
			ServiceAccount: podDetail.ServiceAccountName}

		podDetails = append(podDetails, *podDetail)
	}

	return podDetails, nil
}

func HashToGt(msg []byte) *bls.Gt {
	g1 := new(bls.G1)
	g1.Hash(msg, nil)
	g2 := new(bls.G2)
	g2.Hash(msg, nil)
	return bls.Pair(g1, g2)
}

func CheckPodValidity(rbeId *security.RbeId, secret *security.RbeSecretItem) (result bool) {
	thisUser := secret.User
	pp := secret.Pp

	// TODO: defer-recover is used to return a default value on panic
	defer func() {
		if err := recover(); err != nil { //catch
			log.Infof("[dev] error validating pod with detail: %+v", rbeId)
			log.Infof("[dev] error during validation was %+v", err)
		}
	}()

	nonce := []byte(fmt.Sprintf("%d", time.Now().Unix()))
	nonceHash := HashToGt(nonce)

	otherRbeId := &security.RbeId{
		Ip:    rbeId.Ip,
		Port:  rbeId.Port,
		Token: rbeId.Token,
	}

	idOtherUser := int(otherRbeId.ToNumber())

	if idOtherUser == thisUser.Id() {
		return true
	}

	log.Infof("[dev] id other user: %d", idOtherUser)
	log.Infof("[dev] id of this user: %d", thisUser.Id())

	cipherText := thisUser.Encrypt(idOtherUser, nonceHash)

	sk := new(bls.Scalar)
	// sk.SetUint64(uint64(idOtherUser))
	sk.SetUint64(uint64(otherRbeId.SecretKey()))

	otherUser := rbe.NewUserWithSecret(pp, idOtherUser, sk)

	commitments := secret.Commitments
	userOpening := secret.Openings[idOtherUser]
	otherUser.Update(commitments, userOpening)

	log.Infof("[dev] other user initailized here is : %+v", otherUser)

	decryptedNonce, err := otherUser.Decrypt(cipherText)
	if err != nil {
		log.Errorf("[dev] failed to decrypt nonce: %v", err)
		return false
	}

	return nonceHash.IsEqual(decryptedNonce)
}

const MAZU_CONFIG_PATH = "/etc/mazu-config"
const MAZU_ATTESTATION_ENABLED = "MAZU_ATTESTATION_ENABLED"
const MAZU_RBE_PROOF_ENABLED = "MAZU_RBE_PROOF_ENABLED"
const MAZU_ON_DEMAND_ENABLED = "MAZU_ON_DEMAND_ENABLED"

// looks for MAZU_ATTESTATION_ENABLED file loaded by config map: mazu-config
// under path: /etc/mazu-config/MAZU_ATTESTATION_ENABLED
func IsAttestationEnabled() bool {
	filepath := fmt.Sprintf("%s/%s", MAZU_CONFIG_PATH, MAZU_ATTESTATION_ENABLED)
	content, err := os.ReadFile(filepath)
	if err != nil {
		log.Infof("[dev] attestation is disabled, file %s not found", filepath)
		return false
	}
	if strings.TrimSpace(string(content)) != "true" {
		log.Infof("[dev] attestation is disabled, with value: %s", string(content))
		return false
	} else {
		log.Infof("[dev] attestation is enabled")
		return true
	}
}

// looks for MAZU_RBE_PROOF_ENABLED file loaded by config map: mazu-config
// under path: /etc/mazu-config/MAZU_RBE_PROOF_ENABLED
// IsOnDemandEnabled checks whether on-demand registration fetching is enabled.
// Reads /etc/mazu-config/MAZU_ON_DEMAND_ENABLED. Disabled by default.
func IsOnDemandEnabled() bool {
	filepath := fmt.Sprintf("%s/%s", MAZU_CONFIG_PATH, MAZU_ON_DEMAND_ENABLED)
	content, err := os.ReadFile(filepath)
	if err != nil {
		log.Infof("[dev] on-demand registration is disabled, file %s not found", filepath)
		return false
	}
	if strings.TrimSpace(string(content)) != "true" {
		log.Infof("[dev] on-demand registration is disabled, with value: %s", string(content))
		return false
	}
	log.Infof("[dev] on-demand registration is enabled")
	return true
}

func IsRbeProofEnabled() bool {
	filepath := fmt.Sprintf("%s/%s", MAZU_CONFIG_PATH, MAZU_RBE_PROOF_ENABLED)
	content, err := os.ReadFile(filepath)
	if err != nil {
		log.Infof("[dev] RBE proof verification is disabled, file %s not found", filepath)
		return false
	}
	if strings.TrimSpace(string(content)) != "true" {
		log.Infof("[dev] RBE proof verification is disabled, with value: %s", string(content))
		return false
	} else {
		log.Infof("[dev] RBE proof verification is enabled")
		return true
	}
}

func TryParseRbePpFromFile() (*rbe.PublicParams, error) {
	// filename := RBE_PP_FILE

	// ppBytes, err := os.ReadFile(filename)
	// if err != nil {
	// 	return nil, fmt.Errorf("could not read RBE public params file: %w", err)
	// }

	// // parse the public params from the file
	// ppProto := &proto.PublicParams{}
	// err = gproto.Unmarshal(ppBytes, ppProto)
	// if err != nil {
	// 	return nil, fmt.Errorf("could not unmarshal RBE public params from file: %w", err)
	// }

	// pp := new(rbe.PublicParams)
	// pp.FromProto(ppProto)

	// saveRbeParams(pp)
	start := time.Now()
	pp, err := restoreRbePp()
	if err != nil {
		return nil, fmt.Errorf("could not restore RBE public params from files: %w", err)
	}
	log.Infof("[dev] restored RBE public params from files in %s", time.Since(start))

	return pp, nil
}

func SaveRbeParams(pp *rbe.PublicParams, outDir string) error {
	ppOnlyFile := filepath.Join(outDir, "rbe-pp-only.txt")
	crsH1File := filepath.Join(outDir, "rbe-crs-h1.txt")
	crsH2File := filepath.Join(outDir, "rbe-crs-h2.txt")

	// save crs h1 and h2 separately
	crsH1 := new(rbe.CRS)
	crsH1.H1 = pp.CRS.H1
	crsH1.H2 = make([]*bls.G2, len(pp.CRS.H2))

	// marshal and save
	crsH1Proto := crsH1.ToProto()
	crsH1Bytes, err := gproto.Marshal(crsH1Proto)
	if err != nil {
		return fmt.Errorf("could not marshal RBE CRS H1 to proto: %w", err)
	}
	err = os.WriteFile(crsH1File, crsH1Bytes, 0644)
	if err != nil {
		return fmt.Errorf("could not write RBE CRS H1 to file: %w", err)
	}
	log.Infof("[dev] successfully saved RBE CRS H1 to file: %s", crsH1File)

	crsH2 := new(rbe.CRS)
	crsH2.H2 = pp.CRS.H2
	crsH1.H1 = make([]*bls.G1, len(pp.CRS.H1))

	// marshal and save
	crsH2Proto := crsH2.ToProto()
	crsH2Bytes, err := gproto.Marshal(crsH2Proto)
	if err != nil {
		return fmt.Errorf("could not marshal RBE CRS H2 to proto: %w", err)
	}
	err = os.WriteFile(crsH2File, crsH2Bytes, 0644)
	if err != nil {
		return fmt.Errorf("could not write RBE CRS H2 to file: %w", err)
	}
	log.Infof("[dev] successfully saved RBE CRS H2 to file: %s", crsH2File)

	ppWithoutCommitmentsAndCrs := &rbe.PublicParams{
		MaxUsers:    pp.MaxUsers,
		BlockSize:   pp.BlockSize,
		NumBlocks:   pp.NumBlocks,
		G1:          pp.G1,
		G2:          pp.G2,
		CRS:         &rbe.CRS{},
		Commitments: []*bls.G1{},
	}
	// marshal and save
	ppOnlyProto := ppWithoutCommitmentsAndCrs.ToProto()
	ppOnlyBytes, err := gproto.Marshal(ppOnlyProto)
	if err != nil {
		return fmt.Errorf("could not marshal RBE public params without commitments and crs to proto: %w", err)
	}
	err = os.WriteFile(ppOnlyFile, ppOnlyBytes, 0644)
	if err != nil {
		return fmt.Errorf("could not write RBE public params without commitments and crs to file: %w", err)
	}
	log.Infof("[dev] successfully saved RBE public params without commitments and crs to file: %s", ppOnlyFile)

	return nil
}

func restoreRbePp() (*rbe.PublicParams, error) {
	var (
		ppOnly *rbe.PublicParams
		crsH1  *rbe.CRS
		crsH2  *rbe.CRS
	)

	g, _ := errgroup.WithContext(context.Background())

	// Goroutine 1: Read PP only file
	g.Go(func() error {
		ppOnlyBytes, err := os.ReadFile(RBE_PP_ONLY_FILE)
		if err != nil {
			return fmt.Errorf("could not read RBE public params only file: %w", err)
		}

		ppOnlyProto := &proto.PublicParams{}
		if err := gproto.Unmarshal(ppOnlyBytes, ppOnlyProto); err != nil {
			return fmt.Errorf("could not unmarshal RBE public params only from file: %w", err)
		}

		ppOnly = new(rbe.PublicParams)
		ppOnly.FromProto(ppOnlyProto)

		// Initialize commitments to identity
		ppOnly.Commitments = make([]*bls.G1, ppOnly.NumBlocks)
		for i := 0; i < ppOnly.NumBlocks; i++ {
			ppOnly.Commitments[i] = new(bls.G1)
			ppOnly.Commitments[i].SetIdentity()
		}

		return nil
	})

	// Goroutine 2: Read CRS H1 file
	g.Go(func() error {
		crsH1Bytes, err := os.ReadFile(RBE_PP_CRS_H1_FILE)
		if err != nil {
			return fmt.Errorf("could not read RBE CRS H1 file: %w", err)
		}

		crsH1Proto := &proto.CRS{}
		if err := gproto.Unmarshal(crsH1Bytes, crsH1Proto); err != nil {
			return fmt.Errorf("could not unmarshal RBE CRS H1 from file: %w", err)
		}

		crsH1 = new(rbe.CRS)
		crsH1.FromProto(crsH1Proto)
		return nil
	})

	// Goroutine 3: Read CRS H2 file
	g.Go(func() error {
		crsH2Bytes, err := os.ReadFile(RBE_PP_CRS_H2_FILE)
		if err != nil {
			return fmt.Errorf("could not read RBE CRS H2 file: %w", err)
		}

		crsH2Proto := &proto.CRS{}
		if err := gproto.Unmarshal(crsH2Bytes, crsH2Proto); err != nil {
			return fmt.Errorf("could not unmarshal RBE CRS H2 from file: %w", err)
		}

		crsH2 = new(rbe.CRS)
		crsH2.FromProto(crsH2Proto)
		return nil
	})

	// Wait for all goroutines and check for errors
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Build the final pp after all parallel reads complete
	pp := &rbe.PublicParams{
		BlockSize: ppOnly.BlockSize,
		NumBlocks: ppOnly.NumBlocks,
		MaxUsers:  ppOnly.MaxUsers,
		G1:        ppOnly.G1,
		G2:        ppOnly.G2,
		CRS: &rbe.CRS{
			H1: crsH1.H1,
			H2: crsH2.H2,
		},
		Commitments: ppOnly.Commitments,
	}

	return pp, nil
}
