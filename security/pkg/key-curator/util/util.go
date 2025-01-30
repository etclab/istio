package keycurator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/etclab/rbe"
	"github.com/golang-jwt/jwt/v5"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	cniconsts "istio.io/istio/cni/pkg/constants"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
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

	result = nonceHash.IsEqual(decryptedNonce)
	return
}
