package keycurator

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	cniconsts "istio.io/istio/cni/pkg/constants"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RbeId struct {
	Ip         string
	Port       int
	Nonce      string
	ExpireTime int64
	SpiffeId   *spiffe.Identity
	PodUid     string
}

func (id *RbeId) String() string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", id.SpiffeId,
		id.Ip, id.Port, id.Nonce, id.ExpireTime)
}

func (id *RbeId) ToNumber() int32 {
	return idStringToNumber(id.String())
}

// convert s to 16-bit number
func idStringToNumber(s string) int32 {
	data := []byte(s)
	hash128 := md5.Sum(data) // 128 bits

	hash16 := hash128[0:2] // 16 bits
	number := binary.BigEndian.Uint16(hash16)

	return int32(number)
}

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

// this fails: workload is forbidden to list all ports
func GetPodMetadata() {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Errorf("[dev] failed to get in-cluster config: %v", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("[dev] failed to create clientset: %v", err)
		return
	}

	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("[dev] failed to list pods: %v", err)
		return
	}

	for _, pod := range pods.Items {
		log.Infof("[dev] Pod Name: %s, UID: %s", pod.Name, pod.UID)
	}
}
