package keycurator

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	cniconsts "istio.io/istio/cni/pkg/constants"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/credentialfetcher/plugin"
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
// TODO: how do I verify the token? with TokenReview API?
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

// TODO: there should be better way to get pod name and uid
// TODO: pod name is easily accessed via node.Metadata.InstanceName
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
