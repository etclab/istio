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

package model

import (
	gotls "crypto/tls"
	"strings"

	udpa "github.com/cncf/xds/go/udpa/type/v1"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/model/credentials"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/log"
	pm "istio.io/istio/pkg/model"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
)

const (
	// SDSClusterName is the name of the cluster for SDS connections
	SDSClusterName = pm.SDSClusterName

	// SDSDefaultResourceName is the default name in sdsconfig, used for fetching normal key/cert.
	SDSDefaultResourceName = pm.SDSDefaultResourceName

	// SDSRootResourceName is the sdsconfig name for root CA, used for fetching root cert.
	SDSRootResourceName = pm.SDSRootResourceName

	// ThirdPartyJwtPath is the token volume mount file name for k8s trustworthy jwt token.
	ThirdPartyJwtPath = "/var/run/secrets/tokens/istio-token"

	// SdsCaSuffix is the suffix of the sds resource name for root CA.
	SdsCaSuffix = credentials.SdsCaSuffix

	// EnvoyJwtFilterName is the name of the Envoy JWT filter. This should be the same as the name defined
	// in https://github.com/envoyproxy/envoy/blob/v1.9.1/source/extensions/filters/http/well_known_names.h#L48
	EnvoyJwtFilterName = "envoy.filters.http.jwt_authn"
)

var SDSAdsConfig = &core.ConfigSource{
	ConfigSourceSpecifier: &core.ConfigSource_Ads{
		Ads: &core.AggregatedConfigSource{},
	},
	// We intentionally do *not* set InitialFetchTimeout to 0s here, as this is used for
	// credentialName SDS which may refer to secrets which do not exist. We do not want to block the
	// entire listener/cluster in these cases.
	ResourceApiVersion: core.ApiVersion_V3,
}

// ConstructSdsSecretConfigForCredential constructs SDS secret configuration used
// from certificates referenced by credentialName in DestinationRule or Gateway.
// Currently this is served by a local SDS server, but in the future replaced by
// Istiod SDS server.
func ConstructSdsSecretConfigForCredential(name string, credentialSocketExist bool) *tls.SdsSecretConfig {
	if name == "" {
		return nil
	}
	if name == credentials.BuiltinGatewaySecretTypeURI {
		return ConstructSdsSecretConfig(SDSDefaultResourceName)
	}
	if name == credentials.BuiltinGatewaySecretTypeURI+SdsCaSuffix {
		return ConstructSdsSecretConfig(SDSRootResourceName)
	}
	// if credentialSocketExist exists and credentialName is using SDSExternalCredentialPrefix
	// SDS will be served via SDSExternalClusterName
	if credentialSocketExist && strings.HasPrefix(name, security.SDSExternalCredentialPrefix) {
		return ConstructSdsSecretConfigForCredentialSocket(name)
	}

	return &tls.SdsSecretConfig{
		Name:      credentials.ToResourceName(name),
		SdsConfig: SDSAdsConfig,
	}
}

// ConstructSdsSecretConfigForCredentialSocket constructs SDS Secret Configuration based on CredentialNameSocketPath
// if CredentialNameSocketPath exists, use a static cluster 'sds-external'
func ConstructSdsSecretConfigForCredentialSocket(name string) *tls.SdsSecretConfig {
	return &tls.SdsSecretConfig{
		Name: name,
		SdsConfig: &core.ConfigSource{
			ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
				ApiConfigSource: &core.ApiConfigSource{
					ApiType:                   core.ApiConfigSource_GRPC,
					SetNodeOnFirstMessageOnly: true,
					TransportApiVersion:       core.ApiVersion_V3,
					GrpcServices: []*core.GrpcService{
						{
							TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
								EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: security.SDSExternalClusterName},
							},
						},
					},
				},
			},
			ResourceApiVersion: core.ApiVersion_V3,
		},
	}
}

// ConstructSdsSecretConfig constructs SDS Secret Configuration for workload proxy.
func ConstructSdsSecretConfig(name string) *tls.SdsSecretConfig {
	return pm.ConstructSdsSecretConfig(name)
}

func AppendURIPrefixToTrustDomain(trustDomainAliases []string) []string {
	res := make([]string, 0, len(trustDomainAliases))
	for _, td := range trustDomainAliases {
		res = append(res, spiffe.URIPrefix+td+"/")
	}
	return res
}

// ApplyToCommonTLSContext completes the commonTlsContext
func ApplyToCommonTLSContext(tlsContext *tls.CommonTlsContext, proxy *model.Proxy,
	subjectAltNames []string, crl string, trustDomainAliases []string, validateClient bool,
) {
	// These are certs being mounted from within the pod. Rather than reading directly in Envoy,
	// which does not support rotation, we will serve them over SDS by reading the files.
	// We should check if these certs have values, if yes we should use them or otherwise fall back to defaults.
	res := security.SdsCertificateConfig{
		CertificatePath:   proxy.Metadata.TLSServerCertChain,
		PrivateKeyPath:    proxy.Metadata.TLSServerKey,
		CaCertificatePath: proxy.Metadata.TLSServerRootCert,
	}

	// TODO: if subjectAltName ends with *, create a prefix match as well.
	// TODO: if user explicitly specifies SANs - should we alter his explicit config by adding all spifee aliases?
	matchSAN := util.StringToExactMatch(subjectAltNames)
	log.Infof("[dev] ApplyToCommonTLSContext: subject alt names : %v", subjectAltNames)

	if len(trustDomainAliases) > 0 {
		matchSAN = append(matchSAN, util.StringToPrefixMatch(AppendURIPrefixToTrustDomain(trustDomainAliases))...)
	}

	rbeConfig := map[string]interface{}{
		"pod_validity_map": map[string]interface{}{
			"filename": "/etc/istio/proxy/pod_validity_data.json",
		},
	}

	// rbeConfig := map[string]interface{}{
	// 	"pod_validity_sds": map[string]interface{}{
	// 		"name": "rbePodValidation",
	// 		"sdsConfig": map[string]interface{}{
	// 			"apiConfigSource": map[string]interface{}{
	// 				"apiType":             "GRPC",
	// 				"transportApiVersion": "V3",
	// 				"grpcServices": []interface{}{
	// 					map[string]interface{}{
	// 						"envoyGrpc": map[string]interface{}{
	// 							"clusterName": "sds-grpc",
	// 						},
	// 					},
	// 				},
	// 				"setNodeOnFirstMessageOnly": true,
	// 			},
	// 			// "initial_fetch_timeout": "0s",
	// 			"resourceApiVersion": "V3",
	// 		},
	// 	},
	// }

	// rbeConfig := map[string]interface{}{
	// 	"pod_validity_sds": ConstructSdsSecretConfig(model.GetOrDefault(res.GetRootResourceName(), SDSRootResourceName)),
	// }

	rbeStruct, err := structpb.NewStruct(rbeConfig)
	if err != nil {
		log.Errorf("[dev] Failed to create RBE struct: %v", err)
	}

	typedStruct := &udpa.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.RBECertValidatorConfig",
		Value:   rbeStruct,
	}

	// see if you can pass a certificate to envoy and it is able to read it
	// this is a normal certificate so I need to parse it with findOrCreateCertificate.. or similar method

	typedStructAny, err := anypb.New(typedStruct)
	if err != nil {
		log.Errorf("[dev] Failed to create TypedStructAny: %v", err)
	}
	log.Infof("[dev] typed struct any: %v", typedStructAny)

	// configure server listeners with SDS.
	if validateClient {
		log.Infof("[dev] inside validate client")
		defaultValidationContext := &tls.CertificateValidationContext{
			MatchSubjectAltNames: matchSAN,
		}
		if crl != "" {
			defaultValidationContext.Crl = &core.DataSource{
				Specifier: &core.DataSource_Filename{
					Filename: crl,
				},
			}
		}

		// log.Infof("[dev] proxy type: %v", proxy.Type)
		// log.Infof("[dev] proxy id: %v", proxy.ID)
		// log.Infof("[dev] proxy labels: %v", proxy.Labels)

		if proxy.Type == model.SidecarProxy {
			defaultValidationContext.CustomValidatorConfig = &core.TypedExtensionConfig{
				Name:        "envoy.tls.cert_validator.rbe",
				TypedConfig: typedStructAny,
			}
		}

		tlsContext.ValidationContextType = &tls.CommonTlsContext_CombinedValidationContext{
			CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: defaultValidationContext,
				// we won't have a default CA (for workload) so whatever we add here should be ignored
				// what about communication with other non-workload services in k8s?
				ValidationContextSdsSecretConfig: ConstructSdsSecretConfig(model.GetOrDefault(res.GetRootResourceName(), SDSRootResourceName)),
			},
		}

	}

	log.Infof("[dev] setting default and rbeIdentity for proxy: \n metadata: %v", proxy.Metadata)

	if proxy.Type == model.SidecarProxy {
		log.Infof("[dev] setting default and rbeIdentity for proxy with labels: %v", proxy.Labels)

		tlsContext.TlsCertificateSdsSecretConfigs = append(tlsContext.TlsCertificateSdsSecretConfigs,
			ConstructSdsSecretConfig("rbeIdentity"),
		)
		// TODO: setting multiple certificates here leads to `rbeIdentiy` being overridden
		// tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
		// 	ConstructSdsSecretConfig(model.GetOrDefault(res.GetResourceName(), SDSDefaultResourceName)),``
		// }
	} else {
		tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
			ConstructSdsSecretConfig(model.GetOrDefault(res.GetResourceName(), SDSDefaultResourceName)),
		}
	}

	// if proxy.Type == model.SidecarProxy {
	// 	tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
	// 		ConstructSdsSecretConfig(model.GetOrDefault(res.GetResourceName(), SDSDefaultResourceName)),
	// 	}
	// 	tlsContext.TlsCertificateSdsSecretConfigs = append(tlsContext.TlsCertificateSdsSecretConfigs,
	// 		ConstructSdsSecretConfig("rbeIdentity"),
	// 	)
	// } else {
	// 	tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
	// 		ConstructSdsSecretConfig(model.GetOrDefault(res.GetResourceName(), SDSDefaultResourceName)),
	// 	}
	// }

	// log.Infof("[dev] final tls context: %+v", tlsContext)
}

// ApplyCustomSDSToClientCommonTLSContext applies the customized sds to CommonTlsContext
// Used for building upstream TLS context for egress gateway's TLS/mTLS origination
func ApplyCustomSDSToClientCommonTLSContext(tlsContext *tls.CommonTlsContext,
	tlsOpts *networking.ClientTLSSettings, credentialSocketExist bool,
) {
	if tlsOpts.Mode == networking.ClientTLSSettings_MUTUAL {
		// create SDS config for gateway to fetch key/cert from agent.
		tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
			ConstructSdsSecretConfigForCredential(tlsOpts.CredentialName, credentialSocketExist),
		}
	}

	// If the InsecureSkipVerify is true, there is no need to configure CA Cert and SAN.
	if tlsOpts.GetInsecureSkipVerify().GetValue() {
		return
	}

	// create SDS config for gateway to fetch certificate validation context
	// at gateway agent.
	defaultValidationContext := &tls.CertificateValidationContext{
		MatchSubjectAltNames: util.StringToExactMatch(tlsOpts.SubjectAltNames),
	}
	tlsContext.ValidationContextType = &tls.CommonTlsContext_CombinedValidationContext{
		CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
			DefaultValidationContext: defaultValidationContext,
			ValidationContextSdsSecretConfig: ConstructSdsSecretConfigForCredential(
				tlsOpts.CredentialName+SdsCaSuffix, credentialSocketExist),
		},
	}
}

// ApplyCredentialSDSToServerCommonTLSContext applies the credentialName sds (Gateway/DestinationRule) to CommonTlsContext
// Used for building both gateway/sidecar TLS context
func ApplyCredentialSDSToServerCommonTLSContext(tlsContext *tls.CommonTlsContext,
	tlsOpts *networking.ServerTLSSettings, credentialSocketExist bool,
) {
	// create SDS config for gateway/sidecar to fetch key/cert from agent.
	tlsContext.TlsCertificateSdsSecretConfigs = []*tls.SdsSecretConfig{
		ConstructSdsSecretConfigForCredential(tlsOpts.CredentialName, credentialSocketExist),
	}
	// If tls mode is MUTUAL/OPTIONAL_MUTUAL, create SDS config for gateway/sidecar to fetch certificate validation context
	// at gateway agent. Otherwise, use the static certificate validation context config.
	if tlsOpts.Mode == networking.ServerTLSSettings_MUTUAL || tlsOpts.Mode == networking.ServerTLSSettings_OPTIONAL_MUTUAL {
		defaultValidationContext := &tls.CertificateValidationContext{
			MatchSubjectAltNames:  util.StringToExactMatch(tlsOpts.SubjectAltNames),
			VerifyCertificateSpki: tlsOpts.VerifyCertificateSpki,
			VerifyCertificateHash: tlsOpts.VerifyCertificateHash,
		}
		tlsContext.ValidationContextType = &tls.CommonTlsContext_CombinedValidationContext{
			CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: defaultValidationContext,
				ValidationContextSdsSecretConfig: ConstructSdsSecretConfigForCredential(
					tlsOpts.CredentialName+SdsCaSuffix, credentialSocketExist),
			},
		}
	} else if len(tlsOpts.SubjectAltNames) > 0 {
		tlsContext.ValidationContextType = &tls.CommonTlsContext_ValidationContext{
			ValidationContext: &tls.CertificateValidationContext{
				MatchSubjectAltNames: util.StringToExactMatch(tlsOpts.SubjectAltNames),
			},
		}
	}
}

func EnforceGoCompliance(ctx *gotls.Config) {
	pm.EnforceGoCompliance(ctx)
}

func EnforceCompliance(ctx *tls.CommonTlsContext) {
	pm.EnforceCompliance(ctx)
}
