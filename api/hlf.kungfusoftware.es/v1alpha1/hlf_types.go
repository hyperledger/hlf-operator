/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"fmt"
	"k8s.io/api/networking/v1beta1"

	"github.com/operator-framework/operator-lib/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type CA struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:MinLength=1
	Cert string `json:"cert"`
	// +kubebuilder:validation:MinLength=1
	User string `json:"user"`
	// +kubebuilder:validation:MinLength=1
	Password string `json:"password"`
}

// +kubebuilder:validation:Enum=couchdb;leveldb
type StateDB string

// Use LevelDB database
const StateDBLevelDB StateDB = "leveldb"

// Use CouchDB database
const StateDBCouchDB StateDB = "couchdb"

type ExternalBuilder struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	PropagateEnvironment []string `json:"propagateEnvironment"`
}

const DefaultImagePullPolicy = corev1.PullAlways

type ServiceMonitor struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +optional
	Labels map[string]string `json:"labels"`
	// +kubebuilder:default:=0
	SampleLimit int `json:"sampleLimit"`
	// +kubebuilder:default:="10s"
	Interval string `json:"interval"`
	// +kubebuilder:default:="10s"
	ScrapeTimeout string `json:"scrapeTimeout"`
}

type FabricPeerCouchdbExporter struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +kubebuilder:default:="gesellix/couchdb-prometheus-exporter"
	Image string `json:"image"`
	// +kubebuilder:default:="v30.0.0"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
}

type GRPCProxy struct {
	// +kubebuilder:default:=false
	Enabled bool `json:"enabled"`
	// +kubebuilder:default:="ghcr.io/hyperledger-labs/grpc-web"
	Image string `json:"image"`
	// +kubebuilder:default:="latest"
	Tag string `json:"tag"`

	Istio FabricIstio `json:"istio"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`

	// +nullable
	Resources *corev1.ResourceRequirements `json:"resources"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
}

// FabricPeerSpec defines the desired state of FabricPeer
type FabricPeerSpec struct {
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	// +optional
	// +nullable
	CouchDBExporter *FabricPeerCouchdbExporter `json:"couchDBexporter"`

	// +optional
	// +nullable
	GRPCProxy *GRPCProxy `json:"grpcProxy"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:default:=""
	DockerSocketPath string `json:"dockerSocketPath"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	ExternalBuilders []ExternalBuilder `json:"externalBuilders"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio            *FabricIstio         `json:"istio"`
	Gossip           FabricPeerSpecGossip `json:"gossip"`
	ExternalEndpoint string               `json:"externalEndpoint"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy          corev1.PullPolicy `json:"imagePullPolicy,omitempty"`
	ExternalChaincodeBuilder bool              `json:"external_chaincode_builder"`
	CouchDB                  FabricPeerCouchDB `json:"couchdb"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	FSServer *FabricFSServer `json:"fsServer"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +kubebuilder:validation:MinLength=3
	MspID     string              `json:"mspID"`
	Secret    Secret              `json:"secret"`
	Service   PeerService         `json:"service"`
	StateDb   StateDB             `json:"stateDb"`
	Storage   FabricPeerStorage   `json:"storage"`
	Discovery FabricPeerDiscovery `json:"discovery"`
	Logging   FabricPeerLogging   `json:"logging"`
	Resources FabricPeerResources `json:"resources"`
	Hosts     []string            `json:"hosts"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`
}
type FabricPeerResources struct {
	Peer      corev1.ResourceRequirements `json:"peer"`
	CouchDB   corev1.ResourceRequirements `json:"couchdb"`
	Chaincode corev1.ResourceRequirements `json:"chaincode"`
	// +optional
	// +nullable
	CouchDBExporter *corev1.ResourceRequirements `json:"couchdbExporter"`
	// +optional
	// +nullable
	Proxy *corev1.ResourceRequirements `json:"proxy"`
}
type FabricPeerDiscovery struct {
	Period      string `json:"period"`
	TouchPeriod string `json:"touchPeriod"`
}
type FabricPeerLogging struct {
	Level    string `json:"level"`
	Peer     string `json:"peer"`
	Cauthdsl string `json:"cauthdsl"`
	Gossip   string `json:"gossip"`
	Grpc     string `json:"grpc"`
	Ledger   string `json:"ledger"`
	Msp      string `json:"msp"`
	Policies string `json:"policies"`
}
type FabricPeerStorage struct {
	CouchDB   Storage `json:"couchdb"`
	Peer      Storage `json:"peer"`
	Chaincode Storage `json:"chaincode"`
}
type FabricFSServer struct {
	// +kubebuilder:default:="quay.io/kfsoftware/fs-peer"
	Image string `json:"image"`
	// +kubebuilder:default:="amd64-2.2.0"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy"`
}
type FabricPeerCouchDB struct {
	User     string `json:"user"`
	Password string `json:"password"`

	// +kubebuilder:default:="couchdb"
	Image string `json:"image"`
	// +kubebuilder:default:="3.1.1"
	Tag string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy"`

	// +optional
	// +nullable
	ExternalCouchDB *FabricPeerExternalCouchDB `json:"externalCouchDB"`
}

type FabricPeerExternalCouchDB struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}
type FabricIstio struct {
	// +optional
	// +nullable
	Port int `json:"port"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Hosts []string `json:"hosts,omitempty"`
	// +kubebuilder:validation:Default=ingressgateway
	IngressGateway string `json:"ingressGateway"`
}

type FabricPeerSpecGossip struct {
	ExternalEndpoint  string `json:"externalEndpoint"`
	Bootstrap         string `json:"bootstrap"`
	Endpoint          string `json:"endpoint"`
	UseLeaderElection bool   `json:"useLeaderElection"`
	OrgLeader         bool   `json:"orgLeader"`
}
type Catls struct {
	Cacert string `json:"cacert"`
}
type Component struct {
	// +kubebuilder:validation:MinLength=1
	Cahost string `json:"cahost"`
	// +kubebuilder:validation:MinLength=1
	Caname string `json:"caname"`
	Caport int    `json:"caport"`
	Catls  Catls  `json:"catls"`
	// +kubebuilder:validation:MinLength=1
	Enrollid string `json:"enrollid"`
	// +kubebuilder:validation:MinLength=1
	Enrollsecret string `json:"enrollsecret"`
}

func (c *Component) CAUrl() string {
	return fmt.Sprintf("https://%s:%d", c.Cahost, c.Caport)
}

type Csr struct {
	// +optional
	Hosts []string `json:"hosts"`
	// +optional
	CN string `json:"cn"`
}
type TLS struct {
	Cahost string `json:"cahost"`
	Caname string `json:"caname"`
	Caport int    `json:"caport"`
	Catls  Catls  `json:"catls"`
	// +optional
	Csr          Csr    `json:"csr"`
	Enrollid     string `json:"enrollid"`
	Enrollsecret string `json:"enrollsecret"`
}
type Enrollment struct {
	Component Component `json:"component"`
	TLS       TLS       `json:"tls"`
}
type OrdererEnrollment struct {
	Component Component `json:"component"`
	TLS       TLS       `json:"tls"`
}
type Secret struct {
	Enrollment Enrollment `json:"enrollment"`
}
type OrdererNode struct {
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// +optional
	Host string `json:"host"`
	// +optional
	Port       int                   `json:"port"`
	Enrollment OrdererNodeEnrollment `json:"enrollment"`
}
type OrdererNodeEnrollment struct {
	TLS OrdererNodeEnrollmentTLS `json:"tls"`
}
type OrdererNodeEnrollmentTLS struct {
	// +optional
	Csr Csr `json:"csr"`
}

// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
// +kubebuilder:default:NodePort
type ServiceType string

const ServiceTypeNodePort = "NodePort"
const ServiceTypeClusterIP = "ClusterIP"
const ServiceTypeLoadBalancer = "LoadBalancer"

type Service struct {
	Type ServiceType `json:"type"`
}

type PeerService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type corev1.ServiceType `json:"type"`
}

// FabricPeerStatus defines the observed state of FabricPeer
type FabricPeerStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	TlsCACert string `json:"tlsCaCert"`
	// +optional
	SignCACert string `json:"signCaCert"`
	// +optional
	NodePort int `json:"port"`
}
type OrdererService struct {
	// +kubebuilder:validation:Enum=NodePort;ClusterIP;LoadBalancer
	// +kubebuilder:default:NodePort
	Type ServiceType `json:"type"`
}

type OrdererNodeService struct {
	Type               corev1.ServiceType `json:"type"`
	NodePortOperations int                `json:"nodePortOperations,omitempty"`
	NodePortRequest    int                `json:"nodePortRequest,omitempty"`
}

// FabricOrderingServiceSpec defines the desired state of FabricOrderingService
type FabricOrderingServiceSpec struct {
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`
	// +kubebuilder:validation:MinLength=3
	MspID         string               `json:"mspID"`
	Enrollment    OrdererEnrollment    `json:"enrollment"`
	Nodes         []OrdererNode        `json:"nodes"`
	Service       OrdererService       `json:"service"`
	Storage       Storage              `json:"storage"`
	SystemChannel OrdererSystemChannel `json:"systemChannel"`
}
type BootstrapMethod string

const (
	BootstrapMethodNone = "none"
	BootstrapMethodFile = "file"
)

// FabricOrdererNodeSpec defines the desired state of FabricOrdererNode
type FabricOrdererNodeSpec struct {
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +optional
	// +nullable
	GRPCProxy *GRPCProxy `json:"grpcProxy"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +nullable
	UpdateCertificateTime *metav1.Time `json:"updateCertificateTime"`
	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +nullable
	HostAliases []corev1.HostAlias `json:"hostAliases"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	Resources corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:default:=1
	Replicas int `json:"replicas"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Tag string `json:"tag"`

	// +kubebuilder:default:="IfNotPresent"
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// +kubebuilder:validation:MinLength=3
	MspID string `json:"mspID"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	Genesis                     string             `json:"genesis"`
	BootstrapMethod             BootstrapMethod    `json:"bootstrapMethod"`
	ChannelParticipationEnabled bool               `json:"channelParticipationEnabled"`
	Storage                     Storage            `json:"storage"`
	Service                     OrdererNodeService `json:"service"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Secret *Secret `json:"secret"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio *FabricIstio `json:"istio"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	AdminIstio *FabricIstio `json:"adminIstio"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`
}

type OrdererSystemChannel struct {
	// +kubebuilder:validation:MinLength=3
	Name   string        `json:"name"`
	Config ChannelConfig `json:"config"`
}
type OrdererCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ApplicationCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelCapabilities struct {
	V2_0 bool `json:"V2_0"`
}
type ChannelConfig struct {
	BatchTimeout            string                  `json:"batchTimeout"`
	MaxMessageCount         int                     `json:"maxMessageCount"`
	AbsoluteMaxBytes        int                     `json:"absoluteMaxBytes"`
	PreferredMaxBytes       int                     `json:"preferredMaxBytes"`
	OrdererCapabilities     OrdererCapabilities     `json:"ordererCapabilities"`
	ApplicationCapabilities ApplicationCapabilities `json:"applicationCapabilities"`
	ChannelCapabilities     ChannelCapabilities     `json:"channelCapabilities"`
	SnapshotIntervalSize    int                     `json:"snapshotIntervalSize"`
	TickInterval            string                  `json:"tickInterval"`
	ElectionTick            int                     `json:"electionTick"`
	HeartbeatTick           int                     `json:"heartbeatTick"`
	MaxInflightBlocks       int                     `json:"maxInflightBlocks"`
}

// FabricOrderingServiceStatus defines the observed state of FabricOrderingService
type FabricOrderingServiceStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`
}

// FabricOrdererNodeStatus defines the observed state of FabricOrdererNode
type FabricOrdererNodeStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Status     DeploymentStatus  `json:"status"`

	// +optional
	// +nullable
	LastCertificateUpdate *metav1.Time `json:"lastCertificateUpdate"`

	// +optional
	SignCert string `json:"signCert"`
	// +optional
	TlsCert string `json:"tlsCert"`
	// +optional
	SignCACert string `json:"signCaCert"`
	// +optional
	TlsCACert string `json:"tlsCaCert"`
	// +optional
	TlsAdminCert string `json:"tlsAdminCert"`
	// +optional
	OperationsPort int `json:"operationsPort"`
	// +optional
	AdminPort int `json:"adminPort"`
	// +optional
	NodePort int `json:"port"`
	// +optional
	Message string `json:"message"`
}

type Cors struct {
	// +kubebuilder:default:=false
	Enabled bool     `json:"enabled"`
	Origins []string `json:"origins"`
}
type FabricCADatabase struct {
	Type       string `json:"type"`
	Datasource string `json:"datasource"`
}

// FabricCASpec defines the desired state of FabricCA
type FabricCASpec struct {
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	NodeSelector *corev1.NodeSelector `json:"nodeSelector,omitempty"`

	// +optional
	// +nullable
	ServiceMonitor *ServiceMonitor `json:"serviceMonitor"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Istio    *FabricIstio     `json:"istio"`
	Database FabricCADatabase `json:"db"`
	// +kubebuilder:validation:MinItems=1
	// Hosts for the Fabric CA
	Hosts   []string            `json:"hosts"`
	Service FabricCASpecService `json:"service"`
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image"`
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// +kubebuilder:default:=false
	Debug bool `json:"debug"`
	// +kubebuilder:default:=512000
	CLRSizeLimit int              `json:"clrSizeLimit"`
	TLS          FabricCATLSConf  `json:"rootCA"`
	CA           FabricCAItemConf `json:"ca"`
	TLSCA        FabricCAItemConf `json:"tlsCA"`
	Cors         Cors             `json:"cors"`

	Resources corev1.ResourceRequirements `json:"resources"`
	Storage   Storage                     `json:"storage"`
	Metrics   FabricCAMetrics             `json:"metrics"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`
}

type FabricCATLSConf struct {
	Subject FabricCASubject `json:"subject"`
}
type FabricCACFG struct {
	Identities   FabricCACFGIdentities  `json:"identities"`
	Affiliations FabricCACFGAffilitions `json:"affiliations"`
}
type FabricCACFGIdentities struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCACFGAffilitions struct {
	// +kubebuilder:default:=true
	AllowRemove bool `json:"allowRemove"`
}
type FabricCAMetrics struct {
	// +kubebuilder:default:="disabled"
	Provider string `json:"provider"`
	// +optional
	Statsd *FabricCAMetricsStatsd `json:"statsd"`
}
type FabricCAMetricsStatsd struct {
	// +kubebuilder:validation:Enum=udp;tcp
	// +kubebuilder:default:="udp"
	Network string `json:"network"`
	// +optional
	Address string `json:"address"`
	// +optional
	// +kubebuilder:default:="10s"
	WriteInterval string `json:"writeInterval"`
	// +optional
	// +kubebuilder:default:=""
	Prefix string `json:"prefix"`
}

// +kubebuilder:validation:Enum=statsd;prometheus;disabled
type MetricsProvider string

type Storage struct {
	// +kubebuilder:default:="5Gi"
	Size string `json:"size"`
	// +kubebuilder:default:=""
	// +optional
	StorageClass string `json:"storageClass"`
	// +kubebuilder:default:="ReadWriteOnce"
	AccessMode corev1.PersistentVolumeAccessMode `json:"accessMode"`
}

type FabricCASigning struct {
	Default  FabricCASigningDefault  `json:"default"`
	Profiles FabricCASigningProfiles `json:"profiles"`
}
type FabricCASigningProfiles struct {
	CA  FabricCASigningSignProfile `json:"ca"`
	TLS FabricCASigningTLSProfile  `json:"tls"`
}
type FabricCASigningSignProfile struct {
	// +kubebuilder:default:={"cert sign","crl sign"}
	Usage []string `json:"usage"`
	// +kubebuilder:default:="43800h"
	Expiry       string                               `json:"expiry"`
	CAConstraint FabricCASigningSignProfileConstraint `json:"caconstraint"`
}
type FabricCASigningSignProfileConstraint struct {
	// +kubebuilder:default:=true
	IsCA bool `json:"isCA"`
	// +kubebuilder:default:=0
	MaxPathLen int `json:"maxPathLen"`
}
type FabricCASigningTLSProfile struct {
	// +kubebuilder:default:={"signing","key encipherment", "server auth", "client auth", "key agreement"}
	Usage []string `json:"usage"`
	// +kubebuilder:default:="8760h"
	Expiry string `json:"expiry"`
}
type FabricCASigningDefault struct {
	// +kubebuilder:default:="8760h"
	Expiry string `json:"expiry"`
	// +kubebuilder:default:={"digital signature"}
	Usage []string `json:"usage"`
}

type FabricCAAffiliation struct {
	Name        string   `json:"name"`
	Departments []string `json:"departments"`
}

type FabricCAItemConf struct {
	Name    string          `json:"name"`
	CFG     FabricCACFG     `json:"cfg"`
	Subject FabricCASubject `json:"subject"`
	CSR     FabricCACSR     `json:"csr"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	Signing      *FabricCASigning     `json:"signing"`
	CRL          FabricCACRL          `json:"crl"`
	Registry     FabricCARegistry     `json:"registry"`
	Intermediate FabricCAIntermediate `json:"intermediate"`
	BCCSP        FabricCABCCSP        `json:"bccsp"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Affiliations []FabricCAAffiliation `json:"affiliations"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	CA *FabricCACrypto `json:"ca"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	TlsCA *FabricTLSCACrypto `json:"tlsCa"`
}
type FabricTLSCACrypto struct {
	Key        string             `json:"key"`
	Cert       string             `json:"cert"`
	ClientAuth FabricCAClientAuth `json:"clientAuth"`
}
type FabricCAClientAuth struct {
	// NoClientCert, RequestClientCert, RequireAnyClientCert, VerifyClientCertIfGiven and RequireAndVerifyClientCert.
	Type     string   `json:"type"`
	CertFile []string `json:"cert_file"`
}
type FabricCACrypto struct {
	Key   string `json:"key"`
	Cert  string `json:"cert"`
	Chain string `json:"chain"`
}
type FabricCASubject struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCABCCSP struct {
	// +kubebuilder:default:="SW"
	Default string          `json:"default"`
	SW      FabricCABCCSPSW `json:"sw"`
}
type FabricCABCCSPSW struct {
	// +kubebuilder:default:="SHA2"
	Hash string `json:"hash"`
	// +kubebuilder:default:="256"
	Security string `json:"security"`
}

type FabricCAIntermediate struct {
	ParentServer FabricCAIntermediateParentServer `json:"parentServer"`
}
type FabricCAIntermediateParentServer struct {
	URL    string `json:"url"`
	CAName string `json:"caName"`
}
type FabricCAIntermediateEnrollment struct {
	Hosts   string `json:"hosts"`
	Profile string `json:"profile"`
	Label   string `json:"label"`
}
type FabricCAIntermediateTLS struct {
	CertFiles []string                      `json:"certFiles"`
	Client    FabricCAIntermediateTLSClient `json:"client"`
}
type FabricCAIntermediateTLSClient struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}
type FabricCARegistry struct {
	MaxEnrollments int                `json:"max_enrollments"`
	Identities     []FabricCAIdentity `json:"identities"`
}
type FabricCAIdentity struct {
	Name string `json:"name"`
	Pass string `json:"pass"`
	Type string `json:"type"`
	// +kubebuilder:default:=""
	Affiliation string                `json:"affiliation"`
	Attrs       FabricCAIdentityAttrs `json:"attrs"`
}
type FabricCAIdentityAttrs struct {
	// +kubebuilder:default:="*"
	RegistrarRoles string `json:"hf.Registrar.Roles"`
	// +kubebuilder:default:="*"
	DelegateRoles string `json:"hf.Registrar.DelegateRoles"`
	// +kubebuilder:default:="*"
	Attributes string `json:"hf.Registrar.Attributes"`
	// +kubebuilder:default:=true
	Revoker bool `json:"hf.Revoker"`
	// +kubebuilder:default:=true
	IntermediateCA bool `json:"hf.IntermediateCA"`
	// +kubebuilder:default:=true
	GenCRL bool `json:"hf.GenCRL"`
	// +kubebuilder:default:=true
	AffiliationMgr bool `json:"hf.AffiliationMgr"`
}
type FabricCACRL struct {
	// +kubebuilder:default:="24h"
	Expiry string `json:"expiry"`
}
type FabricCACSR struct {
	// +kubebuilder:default:="ca"
	CN string `json:"cn"`
	// +kubebuilder:default:={"localhost"}
	Hosts []string        `json:"hosts"`
	Names []FabricCANames `json:"names"`
	CA    FabricCACSRCA   `json:"ca"`
}
type FabricCACSRCA struct {
	// +kubebuilder:default:="131400h"
	Expiry string `json:"expiry"`
	// +kubebuilder:default:=0
	PathLength int `json:"pathLength"`
}
type FabricCANames struct {
	// +kubebuilder:default:="US"
	C string `json:"C"`
	// +kubebuilder:default:="North Carolina"
	ST string `json:"ST"`
	// +kubebuilder:default:="Hyperledger"
	O string `json:"O"`
	// +kubebuilder:default:="Raleigh"
	L string `json:"L"`
	// +kubebuilder:default:="Fabric"
	OU string `json:"OU"`
}
type FabricCASpecService struct {
	ServiceType corev1.ServiceType `json:"type"`
}
type DeploymentStatus string

const (
	PendingStatus        DeploymentStatus = "PENDING"
	FailedStatus         DeploymentStatus = "FAILED"
	RunningStatus        DeploymentStatus = "RUNNING"
	UnknownStatus        DeploymentStatus = "UNKNOWN"
	UpdatingVersion      DeploymentStatus = "UPDATING_VERSION"
	UpdatingCertificates DeploymentStatus = "UPDATING_CERTIFICATES"
)

// FabricCAStatus defines the observed state of FabricCA
type FabricCAStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`

	// +optional
	NodePort int `json:"nodePort"`
	// TLS Certificate to connect to the FabricCA
	TlsCert string `json:"tls_cert"`
	// Root certificate for Sign certificates generated by FabricCA
	CACert string `json:"ca_cert"`
	// Root certificate for TLS certificates generated by FabricCA
	TLSCACert string `json:"tlsca_cert"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=peer,singular=peer
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricPeer is the Schema for the hlfs API
type FabricPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricPeerSpec   `json:"spec,omitempty"`
	Status FabricPeerStatus `json:"status,omitempty"`
}

func (in *FabricPeer) FullName() string {
	return fmt.Sprintf("%s.%s", in.Name, in.Namespace)
}

// +kubebuilder:object:root=true

// FabricPeerList contains a list of FabricPeer
type FabricPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricPeer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderingservice,singular=orderingservice
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrderingService is the Schema for the hlfs API
type FabricOrderingService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrderingServiceSpec   `json:"spec,omitempty"`
	Status FabricOrderingServiceStatus `json:"status,omitempty"`
}

func (s *FabricOrderingService) FullName() string {
	return fmt.Sprintf("%s.%s", s.Name, s.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrderingServiceList contains a list of FabricOrderingService
type FabricOrderingServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrderingService `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=orderernode,singular=orderernode
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FabricOrdererNode is the Schema for the hlfs API
type FabricOrdererNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FabricOrdererNodeSpec   `json:"spec,omitempty"`
	Status FabricOrdererNodeStatus `json:"status,omitempty"`
}

func (n *FabricOrdererNode) FullName() string {
	return fmt.Sprintf("%s.%s", n.Name, n.Namespace)
}

// +kubebuilder:object:root=true

// FabricOrdererNodeList contains a list of FabricOrdererNode
type FabricOrdererNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOrdererNode `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ca,singular=ca
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricCA is the Schema for the hlfs API
type FabricCA struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricCASpec   `json:"spec,omitempty"`
	Status            FabricCAStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricCAList contains a list of FabricCA
type FabricCAList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricCA `json:"items"`
}

// FabricExplorerSpec defines the desired state of FabricExplorer
type FabricExplorerSpec struct {
	Resources corev1.ResourceRequirements `json:"resources"`
}

// FabricExplorerStatus defines the observed state of FabricExplorer
type FabricExplorerStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=explorer,singular=explorer
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricExplorer is the Schema for the hlfs API
type FabricExplorer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricExplorerSpec   `json:"spec,omitempty"`
	Status            FabricExplorerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricExplorerList contains a list of FabricExplorer
type FabricExplorerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricExplorer `json:"items"`
}

// FabricOperationsConsoleSpec defines the desired state of FabricOperationsConsole
type FabricOperationsConsoleCouchDB struct {
	// +kubebuilder:default:="couchdb"
	Image string `json:"image"`
	// +kubebuilder:default:="3.1.1"
	Tag string `json:"tag"`

	Username string  `json:"username"`
	Password string  `json:"password"`
	Storage  Storage `json:"storage"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
}
type FabricOperationsConsoleAuth struct {
	// +kubebuilder:default:="couchdb"
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// FabricOperationsConsoleSpec defines the desired state of FabricOperationsConsole
type FabricOperationsConsoleSpec struct {
	Auth FabricOperationsConsoleAuth `json:"auth"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`
	// +kubebuilder:default:="ghcr.io/hyperledger-labs/fabric-console"
	Image string `json:"image"`
	// +kubebuilder:default:="latest"
	Tag string `json:"tag"`

	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	CouchDB FabricOperationsConsoleCouchDB `json:"couchDB"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +kubebuilder:default:=3000
	Port int `json:"port"`

	// +optional
	// +nullable
	Config string `json:"config"`

	Ingress Ingress `json:"ingress"`
	HostURL string  `json:"hostUrl"`
}
type Ingress struct {
	// +kubebuilder:default:=true
	Enabled bool `json:"enabled"`

	ClassName string `json:"className"`
	// +kubebuilder:default:={}
	Annotations map[string]string    `json:"annotations"`
	TLS         []v1beta1.IngressTLS `json:"tls"`
	Hosts       []IngressHost        `json:"hosts"`
}

type IngressHost struct {
	Host  string        `json:"host"`
	Paths []IngressPath `json:"paths"`
}
type IngressPath struct {
	// +kubebuilder:default:="/"
	Path string `json:"path"`
	// +kubebuilder:default:="Prefix"
	PathType string `json:"pathType"`
}

// FabricOperationsConsoleStatus defines the observed state of FabricOperationsConsole
type FabricOperationsConsoleStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperationsconsoles,singular=fabricoperationsconsoles
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperationsConsole is the Schema for the hlfs API
type FabricOperationsConsole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperationsConsoleSpec   `json:"spec,omitempty"`
	Status            FabricOperationsConsoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperationsConsoleList contains a list of FabricOperationsConsole
type FabricOperationsConsoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperationsConsole `json:"items"`
}

// FabricOperatorUIStatus defines the observed state of FabricOperatorUI
type FabricOperatorUIStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperatorui,singular=fabricoperatorui
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperatorUI is the Schema for the hlfs API
type FabricOperatorUI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperatorUISpec   `json:"spec,omitempty"`
	Status            FabricOperatorUIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperatorUIList contains a list of FabricOperatorUI
type FabricOperatorUIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperatorUI `json:"items"`
}
type FabricOperatorUIAuth struct {
	OIDCAuthority string `json:"oidcAuthority"`
	OIDCClientId  string `json:"oidcClientId"`
	OIDCScope     string `json:"oidcScope"`
}

// FabricOperatorUISpec defines the desired state of FabricOperatorUI
type FabricOperatorUISpec struct {
	Image string `json:"image"`
	Tag   string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`

	// +kubebuilder:default:=""
	LogoURL string `json:"logoUrl"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Auth *FabricOperatorUIAuth `json:"auth"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`
	// +kubebuilder:validation:Default=1
	Replicas int     `json:"replicas"`
	Ingress  Ingress `json:"ingress"`

	APIURL string `json:"apiUrl"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`
}

// FabricOperatorAPIStatus defines the observed state of FabricOperatorAPI
type FabricOperatorAPIStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricoperatorapi,singular=fabricoperatorapi
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricOperatorAPI is the Schema for the hlfs API
type FabricOperatorAPI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricOperatorAPISpec   `json:"spec,omitempty"`
	Status            FabricOperatorAPIStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricOperatorAPIList contains a list of FabricOperatorAPI
type FabricOperatorAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricOperatorAPI `json:"items"`
}
type FabricOperatorAPIHLFConfig struct {
	MSPID         string                         `json:"mspID"`
	User          string                         `json:"user"`
	NetworkConfig FabricOperatorAPINetworkConfig `json:"networkConfig"`
}
type FabricOperatorAPINetworkConfig struct {
	SecretName string `json:"secretName"`
	Key        string `json:"key"`
}
type FabricOperatorAPIAuth struct {
	OIDCJWKS   string `json:"oidcJWKS"`
	OIDCIssuer string `json:"oidcIssuer"`
}

// FabricOperatorAPISpec defines the desired state of FabricOperatorAPI
type FabricOperatorAPISpec struct {
	Image string `json:"image"`
	Tag   string `json:"tag"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	Istio           FabricIstio       `json:"istio"`
	Ingress         Ingress           `json:"ingress"`
	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Auth *FabricOperatorAPIAuth `json:"auth"`

	HLFConfig FabricOperatorAPIHLFConfig `json:"hlfConfig"`
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`
}

// FabricNetworkConfigSpec defines the desired state of FabricNetworkConfig
type FabricNetworkConfigSpec struct {
	Organization  string   `json:"organization"`
	Internal      bool     `json:"internal"`
	Organizations []string `json:"organizations"`
	SecretName    string   `json:"secretName"`
}

// FabricNetworkConfigStatus defines the observed state of FabricNetworkConfig
type FabricNetworkConfigStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricNetworkConfig
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=networkconfig,singular=networkconfig
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricNetworkConfig is the Schema for the hlfs API
type FabricNetworkConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricNetworkConfigSpec   `json:"spec,omitempty"`
	Status            FabricNetworkConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricNetworkConfigList contains a list of FabricNetworkConfig
type FabricNetworkConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricNetworkConfig `json:"items"`
}

// FabricChaincodeSpec defines the desired state of FabricChaincode
type FabricChaincodeSpec struct {
	Image string `json:"image"`
	// +kubebuilder:default:="IfNotPresent"
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy"`
	// +kubebuilder:validation:MinLength=1
	PackageID string `json:"packageId"`
	// +kubebuilder:validation:Default={}
	// +optional
	// +kubebuilder:validation:Optional
	// +nullable
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Affinity *corev1.Affinity `json:"affinity"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Tolerations []corev1.Toleration `json:"tolerations"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Credentials *TLS `json:"credentials"`

	// +kubebuilder:validation:Default=1
	Replicas int `json:"replicas"`

	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	// +kubebuilder:validation:Default={}
	Env []corev1.EnvVar `json:"env"`
}

// FabricChaincodeStatus defines the observed state of FabricChaincode
type FabricChaincodeStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricChaincode
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=fabricchaincode,singular=fabricchaincode
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricChaincode is the Schema for the hlfs API
type FabricChaincode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricChaincodeSpec   `json:"spec,omitempty"`
	Status            FabricChaincodeStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricChaincodeList contains a list of FabricChaincode
type FabricChaincodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricChaincode `json:"items"`
}

// FabricMainChannelStatus defines the observed state of FabricMainChannel
type FabricMainChannelStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricmainchannel,singular=fabricmainchannel
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricMainChannel is the Schema for the hlfs API
type FabricMainChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricMainChannelSpec   `json:"spec,omitempty"`
	Status            FabricMainChannelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricMainChannelList contains a list of FabricMainChannel
type FabricMainChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricMainChannel `json:"items"`
}

// FabricMainChannelSpec defines the desired state of FabricMainChannel
type FabricMainChannelSpec struct {
	Name string `json:"name"`

	Identities map[string]FabricMainChannelIdentity `json:"identities"`

	AdminPeerOrganizations    []FabricMainChannelAdminPeerOrganizationSpec `json:"adminPeerOrganizations"`
	PeerOrganizations         []FabricMainChannelPeerOrganization          `json:"peerOrganizations"`
	ExternalPeerOrganizations []FabricMainChannelExternalPeerOrganization  `json:"externalPeerOrganizations"`

	// +nullable
	ChannelConfig *FabricMainChannelConfig `json:"channelConfig"`

	AdminOrdererOrganizations    []FabricMainChannelAdminOrdererOrganizationSpec `json:"adminOrdererOrganizations"`
	OrdererOrganizations         []FabricMainChannelOrdererOrganization          `json:"ordererOrganizations"`
	ExternalOrdererOrganizations []FabricMainChannelExternalOrdererOrganization  `json:"externalOrdererOrganizations"`

	Consenters []FabricMainChannelConsenter `json:"orderers"`
}
type FabricMainChannelAdminPeerOrganizationSpec struct {
	MSPID string `json:"mspID"`
}
type FabricMainChannelAdminOrdererOrganizationSpec struct {
	MSPID string `json:"mspID"`
}
type FabricMainChannelConfig struct {
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Application *FabricMainChannelApplicationConfig `json:"application"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Orderer *FabricMainChannelOrdererConfig `json:"orderer"`
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
}

type FabricMainChannelApplicationConfig struct {
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	ACLs *map[string]string `json:"acls"`
}
type FabricMainChannelOrdererConfig struct {
	// +kubebuilder:default:="etcdraft"
	OrdererType string `json:"ordererType"`
	// +kubebuilder:default:={"V2_0"}
	Capabilities []string `json:"capabilities"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Policies *map[string]FabricMainChannelPoliciesConfig `json:"policies"`
	// +kubebuilder:default:="2s"
	BatchTimeout string `json:"batchTimeout"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	BatchSize *FabricMainChannelOrdererBatchSize `json:"batchSize"`
	// +kubebuilder:default:="STATE_NORMAL"
	State FabricMainChannelConsensusState `json:"state"`
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	EtcdRaft *FabricMainChannelEtcdRaft `json:"etcdRaft"`
}

type FabricMainChannelEtcdRaft struct {
	// +nullable
	// +kubebuilder:validation:Optional
	// +optional
	Options *FabricMainChannelEtcdRaftOptions `json:"options"`
}

type FabricMainChannelEtcdRaftOptions struct {
	// +kubebuilder:default:="500ms"
	TickInterval string `json:"tickInterval"`
	// +kubebuilder:default:=10
	ElectionTick uint32 `json:"electionTick"`
	// +kubebuilder:default:=1
	HeartbeatTick uint32 `json:"heartbeatTick"`
	// +kubebuilder:default:=5
	MaxInflightBlocks uint32 `json:"maxInflightBlocks"`
	// 16 MB
	// +kubebuilder:default:=16777216
	SnapshotIntervalSize uint32 `json:"snapshotIntervalSize"`
}
type FabricMainChannelConsensusState string

const (
	ConsensusStateNormal FabricMainChannelConsensusState = "STATE_NORMAL"

	ConsensusStateMaintenance FabricMainChannelConsensusState = "STATE_MAINTENANCE"
)

type FabricMainChannelOrdererBatchSize struct {
	// +kubebuilder:default:=100
	MaxMessageCount int `json:"maxMessageCount"`
	// default is 1024 * 1024
	// +kubebuilder:default:=1048576
	AbsoluteMaxBytes int `json:"absoluteMaxBytes"`
	// default is 512 * 1024
	// +kubebuilder:default:=524288
	PreferredMaxBytes int `json:"preferredMaxBytes"`
}

type FabricMainChannelPoliciesConfig struct {
	Type      string `json:"type"`
	Rule      string `json:"rule"`
	ModPolicy string `json:"modPolicy"`
}

type FabricMainChannelIdentity struct {
	// +kubebuilder:default:=default
	SecretNamespace string `json:"secretNamespace"`
	SecretName      string `json:"secretName"`
	SecretKey       string `json:"secretKey"`
}

type FabricMainChannelConsenter struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	TLSCert string `json:"tlsCert"`
}

type FabricMainChannelOrderer struct {
	URL     string `json:"url"`
	TLSCert string `json:"tlsCert"`
}

type FabricMainChannelExternalPeerOrganization struct {
	MSPID        string `json:"mspID"`
	TLSRootCert  string `json:"tlsRootCert"`
	SignRootCert string `json:"signRootCert"`
}

type FabricMainChannelExternalOrdererOrganization struct {
	MSPID            string   `json:"mspID"`
	TLSRootCert      string   `json:"tlsRootCert"`
	SignRootCert     string   `json:"signRootCert"`
	OrdererEndpoints []string `json:"ordererEndpoints"`
}

type FabricMainChannelPeerOrganization struct {
	MSPID       string `json:"mspID"`
	CAName      string `json:"cAName"`
	CANamespace string `json:"cANamespace"`
}

type FabricMainChannelOrdererOrganization struct {
	MSPID                  string                                 `json:"mspID"`
	CAName                 string                                 `json:"cAName"`
	CANamespace            string                                 `json:"cANamespace"`
	OrdererEndpoints       []string                               `json:"ordererEndpoints"`
	OrderersToJoin         []FabricMainChannelOrdererNode         `json:"orderersToJoin"`
	ExternalOrderersToJoin []FabricMainChannelExternalOrdererNode `json:"externalOrderersToJoin"`
}

type FabricMainChannelExternalOrdererNode struct {
	Host      string `json:"host"`
	AdminPort int    `json:"port"`
}

type FabricMainChannelOrdererNode struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type FabricMainChannelAnchorPeer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// FabricFollowerChannelStatus defines the observed state of FabricFollowerChannel
type FabricFollowerChannelStatus struct {
	Conditions status.Conditions `json:"conditions"`
	Message    string            `json:"message"`
	// Status of the FabricCA
	Status DeploymentStatus `json:"status"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:defaulter-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=fabricfollowerchannel,singular=fabricfollowerchannel
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +k8s:openapi-gen=true

// FabricFollowerChannel is the Schema for the hlfs API
type FabricFollowerChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              FabricFollowerChannelSpec   `json:"spec,omitempty"`
	Status            FabricFollowerChannelStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FabricFollowerChannelList contains a list of FabricFollowerChannel
type FabricFollowerChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricFollowerChannel `json:"items"`
}

// FabricFollowerChannelSpec defines the desired state of FabricFollowerChannel
type FabricFollowerChannelSpec struct {
	Name        string                            `json:"name"`
	MSPID       string                            `json:"mspId"`
	Orderers    []FabricFollowerChannelOrderer    `json:"orderers"`
	PeersToJoin []FabricFollowerChannelPeer       `json:"peersToJoin"`
	AnchorPeers []FabricFollowerChannelAnchorPeer `json:"anchorPeers"`
	HLFIdentity HLFIdentity                       `json:"hlfIdentity"`
}

type FabricFollowerChannelAnchorPeer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type HLFIdentity struct {
	SecretName string `json:"secretName"`
	// +kubebuilder:default:=default
	SecretNamespace string `json:"secretNamespace"`
	SecretKey       string `json:"secretKey"`
}
type FabricFollowerChannelPeer struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type FabricFollowerChannelOrderer struct {
	URL         string `json:"url"`
	Certificate string `json:"certificate"`
}

func init() {
	SchemeBuilder.Register(&FabricPeer{}, &FabricPeerList{})
	SchemeBuilder.Register(&FabricOrderingService{}, &FabricOrderingServiceList{})
	SchemeBuilder.Register(&FabricCA{}, &FabricCAList{})
	SchemeBuilder.Register(&FabricOrdererNode{}, &FabricOrdererNodeList{})
	SchemeBuilder.Register(&FabricExplorer{}, &FabricExplorerList{})
	SchemeBuilder.Register(&FabricNetworkConfig{}, &FabricNetworkConfigList{})
	SchemeBuilder.Register(&FabricChaincode{}, &FabricChaincodeList{})
	SchemeBuilder.Register(&FabricOperationsConsole{}, &FabricOperationsConsoleList{})
	SchemeBuilder.Register(&FabricOperatorUI{}, &FabricOperatorUIList{})
	SchemeBuilder.Register(&FabricOperatorAPI{}, &FabricOperatorAPIList{})
	SchemeBuilder.Register(&FabricMainChannel{}, &FabricMainChannelList{})
	SchemeBuilder.Register(&FabricFollowerChannel{}, &FabricFollowerChannelList{})
}
