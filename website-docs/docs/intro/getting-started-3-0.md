---
id: getting-started-3-0
title: Getting started with Hyperledger Fabric 3.0
---

# Hyperledger Fabric 3.0

This workshop is divided in this steps:

1. [Create kubernetes cluster](#1-create-kubernetes-cluster)
2. [Install and configure Istio](#2-install-and-configure-istio)
3. [Install Hyperledger Fabric operator](#3-install-hyperledger-fabric-operator)
4. [Deploy a peer organization](#4-deploy-a-peer-organization)
5. [Deploy an orderer organization](#5-deploy-an-orderer-organization)
6. [Create a channel](#6-create-a-channel)
7. [Join peer to the channel](#7-join-peer-to-the-channel)
8. [Install a chaincode](#8-install-a-chaincode)
9. [Deploy chaincode container on cluster](#9-deploy-chaincode-container-on-cluster)
10. [Approve chaincode](#10-approve-chaincode)
11. [Commit chaincode](#11-commit-chaincode)
12. [Invoke a transaction on the channel](#12-invoke-a-transaction-on-the-channel)
13. [Query assets in the channel](#13-query-assets-in-the-channel)
14. [Completion](#14-completion)

In order to follow the workshop, you have two options, follow the Loom video or follow the steps below.

Run through the steps explaining what we are going to do and how to do it.

## 1. Create kubernetes cluster

To start deploying our red fabric we have to have a Kubernetes cluster. For this we will use KinD.

Ensure you have these ports available before creating the cluster:

-   80
-   443

If these ports are not available this tutorial will not work.

### Using K3D

```bash
k3d cluster create  -p "80:30949@agent:0" -p "443:30950@agent:0" --agents 2 k8s-hlf
```

### Using KinD

```bash
cat << EOF > kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.27.3
  extraPortMappings:
  - containerPort: 30949
    hostPort: 80
  - containerPort: 30950
    hostPort: 443
EOF

kind create cluster --config=./kind-config.yaml

```

## 2. Install and configure Istio

Install Istio binaries on the machine:

```bash
# add TARGET_ARCH=x86_64 if you are using arm64
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.20.0 sh -
export PATH="$PATH:$PWD/istio-1.20.0/bin"
```

Install Istio on the Kubernetes cluster:

```bash

kubectl create namespace istio-system

istioctl operator init

kubectl apply -f - <<EOF
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: istio-gateway
  namespace: istio-system
spec:
  addonComponents:
    grafana:
      enabled: false
    kiali:
      enabled: false
    prometheus:
      enabled: false
    tracing:
      enabled: false
  components:
    ingressGateways:
      - enabled: true
        k8s:
          hpaSpec:
            minReplicas: 2
          resources:
            limits:
              cpu: 500m
              memory: 512Mi
            requests:
              cpu: 100m
              memory: 128Mi
          service:
            ports:
              - name: http
                port: 80
                targetPort: 8080
                nodePort: 30949
              - name: https
                port: 443
                targetPort: 8443
                nodePort: 30950
            type: NodePort
        name: istio-ingressgateway
    pilot:
      enabled: true
      k8s:
        hpaSpec:
          minReplicas: 1
        resources:
          limits:
            cpu: 300m
            memory: 512Mi
          requests:
            cpu: 100m
            memory: 128Mi
  meshConfig:
    accessLogFile: /dev/stdout
    enableTracing: false
    outboundTrafficPolicy:
      mode: ALLOW_ANY
  profile: default

EOF
```

### Configure Internal DNS

This needs to be applied every time you restart the machine.

```bash
kubectl apply -f - <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        rewrite name regex (.*)\.localho\.st istio-ingressgateway.istio-system.svc.cluster.local
        hosts {
          fallthrough
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
    }
EOF
```

## 3. Install Hyperledger Fabric operator

In this step we are going to install the kubernetes operator for Fabric, this will install:

-   CRD (Custom Resource Definitions) to deploy Certification Fabric Peers, Orderers and Authorities
-   Deploy the program to deploy the nodes in Kubernetes

To install helm: [https://helm.sh/docs/intro/install/](https://helm.sh/docs/intro/install/)

```bash
helm repo add kfs https://kfsoftware.github.io/hlf-helm-charts --force-update

helm upgrade --install hlf-operator --version=1.11.0-beta3 -- kfs/hlf-operator

```


### Install the Kubectl plugin

To install the kubectl plugin, you must first install Krew:
[https://krew.sigs.k8s.io/docs/user-guide/setup/install/](https://krew.sigs.k8s.io/docs/user-guide/setup/install/)

Afterwards, the plugin can be installed with the following command:

```bash
kubectl krew install hlf
```

## 4. Deploy a peer organization

### Environment Variables for AMD and ARM

```bash
export PEER_IMAGE=hyperledger/fabric-peer
export PEER_VERSION=3.0.0

export ORDERER_IMAGE=hyperledger/fabric-orderer
export ORDERER_VERSION=3.0.0

export CA_IMAGE=hyperledger/fabric-ca
export CA_VERSION=1.5.13
```

### Deploy a certificate authority

```bash
export STORAGE_CLASS=local-path # k3d storage class, "standard" for KinD
kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=$STORAGE_CLASS --capacity=1Gi --name=org1-ca \
    --enroll-id=enroll --enroll-pw=enrollpw --hosts=org1-ca.localho.st --istio-port=443

kubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all
```

Check that the certification authority is deployed and works:

```bash
curl -k https://org1-ca.localho.st:443/cainfo
```

Register a user in the certification authority of the peer organization (Org1MSP)

```bash
# register user in CA for peers
kubectl hlf ca register --name=org1-ca --user=peer --secret=peerpw --type=peer \
 --enroll-id enroll --enroll-secret=enrollpw --mspid Org1MSP

```

### Deploy a peer 

```bash

kubectl hlf peer create --statedb=leveldb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=$STORAGE_CLASS --enroll-id=peer --mspid=Org1MSP \
        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer0 --ca-name=org1-ca.default \
        --hosts=peer0-org1.localho.st --istio-port=443


kubectl hlf peer create --statedb=leveldb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=$STORAGE_CLASS --enroll-id=peer --mspid=Org1MSP \
        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer1 --ca-name=org1-ca.default \
        --hosts=peer1-org1.localho.st --istio-port=443


kubectl wait --timeout=180s --for=condition=Running fabricpeers.hlf.kungfusoftware.es --all
```

Check that the peer is deployed and works:

```bash
openssl s_client -connect peer0-org1.localho.st:443
openssl s_client -connect peer1-org1.localho.st:443
```

## 5. Deploy an orderer organization

To deploy an `Orderer` organization we have to:

1. Create a certification authority
2. Register user `orderer` with password `ordererpw`
3. Create orderer

### Create the certification authority

```bash

kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=$STORAGE_CLASS --capacity=1Gi --name=ord-ca \
    --enroll-id=enroll --enroll-pw=enrollpw --hosts=ord-ca.localho.st --istio-port=443

kubectl wait --timeout=180s --for=condition=Running fabriccas.hlf.kungfusoftware.es --all

```

Check that the certification authority is deployed and works:

```bash
curl -vik https://ord-ca.localho.st:443/cainfo
```

### Register user `orderer`

```bash
kubectl hlf ca register --name=ord-ca --user=orderer --secret=ordererpw \
    --type=orderer --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP --ca-url="https://ord-ca.localho.st:443"

```

### Deploy orderer

```bash

kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \
    --storage-class=$STORAGE_CLASS --enroll-id=orderer --mspid=OrdererMSP \
    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node1 --ca-name=ord-ca.default \
    --hosts=orderer0-ord.localho.st --admin-hosts=admin-orderer0-ord.localho.st --istio-port=443


kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \
    --storage-class=$STORAGE_CLASS --enroll-id=orderer --mspid=OrdererMSP \
    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node2 --ca-name=ord-ca.default \
    --hosts=orderer1-ord.localho.st --admin-hosts=admin-orderer1-ord.localho.st --istio-port=443

kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \
    --storage-class=$STORAGE_CLASS --enroll-id=orderer --mspid=OrdererMSP \
    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node3 --ca-name=ord-ca.default \
    --hosts=orderer2-ord.localho.st --admin-hosts=admin-orderer2-ord.localho.st --istio-port=443


kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \
    --storage-class=$STORAGE_CLASS --enroll-id=orderer --mspid=OrdererMSP \
    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node4 --ca-name=ord-ca.default \
    --hosts=orderer3-ord.localho.st --admin-hosts=admin-orderer3-ord.localho.st --istio-port=443

# 3/4

kubectl wait --timeout=180s --for=condition=Running fabricorderernodes.hlf.kungfusoftware.es --all
```

Check that the orderer is running:

```bash
kubectl get pods
```

```bash
openssl s_client -connect orderer0-ord.localho.st:443
```

## 6. Create a channel

To create the channel we need to first create the wallet secret, which will contain the identities used by the operator to manage the channel

### Register and enrolling OrdererMSP identity

```bash
# register
kubectl hlf ca register --name=ord-ca --user=admin --secret=adminpw \
    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=OrdererMSP


kubectl hlf identity create --name orderer-admin-sign --namespace default \
    --ca-name ord-ca --ca-namespace default \
    --ca ca --mspid OrdererMSP --enroll-id admin --enroll-secret adminpw # sign identity

kubectl hlf identity create --name orderer-admin-tls --namespace default \
    --ca-name ord-ca --ca-namespace default \
    --ca tlsca --mspid OrdererMSP --enroll-id admin --enroll-secret adminpw # tls identity

```

### Register and enrolling Org1MSP identity

```bash
# register
kubectl hlf ca register --name=org1-ca --namespace=default --user=admin --secret=adminpw \
    --type=admin --enroll-id enroll --enroll-secret=enrollpw --mspid=Org1MSP

# enroll
kubectl hlf identity create --name org1-admin --namespace default \
    --ca-name org1-ca --ca-namespace default \
    --ca ca --mspid Org1MSP --enroll-id admin --enroll-secret adminpw

```

### Create main channel

```bash
export IDENT_12=$(printf "%16s" "")
# tls CA certificate
export ORDERER_TLS_CERT=$(kubectl get fabriccas ord-ca -o=jsonpath='{.status.tlsca_cert}' | sed -e "s/^/${IDENT_12}/" )

export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER1_TLS_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER2_TLS_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER3_TLS_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_12}/" )

export ORDERER0_SIGN_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.signCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER1_SIGN_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath='{.status.signCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER2_SIGN_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath='{.status.signCert}' | sed -e "s/^/${IDENT_12}/" )
export ORDERER3_SIGN_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath='{.status.signCert}' | sed -e "s/^/${IDENT_12}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricMainChannel
metadata:
  name: demo
spec:
  name: demo
  adminOrdererOrganizations:
    - mspID: OrdererMSP
  adminPeerOrganizations:
    - mspID: Org1MSP
  channelConfig:
    application:
      acls: null
      capabilities:
        - V2_5
      policies: null
    capabilities:
      - V3_0
    orderer:
      batchSize:
        absoluteMaxBytes: 1048576
        maxMessageCount: 100
        preferredMaxBytes: 524288
      batchTimeout: 2s
      capabilities:
        - V2_0
      smartBFT:
        request_batch_max_count: 100
        request_batch_max_bytes: 10485760
        request_batch_max_interval: "50ms"
        incoming_message_buffer_size: 200
        request_pool_size: 100000
        request_forward_timeout: "2s"
        request_complain_timeout: "20s"
        request_auto_remove_timeout: "3m"
        view_change_resend_interval: "5s"
        view_change_timeout: "20s"
        leader_heartbeat_timeout: "1m0s"
        leader_heartbeat_count: 10
        collect_timeout: "1s"
        sync_on_start: true
        speed_up_view_change: false
        leader_rotation: 1 # off
        decisions_per_leader: 3
        request_max_bytes: 0

      consenterMapping:
      - host: orderer0-ord.localho.st
        port: 443
        id: 1
        msp_id: OrdererMSP
        client_tls_cert: |
${ORDERER0_TLS_CERT}

        server_tls_cert: |
${ORDERER0_TLS_CERT}

        identity: |
${ORDERER0_SIGN_CERT}

      - host: orderer1-ord.localho.st
        port: 443
        id: 2
        msp_id: OrdererMSP
        client_tls_cert: |
${ORDERER1_TLS_CERT}

        server_tls_cert: |
${ORDERER1_TLS_CERT}

        identity: |
${ORDERER1_SIGN_CERT}

      - host: orderer2-ord.localho.st
        port: 443
        id: 3
        msp_id: OrdererMSP
        client_tls_cert: |
${ORDERER2_TLS_CERT}

        server_tls_cert: |
${ORDERER2_TLS_CERT}

        identity: |
${ORDERER2_SIGN_CERT}

      - host: orderer3-ord.localho.st
        port: 443
        id: 4
        msp_id: OrdererMSP
        client_tls_cert: |
${ORDERER3_TLS_CERT}

        server_tls_cert: |
${ORDERER3_TLS_CERT}

        identity: |
${ORDERER3_SIGN_CERT}

      ordererType: BFT
      policies: null
      state: STATE_NORMAL
    policies: null
  externalOrdererOrganizations: []
  peerOrganizations:
    - mspID: Org1MSP
      caName: "org1-ca"
      caNamespace: "default"
  identities:
    OrdererMSP:
      secretKey: user.yaml
      secretName: orderer-admin-tls
      secretNamespace: default
    OrdererMSP-sign:
      secretKey: user.yaml
      secretName: orderer-admin-sign
      secretNamespace: default
    Org1MSP:
      secretKey: user.yaml
      secretName: org1-admin
      secretNamespace: default
  externalPeerOrganizations: []
  ordererOrganizations:
    - caName: "ord-ca"
      caNamespace: "default"
      externalOrderersToJoin:
        - host: ord-node1
          port: 7053
        - host: ord-node2
          port: 7053
        - host: ord-node3
          port: 7053
        - host: ord-node4
          port: 7053
      mspID: OrdererMSP
      ordererEndpoints:
        - orderer0-ord.localho.st:443
        - orderer1-ord.localho.st:443
        - orderer2-ord.localho.st:443
        - orderer3-ord.localho.st:443
      orderersToJoin: []
  orderers:
    - host: ord-node1
      port: 7050
      tlsCert: |
${ORDERER0_TLS_CERT}
    - host: ord-node2
      port: 7050
      tlsCert: |-
${ORDERER1_TLS_CERT}
    - host: ord-node3
      port: 7050
      tlsCert: |-
${ORDERER2_TLS_CERT}
    - host: ord-node4
      port: 7050
      tlsCert: |-
${ORDERER2_TLS_CERT}

EOF
```

### Create main channel using ETCDRaft

```bash
export PEER_ORG_SIGN_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath='{.status.ca_cert}')
export PEER_ORG_TLS_CERT=$(kubectl get fabriccas org1-ca -o=jsonpath='{.status.tlsca_cert}')
export IDENT_8=$(printf "%8s" "")
export ORDERER_TLS_CERT=$(kubectl get fabriccas ord-ca -o=jsonpath='{.status.tlsca_cert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER1_TLS_CERT=$(kubectl get fabricorderernodes ord-node2 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER2_TLS_CERT=$(kubectl get fabricorderernodes ord-node3 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )
export ORDERER3_TLS_CERT=$(kubectl get fabricorderernodes ord-node4 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricMainChannel
metadata:
  name: demo
spec:
  name: demo
  adminOrdererOrganizations:
    - mspID: OrdererMSP
  adminPeerOrganizations:
    - mspID: Org1MSP
  channelConfig:
    application:
      acls: null
      capabilities:
        - V2_0
      policies: null
    capabilities:
      - V2_0
    orderer:
      batchSize:
        absoluteMaxBytes: 1048576
        maxMessageCount: 10
        preferredMaxBytes: 524288
      batchTimeout: 2s
      capabilities:
        - V2_0
      etcdRaft:
        options:
          electionTick: 10
          heartbeatTick: 1
          maxInflightBlocks: 5
          snapshotIntervalSize: 16777216
          tickInterval: 500ms
      ordererType: etcdraft
      policies: null
      state: STATE_NORMAL
    policies: null
  externalOrdererOrganizations: []
  peerOrganizations:
    - mspID: Org1MSP
      caName: "org1-ca"
      caNamespace: "default"
  identities:
    OrdererMSP:
      secretKey: user.yaml
      secretName: orderer-admin-tls
      secretNamespace: default
    OrdererMSP-sign:
      secretKey: user.yaml
      secretName: orderer-admin-sign
      secretNamespace: default
    Org1MSP:
      secretKey: user.yaml
      secretName: org1-admin
      secretNamespace: default
  externalPeerOrganizations: []
  ordererOrganizations:
    - caName: "ord-ca"
      caNamespace: "default"
      externalOrderersToJoin:
        - host: ord-node1
          port: 7053
        - host: ord-node2
          port: 7053
        - host: ord-node3
          port: 7053
        - host: ord-node4
          port: 7053
      mspID: OrdererMSP
      ordererEndpoints:
        - ord-node1:7050
        - ord-node2:7050
        - ord-node3:7050
        - ord-node4:7050
      orderersToJoin: []
  orderers:
    - host: ord-node1
      port: 7050
      tlsCert: |-
${ORDERER0_TLS_CERT}
    - host: ord-node2
      port: 7050
      tlsCert: |-
${ORDERER1_TLS_CERT}
    - host: ord-node3
      port: 7050
      tlsCert: |-
${ORDERER2_TLS_CERT}
    - host: ord-node4
      port: 7050
      tlsCert: |-
${ORDERER3_TLS_CERT}

EOF

```


## 7. Join peer to the channel

To join the peers from Org1MSP to the channel `demo` we need to create a `FabricFollowerChannel` resource:

```bash

export IDENT_8=$(printf "%8s" "")
export ORDERER0_TLS_CERT=$(kubectl get fabricorderernodes ord-node1 -o=jsonpath='{.status.tlsCert}' | sed -e "s/^/${IDENT_8}/" )

kubectl apply -f - <<EOF
apiVersion: hlf.kungfusoftware.es/v1alpha1
kind: FabricFollowerChannel
metadata:
  name: demo-org1msp
spec:
  anchorPeers:
    - host: org1-peer0.default
      port: 7051
    - host: org1-peer1.default
      port: 7051
  hlfIdentity:
    secretKey: user.yaml
    secretName: org1-admin
    secretNamespace: default
  mspId: Org1MSP
  name: demo
  externalPeersToJoin: []
  orderers:
    - certificate: |
${ORDERER0_TLS_CERT}
      url: grpcs://ord-node1.default:7050
  peersToJoin:
    - name: org1-peer0
      namespace: default
    - name: org1-peer1
      namespace: default
EOF

```

## 8. Install a chaincode

### Prepare connection string for a peer

To prepare the connection string, we have to:

1. Create `FabricNetworkConfig` object in the Kubernetes cluster
2. Fetch the connection string from the Kubernetes secret

3. Get connection string without users for organization Org1MSP and OrdererMSP

```bash

# This identity will register and enroll the user
kubectl hlf identity create --name org1-admin --namespace default \
    --ca-name org1-ca --ca-namespace default \
    --ca ca --mspid Org1MSP --enroll-id explorer-admin --enroll-secret explorer-adminpw \
    --ca-enroll-id=enroll --ca-enroll-secret=enrollpw --ca-type=admin


kubectl hlf networkconfig create --name=org1-cp \
  -o Org1MSP -o OrdererMSP -c demo \
  --identities=org1-admin.default --secret=org1-cp
```

### Fetch the connection string from the Kubernetes secret

```bash
kubectl get secret org1-cp -o jsonpath="{.data.config\.yaml}" | base64 --decode > org1.yaml
```

### Create metadata file

```bash
# remove the code.tar.gz chaincode.tgz if they exist
rm code.tar.gz chaincode.tgz
export CHAINCODE_NAME=asset
export CHAINCODE_LABEL=asset
cat << METADATA-EOF > "metadata.json"
{
    "type": "ccaas",
    "label": "${CHAINCODE_LABEL}"
}
METADATA-EOF
```

### Prepare connection file

```bash
## chaincode as a service
cat > "connection.json" <<CONN_EOF
{
  "address": "${CHAINCODE_NAME}:7052",
  "dial_timeout": "10s",
  "tls_required": false
}
CONN_EOF

tar cfz code.tar.gz connection.json
tar cfz chaincode.tgz metadata.json code.tar.gz
export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=chaincode.tgz --language=node --label=$CHAINCODE_LABEL)
echo "PACKAGE_ID=$PACKAGE_ID"

kubectl hlf chaincode install --path=./chaincode.tgz \
    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=org1-admin-default --peer=org1-peer0.default

kubectl hlf chaincode install --path=./chaincode.tgz \
    --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=org1-admin-default --peer=org1-peer1.default

```

### Check if the chaincode is installed

TO check if the chaincode is installed, we can use the following command:

```bash
kubectl hlf chaincode queryinstalled --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default
```

It should return something like this:

```text
PACKAGE ID                                                              LABEL   REFERENCES
asset:f1056c50a23f901d2aa6893505eef057db548f0775003dabbfd1f500877acda8  asset   {"demo":[{"name":"asset","version":"1.0"}]}
```

## 9. Deploy chaincode container on cluster

The following command will create or update the CRD based on the packageID, chaincode name, and docker image.

```bash
kubectl hlf externalchaincode sync --image=kfsoftware/chaincode-external:latest \
    --name=$CHAINCODE_NAME \
    --namespace=default \
    --package-id=$PACKAGE_ID \
    --tls-required=false \
    --replicas=1
```

## 10. Approve chaincode

To approve the chaincode definition for org1, run the following command:

```bash
export SEQUENCE=1
export VERSION="1.0"
kubectl hlf chaincode approveformyorg --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default \
    --package-id=$PACKAGE_ID \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo
```

## 11. Commit chaincode

To commit chaincode to the channel, run the following command:

```bash
kubectl hlf chaincode commit --config=org1.yaml --user=org1-admin-default --mspid=Org1MSP \
    --version "$VERSION" --sequence "$SEQUENCE" --name=asset \
    --policy="OR('Org1MSP.member')" --channel=demo
```

## 12. Invoke a transaction on the channel

Now that we have committed the chaincode to the channel, we can interact with it.

We will use the kubectl plugin to interact with the chaincode. The plugin is a wrapper around the go-fabric SDK and provides a more user-friendly interface.

### Invoke a transaction on the channel

```bash
kubectl hlf chaincode invoke --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=initLedger

```

## 13. Query assets in the channel

To query the chaincode, run the following command:

```bash
kubectl hlf chaincode query --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=GetAllAssets -a '[]'
```

# 13.1 Create an asset

Create an asset
```bash
kubectl hlf chaincode invoke --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=CreateAsset -a "asset7" -a blue -a "5" -a "tom" -a "100"
```

# 13.2 Query the asset

Query the asset we just created
```bash
kubectl hlf chaincode query --config=org1.yaml \
    --user=org1-admin-default --peer=org1-peer0.default \
    --chaincode=asset --channel=demo \
    --fcn=ReadAsset -a asset7
```

## 14. Completion

Congratulations! You have completed the workshop.

At this point, you must have:

-   Ordering service with 3 nodes and a CA
-   Peer organization with a peer and a CA
-   A channel **demo**
-   A chaincode install in peer0
-   A chaincode approved and committed

If something went wrong or didn't work, please, open an issue.

## Cleanup the environment

```bash
kubectl delete fabricorderernodes.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricpeers.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabriccas.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricchaincode.hlf.kungfusoftware.es --all-namespaces --all
kubectl delete fabricmainchannels --all-namespaces --all
kubectl delete fabricfollowerchannels --all-namespaces --all
```
