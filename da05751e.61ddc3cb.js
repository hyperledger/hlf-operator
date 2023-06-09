(window.webpackJsonp=window.webpackJsonp||[]).push([[49],{120:function(e,a,t){"use strict";t.r(a),t.d(a,"frontMatter",(function(){return s})),t.d(a,"metadata",(function(){return i})),t.d(a,"toc",(function(){return l})),t.d(a,"default",(function(){return d}));var r=t(3),n=t(7),o=(t(0),t(129)),c=["components"],s={id:"implementation",title:"Implementation"},i={unversionedId:"gateway-api/implementation",id:"gateway-api/implementation",isDocsHomePage:!1,title:"Implementation",description:"With the GatewayClass and Gateway resources of your respective proxy setup, let's create the fabric resources like CA, peer and orderer.",source:"@site/docs/gateway-api/implementation.md",slug:"/gateway-api/implementation",permalink:"/bevel-operator-fabric/docs/gateway-api/implementation",editUrl:"https://github.com/hyperledger/bevel-operator-fabric/edit/master/website/docs/gateway-api/implementation.md",version:"current",sidebar:"someSidebar1",previous:{title:"Getting started",permalink:"/bevel-operator-fabric/docs/gateway-api/getting-started"},next:{title:"Using external CouchDB",permalink:"/bevel-operator-fabric/docs/couchdb/external-couchdb"}},l=[{value:"Setup",id:"setup",children:[{value:"Create CA",id:"create-ca",children:[]},{value:"Create Peers",id:"create-peers",children:[]},{value:"Create Ordering Node",id:"create-ordering-node",children:[]}]}],p={toc:l};function d(e){var a=e.components,t=Object(n.a)(e,c);return Object(o.b)("wrapper",Object(r.a)({},p,t,{components:a,mdxType:"MDXLayout"}),Object(o.b)("p",null,"With the GatewayClass and Gateway resources of your respective proxy setup, let's create the fabric resources like CA, peer and orderer."),Object(o.b)("p",null,"Note that this setup is similiar to the original setup given in the docs where we are using coredns to resolve the ip addresses. The gateway api implementation also works externally by making the gateway-api service a LoadBalancer."),Object(o.b)("p",null,"The first step is to get the address of the gateway which needs to be resolved for the fabric resources."),Object(o.b)("p",null,"For istio:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"export INGRESS_HOST=$(kubectl get gateways.gateway.networking.k8s.io gateway -n istio-ingress -ojsonpath='{.status.addresses[*].value}')\n")),Object(o.b)("p",null,"For traefik, the ingress host is the ClusterIP of the traefik-service which is deployed earlier in the setup"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"export INGRESS_HOST=$(kubectl get svc traefik -n gateway-api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')\n")),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl apply -f - <<EOF\nkind: ConfigMap\napiVersion: v1\nmetadata:\n  name: coredns\n  namespace: kube-system\ndata:\n  Corefile: |\n    .:53 {\n        errors\n        health {\n           lameduck 5s\n        }\n        rewrite name regex (.*)\\.localho\\.st host.ingress.internal\n        hosts {\n          ${INGRESS_HOST} host.ingress.internal\n          fallthrough\n        }\n        ready\n        kubernetes cluster.local in-addr.arpa ip6.arpa {\n           pods insecure\n           fallthrough in-addr.arpa ip6.arpa\n           ttl 30\n        }\n        prometheus :9153\n        forward . /etc/resolv.conf {\n           max_concurrent 1000\n        }\n        cache 30\n        loop\n        reload\n        loadbalance\n    }\nEOF\n")),Object(o.b)("h2",{id:"setup"},"Setup"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"export PEER_IMAGE=hyperledger/fabric-peer\nexport PEER_VERSION=2.4.6\n\nexport ORDERER_IMAGE=hyperledger/fabric-orderer\nexport ORDERER_VERSION=2.4.6\n\nexport CA_IMAGE=hyperledger/fabric-ca\nexport CA_VERSION=1.5.6-beta2\n\nexport NAMESPACE=hlf\nexport GATEWAYNAME=gateway  \nexport GATEWAYNAMESPACE=istio-ingress  \n\n")),Object(o.b)("p",null,"Watch out for the following configuration:"),Object(o.b)("p",null,"--gateway-api-hosts : The hosts that are configured to be used with gateway-api\n--gateway-api-name : The name of the gateway (Name of the 'Gateway' Resource created earlier)\n--gateway-api-namespace : The namespace where the 'Gateway' resource is deployed"),Object(o.b)("h3",{id:"create-ca"},"Create CA"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ca create  --image=$CA_IMAGE --version=$CA_VERSION --storage-class=standard --capacity=1Gi --name=org1-ca     --enroll-id=enroll --enroll-pw=enrollpw --gateway-api-hosts=org1-ca.localho.st --gateway-api-name $GATEWAYNAME --gateway-api-namespace $GATEWAYNAMESPACE -n $NAMESPACE\n")),Object(o.b)("p",null,"Make sure the CA is reachable and gives a response"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"curl -k https://org1-ca.localho.st:443/cainfo\n")),Object(o.b)("h3",{id:"create-peers"},"Create Peers"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"}," kubectl hlf peer create --statedb=couchdb --image=$PEER_IMAGE --version=$PEER_VERSION --storage-class=standard --enroll-id=peer --mspid=Org1MSP \\\n        --enroll-pw=peerpw --capacity=5Gi --name=org1-peer0 --ca-name=org1-ca.$NAMESPACE \\\n        --gateway-api-hosts=peer0-org1.localho.st --gateway-api-name $GATEWAYNAME --gateway-api-namespace $GATEWAYNAMESPACE -n $NAMESPACE\n")),Object(o.b)("p",null,"Make sure the Peer is reachable and gives a response"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"openssl s_client -connect peer0-org1.localho.st:443\n")),Object(o.b)("h3",{id:"create-ordering-node"},"Create Ordering Node"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl hlf ordnode create --image=$ORDERER_IMAGE --version=$ORDERER_VERSION \\\n    --storage-class=standard --enroll-id=orderer --mspid=OrdererMSP \\\n    --enroll-pw=ordererpw --capacity=2Gi --name=ord-node1 --ca-name=ord-ca.$NAMESPACE \\\n    --gateway-api-hosts=orderer0-ord.localho.st --gateway-api-name $GATEWAYNAME --gateway-api-namespace $GATEWAYNAMESPACE -n $NAMESPACE --admin-gateway-api-hosts orderer0-ord-admin.localho.st\n")),Object(o.b)("p",null,"Make sure the Orderer is reachable and gives a response"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"openssl s_client -connect orderer0-ord.localho.st:443\n")))}d.isMDXComponent=!0},129:function(e,a,t){"use strict";t.d(a,"a",(function(){return d})),t.d(a,"b",(function(){return g}));var r=t(0),n=t.n(r);function o(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function c(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);a&&(r=r.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,r)}return t}function s(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?c(Object(t),!0).forEach((function(a){o(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):c(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function i(e,a){if(null==e)return{};var t,r,n=function(e,a){if(null==e)return{};var t,r,n={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],a.indexOf(t)>=0||(n[t]=e[t]);return n}(e,a);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(n[t]=e[t])}return n}var l=n.a.createContext({}),p=function(e){var a=n.a.useContext(l),t=a;return e&&(t="function"==typeof e?e(a):s(s({},a),e)),t},d=function(e){var a=p(e.components);return n.a.createElement(l.Provider,{value:a},e.children)},u={inlineCode:"code",wrapper:function(e){var a=e.children;return n.a.createElement(n.a.Fragment,{},a)}},b=n.a.forwardRef((function(e,a){var t=e.components,r=e.mdxType,o=e.originalType,c=e.parentName,l=i(e,["components","mdxType","originalType","parentName"]),d=p(t),b=r,g=d["".concat(c,".").concat(b)]||d[b]||u[b]||o;return t?n.a.createElement(g,s(s({ref:a},l),{},{components:t})):n.a.createElement(g,s({ref:a},l))}));function g(e,a){var t=arguments,r=a&&a.mdxType;if("string"==typeof e||r){var o=t.length,c=new Array(o);c[0]=b;var s={};for(var i in a)hasOwnProperty.call(a,i)&&(s[i]=a[i]);s.originalType=e,s.mdxType="string"==typeof e?e:r,c[1]=s;for(var l=2;l<o;l++)c[l]=t[l];return n.a.createElement.apply(null,c)}return n.a.createElement.apply(null,t)}b.displayName="MDXCreateElement"}}]);