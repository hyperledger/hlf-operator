(window.webpackJsonp=window.webpackJsonp||[]).push([[10],{129:function(e,t,n){"use strict";n.d(t,"a",(function(){return u})),n.d(t,"b",(function(){return d}));var a=n(0),r=n.n(a);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function s(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var c=r.a.createContext({}),p=function(e){var t=r.a.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):s(s({},t),e)),n},u=function(e){var t=p(e.components);return r.a.createElement(c.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return r.a.createElement(r.a.Fragment,{},t)}},b=r.a.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,i=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),u=p(n),b=a,d=u["".concat(i,".").concat(b)]||u[b]||m[b]||o;return n?r.a.createElement(d,s(s({ref:t},c),{},{components:n})):r.a.createElement(d,s({ref:t},c))}));function d(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=b;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s.mdxType="string"==typeof e?e:a,i[1]=s;for(var c=2;c<o;c++)i[c]=n[c];return r.a.createElement.apply(null,i)}return r.a.createElement.apply(null,n)}b.displayName="MDXCreateElement"},80:function(e,t,n){"use strict";n.r(t),n.d(t,"frontMatter",(function(){return s})),n.d(t,"metadata",(function(){return l})),n.d(t,"toc",(function(){return c})),n.d(t,"default",(function(){return u}));var a=n(3),r=n(7),o=(n(0),n(129)),i=["components"],s={id:"getting-started",title:"Getting started"},l={unversionedId:"gateway-api/getting-started",id:"gateway-api/getting-started",isDocsHomePage:!1,title:"Getting started",description:"The gateway-api implementation has been tested with traefik and istio ingress proxies. But the following can be extended to other proxies as well.",source:"@site/docs/gateway-api/getting-started.md",slug:"/gateway-api/getting-started",permalink:"/bevel-operator-fabric/docs/gateway-api/getting-started",editUrl:"https://github.com/hyperledger/bevel-operator-fabric/edit/master/website/docs/gateway-api/getting-started.md",version:"current",sidebar:"someSidebar1",previous:{title:"Introduction",permalink:"/bevel-operator-fabric/docs/gateway-api/introduction"},next:{title:"Implementation",permalink:"/bevel-operator-fabric/docs/gateway-api/implementation"}},c=[{value:"Setup",id:"setup",children:[]},{value:"Traefik implementation",id:"traefik-implementation",children:[]},{value:"Istio implementation",id:"istio-implementation",children:[]}],p={toc:c};function u(e){var t=e.components,n=Object(r.a)(e,i);return Object(o.b)("wrapper",Object(a.a)({},p,n,{components:t,mdxType:"MDXLayout"}),Object(o.b)("p",null,"The gateway-api implementation has been tested with traefik and istio ingress proxies. But the following can be extended to other proxies as well."),Object(o.b)("h2",{id:"setup"},"Setup"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v0.7.0/experimental-install.yaml\n")),Object(o.b)("h2",{id:"traefik-implementation"},"Traefik implementation"),Object(o.b)("p",null,"The first step is to create a service for traefik with necessary RBAC."),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: traefik-controller\n\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: traefik\n\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: traefik-lb\n\n  template:\n    metadata:\n      labels:\n        app: traefik-lb\n\n    spec:\n      serviceAccountName: traefik-controller\n      containers:\n        - name: traefik\n          image: traefik:v2.10\n          args:\n            - --entrypoints.web.address=:80\n            - --entrypoints.websecure.address=:443\n            - --experimental.kubernetesgateway\n            - --providers.kubernetesgateway\n\n          ports:\n            - name: web\n              containerPort: 80\n\n            - name: websecure\n              containerPort: 443\n\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: traefik\n\nspec:\n  type: LoadBalancer\n  selector:\n    app: traefik-lb\n\n  ports:\n    - protocol: TCP\n      port: 80\n      targetPort: web\n      name: web\n\n    - protocol: TCP\n      port: 443\n      targetPort: websecure\n      name: websecure\n")),Object(o.b)("p",null,"RBAC configuration:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},'---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: gateway-role\nrules:\n  - apiGroups:\n      - ""\n    resources:\n      - namespaces\n    verbs:\n      - list\n      - watch\n  - apiGroups:\n      - ""\n    resources:\n      - services\n      - endpoints\n      - secrets\n    verbs:\n      - get\n      - list\n      - watch\n  - apiGroups:\n      - gateway.networking.k8s.io\n    resources:\n      - gatewayclasses\n      - gateways\n      - httproutes\n      - tcproutes\n      - tlsroutes\n    verbs:\n      - get\n      - list\n      - watch\n  - apiGroups:\n      - gateway.networking.k8s.io\n    resources:\n      - gatewayclasses/status\n      - gateways/status\n      - httproutes/status\n      - tcproutes/status\n      - tlsroutes/status\n    verbs:\n      - update\n\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: gateway-controller\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: gateway-role\nsubjects:\n  - kind: ServiceAccount\n    name: traefik-controller\n    namespace: default\n')),Object(o.b)("p",null,"Create a gateway class:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: gateway.networking.k8s.io/v1alpha2\nkind: GatewayClass\nmetadata:\n  name: my-gateway-class #Name of the gateway class\nspec:\n  controllerName: traefik.io/gateway-controller\n")),Object(o.b)("p",null,"Create a Gateway resource:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: gateway.networking.k8s.io/v1alpha2\nkind: Gateway\nmetadata:\n  name: traefik-gateway #Name of the gateway\nspec:\n  gatewayClassName: my-gateway-class #Name of the gateway class to refer to\n  listeners:\n    - protocol: TLS \n      port: 443\n      name: tcp\n      tls:\n        mode: Passthrough\n      allowedRoutes:\n        namespaces:\n            from: Selector\n            selector:\n                matchLabels:\n                    kubernetes.io/metadata.name: hlf #Namespace where the fabric resource is deployed (CA, orderer, peer etc)\n")),Object(o.b)("p",null,"For more info and configuration options refer to: ",Object(o.b)("a",{parentName:"p",href:"https://doc.traefik.io/traefik/routing/providers/kubernetes-gateway/"},"Traefik's Implementation")," "),Object(o.b)("h2",{id:"istio-implementation"},"Istio implementation"),Object(o.b)("p",null,"Install Istio using the minimal profile:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-bash"},"istioctl install --set profile=minimal -y\n")),Object(o.b)("p",null,"By default with this installation, a GatewayClass of name istio would be created."),Object(o.b)("p",null,"Now, Create a Gateway Resource:"),Object(o.b)("pre",null,Object(o.b)("code",{parentName:"pre",className:"language-yaml"},"apiVersion: gateway.networking.k8s.io/v1alpha2\nkind: Gateway\nmetadata:\n  name: istio-gateway #Name of the gateway\nspec:\n  gatewayClassName: istio #Name of the gateway class to refer to\n  listeners:\n    - protocol: TLS \n      port: 443\n      name: tcp\n      tls:\n        mode: Passthrough\n      allowedRoutes:\n        namespaces:\n            from: Selector\n            selector:\n                matchLabels:\n                    kubernetes.io/metadata.name: hlf #Namespace where the fabric resource is deployed (CA, orderer, peer etc)\n")),Object(o.b)("p",null,"For more info and configuration options refer to: ",Object(o.b)("a",{parentName:"p",href:"https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/"},"Istio's Implementation")))}u.isMDXComponent=!0}}]);