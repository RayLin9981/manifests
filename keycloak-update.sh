KEYCLOAK_ISSUER="https://keycloak.fck8slab.local/realms/kubeflow"
CLIENT_ID="kubeflow-oidc-authservice"
CLIENT_SECRET="XuusjyZGIdERHCg2nGK0ZWoZtcbMHFpu"
REDIRECT_URI="http://kubeflow.fck8slab.local:31080/dex/callback"
DEX_ISSUER="http://kubeflow.fck8slab.local:31080/dex"

tee common/dex/overlays/oauth2-proxy/config-map.yaml <<- DEX_CONFIG
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex
data:
  config.yaml: |
    issuer: $DEX_ISSUER
    storage:
      type: kubernetes
      config:
        inCluster: true
    web:
      http: 0.0.0.0:5556
    logger:
      level: "debug"
      format: text
    oauth2:
      skipApprovalScreen: true
    enablePasswordDB: false
    # staticPasswords:
    # - email: user@example.com
    #   hashFromEnv: DEX_USER_PASSWORD
    #   username: user
    #   userID: "15841185641784"
    staticClients:
    - idEnv: OIDC_CLIENT_ID
      redirectURIs: ["/oauth2/callback"]
      name: 'Dex Login Application'
      secretEnv: OIDC_CLIENT_SECRET
    connectors:
    - type: oidc
      id: keycloak
      name: keycloak
      config:
        issuer: $KEYCLOAK_ISSUER
        clientID: $CLIENT_ID
        clientSecret: $CLIENT_SECRET
        redirectURI: $REDIRECT_URI
        insecure: false
        insecureSkipEmailVerified: true
        userNameKey: email       
        scopes:
          - openid
          - profile
          - email
          - offline_access
DEX_CONFIG


kustomize build common/dex/overlays/oauth2-proxy | kubectl delete -f -
kustomize build common/dex/overlays/oauth2-proxy | kubectl apply -f -

#--- step2 oauth
tee common/oauth2-proxy/base/oauth2_proxy.cfg <<- OAUTH2_PROXY_CONFIG
provider = "oidc"
oidc_issuer_url = "$DEX_ISSUER"
scope = "profile email offline_access openid"
email_domains = "*"
insecure_oidc_allow_unverified_email = "true"

upstreams = [ "static://200" ]

skip_auth_routes = [
  "^/dex/",
]

api_routes = [
  "/api/",
  "/apis/",
  "^/ml_metadata",
]

skip_oidc_discovery = true
login_url = "/dex/auth"
redeem_url = "http://dex.auth.svc.cluster.local:5556/dex/token"
oidc_jwks_url = "http://dex.auth.svc.cluster.local:5556/dex/keys"

skip_provider_button = false

provider_display_name = "Dex"
custom_sign_in_logo = "/custom-theme/kubeflow-logo.svg"
banner = "-"
footer = "-"

prompt = "none"

set_authorization_header = true
set_xauthrequest = true

cookie_name = "oauth2_proxy_kubeflow"
cookie_expire = "24h"
cookie_refresh = 0

code_challenge_method = "S256"

redirect_url = "/oauth2/callback"
relative_redirect_url = true
OAUTH2_PROXY_CONFIG


kustomize build common/oauth2-proxy/overlays/m2m-dex-only/ | kubectl delete -f -
kustomize build common/oauth2-proxy/overlays/m2m-dex-only/ | kubectl apply -f -



#--- step3 dex

tee common/oauth2-proxy/components/istio-external-auth/requestauthentication.dex-jwt.yaml <<- ISTIO_REQUEST_AUTH_CONFIG
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: dex-jwt
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-ingressgateway
  jwtRules:
  - issuer: $DEX_ISSUER
    forwardOriginalToken: true
    outputClaimToHeaders:
    - header: kubeflow-userid
      claim: email
    - header: kubeflow-groups
      claim: groups
    fromHeaders:
    - name: Authorization
      prefix: "Bearer "
ISTIO_REQUEST_AUTH_CONFIG


# For Kubeflow 1.91, change istio-1-24 to istio-1-22
kustomize build common/istio-1-24/istio-install/overlays/oauth2-proxy | kubectl delete -f -
kustomize build common/istio-1-24/istio-install/overlays/oauth2-proxy | kubectl apply -f -
kustomize build common/oauth2-proxy/overlays/m2m-dex-only/ | kubectl delete -f -
kustomize build common/oauth2-proxy/overlays/m2m-dex-only/ | kubectl apply -f -


kubectl create secret generic fck8slabrootca.crt --from-file=/root/cert/rootCA/cert/fck8slab-rootCA.crt -n auth
