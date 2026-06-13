#!/bin/bash
set -euo pipefail

checkout_repo() {
    local checkout=$1
    local repo=$2
    local version=$3
    if [ ! -d "$checkout" ]; then
        git clone --branch "$version" --depth 1 "$repo" "$checkout"
    else
        git -C "$checkout" fetch origin "$version"
        git -C "$checkout" checkout FETCH_HEAD
    fi
}

cd "$(dirname "$0")"

kindcluster="haproxy-conformance"
scriptsdir=$PWD
controllerdir=$(cd .. && pwd)
controllerversion=$(git describe || echo "latest")
basecheckout=${LOCAL_CONFORMANCE:-${controllerdir}/bin/conformance}

gwcheckout=${basecheckout}/gateway-api
gwrepo="https://github.com/kubernetes-sigs/gateway-api"
gwversion=${GATEWAY_API_VERSION:-main}

chcheckout=${basecheckout}/helm-chart
chrepo="https://github.com/haproxy-ingress/charts"
chversion=${HELM_CHART_VERSION:-master}

report=""
gwfeatures=""
gwprofiles="GATEWAY-HTTP,GATEWAY-TLS"
singletest=${GATEWAY_API_RUN_TEST:-}
if [ -z "$singletest" ]; then
    report=${scriptsdir}/report.yaml
    gwfeatures="Gateway,GatewayAddressEmpty,GatewayPort8080"
    gwfeatures+=",HTTPRoute,HTTPRouteBackendProtocolWebSocket,HTTPRouteCORS,HTTPRouteDestinationPortMatching,HTTPRouteNamedRouteRule,HTTPRouteResponseHeaderModification,HTTPRouteSchemeRedirect"
    gwfeatures+=",TLSRoute,TLSRouteModeTerminate"
fi

checkout_repo "$gwcheckout" "$gwrepo" "$gwversion"
checkout_repo "$chcheckout" "$chrepo" "$chversion"

if kind get clusters | grep -q "^${kindcluster}\$"; then
    echo
    echo "Reusing kind cluster, deleting it leads to a fresh new one being created:"
    echo "    kind delete cluster --name $kindcluster"
    kind export kubeconfig --name "$kindcluster"
else
    kind create cluster --name "$kindcluster" --config kind-conformance.yaml
    if [ "$gwversion" = "main" ]; then
        kubectl kustomize ${gwrepo}/config/crd/experimental | kubectl create -f -
    else
        kubectl create -f https://github.com/kubernetes-sigs/gateway-api/releases/download/${gwversion}/experimental-install.yaml
    fi
fi
kind load docker-image localhost/haproxy-ingress:latest --name "$kindcluster"

helm upgrade --install --wait --hide-notes --create-namespace --namespace ingress-controller --values "${scriptsdir}/helm-values-conformance.yaml"\
    haproxy-ingress "${chcheckout}/haproxy-ingress"

cd "${gwcheckout}"
set -x
go test ./conformance -run TestConformance -v -timeout=1h -args\
    --project=haproxy-ingress\
    --organization="HAProxy Ingress"\
    --url=https://haproxy-ingress.github.io\
    --version=${controllerversion}\
    --contact=https://kubernetes.slack.com/channels/haproxy-ingress\
    --gateway-class=haproxy\
    --supported-features=${gwfeatures}\
    --conformance-profiles=${gwprofiles}\
    --report-output=${report}\
    --cleanup-base-resources=false\
    --run-test=${singletest}
