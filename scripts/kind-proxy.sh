#!/usr/bin/env bash

: "${SCRIPT_PATH:=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
set -Eeuo pipefail

log() {
  printf "[%s] %s\n" "$(date +'%H:%M:%S')" "$*"
}

launch_kind_api_proxy() {
  log "Launching NGINX stream-proxy on host.docker.internal:6445"

  # Find the control-plane container for the current Kind cluster
  local CP
  CP=$(docker ps --filter "label=io.x-k8s.kind.cluster=${KIND_CLUSTER_NAME}"                  --filter "label=io.x-k8s.kind.role=control-plane"                  --format '{{.Names}}')
  if [[ -z "${CP}" ]]; then
    log "Could not locate Kind control-plane container for cluster '${KIND_CLUSTER_NAME}'." >&2
    return 1
  fi

  # Workspace for ephemeral build context
  : "${WORK_DIR:=$(mktemp -d)}"

  # Generate minimal NGINX config
  cat >"${WORK_DIR}/nginx-kind.conf" <<EOF
events {}
stream {
  upstream apiserver { server ${CP}:6443; }
  server {
    listen 6443;
    proxy_pass apiserver;
  }
}
EOF

  # Dockerfile for the proxy image
  cat >"${WORK_DIR}/Dockerfile" <<'EOF'
FROM nginx:1.25-alpine
COPY nginx-kind.conf /etc/nginx/nginx.conf
CMD ["nginx","-g","daemon off;","-c","/etc/nginx/nginx.conf"]
EOF

  docker build -q -f "${WORK_DIR}/Dockerfile" -t kind-api-proxy-img "${WORK_DIR}"
  docker rm -f kind-api-proxy >/dev/null 2>&1 || true
  docker run -d --name kind-api-proxy --network kind -p 6445:6443 kind-api-proxy-img

  # Wait until the proxy is up
  until curl -ks https://host.docker.internal:6445/livez >/dev/null 2>&1; do sleep 2; done
}

patch_kubeconfigs() {
  log "Patching kubeconfigs to use host.docker.internal:6445"

  local KCONF="$HOME/.kube/config"
  kind get kubeconfig --name "${KIND_CLUSTER_NAME}" > "$KCONF"
  # replace only the server line
  sed -i -E 's#(^[[:space:]]*server:).*#\1 https://host.docker.internal:6445#' "$KCONF"
  export KUBECONFIG="$KCONF"

  # select the new context **here**
  kubectl config use-context "kind-${KIND_CLUSTER_NAME}"

  # write a copy for Headlamp
  local WIN_KCONF="${SCRIPT_PATH}/kind-headlamp.yaml"
  kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "$WIN_KCONF"
  sed -i -E 's#(^[[:space:]]*server:).*#\1 https://localhost:6445#' "$WIN_KCONF"
  chmod 0644 "$WIN_KCONF"
  log "📄  Headlamp kubeconfig written to $WIN_KCONF"
}


