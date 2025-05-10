#!/bin/sh
curl -sSL \
  https://github.com/mikefarah/yq/releases/download/v4.44.1/yq_linux_amd64 \
  -o /usr/local/bin/yq && chmod +x /usr/local/bin/yq 

npm install -g @openai/codex

# sudo apt-get update && sudo apt-get install -y --no-install-recommends curl vim gpg ca-certificates
# curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/trusted.gpg.d/smallstep.asc && \
#     echo 'deb [signed-by=/etc/apt/trusted.gpg.d/smallstep.asc] https://packages.smallstep.com/stable/debian debs main' \
#     | tee /etc/apt/sources.list.d/smallstep.list
# sudo apt-get update && sudo apt-get -y install step-cli

curl -fsSL https://github.com/Azure/azure-workload-identity/releases/download/v1.5.0/azwi-v1.5.0-linux-amd64.tar.gz \
 | tar -xz -C /tmp
sudo install -m0755 /tmp/azwi /usr/local/bin/azwi
az extension add --name aks-preview --only-show-errors >/dev/null 2>&1 || true

curl -fsSL https://github.com/ducaale/xh/releases/download/v0.17.0/xh-v0.17.0-x86_64-unknown-linux-musl.tar.gz \
    | tar -xz -C /usr/local/bin --strip-components=1

# curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
# sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
# rm argocd-linux-amd64

# kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "NodePort"}}'
# kubectl port-forward svc/argocd-server -n argocd 8080:443

## Install rad CLI
CURRENT_BRANCH=$(git branch --show-current)

if [ "$CURRENT_BRANCH" = "edge" ]; then
    RADIUS_VERSION=edge
else
    ## If CURRENT_BRANCH matches a regex of the form "v0.20", set RADIUS_VERSION to the matching string minus the "v"
    if [[ "$CURRENT_BRANCH" =~ ^v[0-9]+\.[0-9]+$ ]]; then
        RADIUS_VERSION=${CURRENT_BRANCH:1}
    else
        ## Otherwise, set RADIUS_VERSION to "edge"
        RADIUS_VERSION=edge
    fi
fi

wget -q "https://raw.githubusercontent.com/radius-project/radius/main/deploy/install.sh" -O - | /bin/bash
