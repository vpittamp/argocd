#!/usr/bin/env bash
# shellcheck disable=SC2155,SC2086
###############################################################################
# wi-kind-setup.sh — create / reuse a Kind cluster + Azure OIDC infrastructure
#
# Tools required: azure-cli • kind • kubectl • openssl • jq • helm • curl • azwi
###############################################################################

set -Eeuo pipefail
log() { printf '[%(%T)T] %s\n' -1 "$*"; }

###############################################################################
# 0. DNS sanity -- be sure we can resolve public hosts
###############################################################################
wait_for_dns() {
  local host=login.microsoftonline.com
  for i in {1..30}; do
    getent hosts "$host" &>/dev/null && return
    echo "⏳  Waiting for DNS… ($i/30)"; sleep 2
  done
  echo "❌  DNS unresolved after 60 s – aborting." >&2; exit 1
}
wait_for_dns

###############################################################################
# 1. Azure session
###############################################################################
ensure_az_login() {
  for i in {1..3}; do
    az account show -o none &>/dev/null && return
    echo "🔑  No Azure session – launching device-code login…"
    az login --use-device-code --output none || true
    sleep 3
  done
  echo "❌  Azure login failed." >&2; exit 1
}
ensure_az_login
# SUBSCRIPTION_ID=$(az account show --query id -o tsv)

###############################################################################
# 2. Args / constants
###############################################################################
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_IMAGE_VERSION="${KIND_IMAGE_VERSION:-v1.29.0}"
AZURE_STORAGE_CONTAINER='$web'   # static-website container
WI_ENV="${SCRIPT_PATH}/../.devcontainer/wi.env"

help() { echo "Usage: $0 <LOCATION> <RESOURCE_GROUP> [KEYVAULT_NAME]"; exit 0; }
[[ ${1:-} =~ ^-h|--help$ ]] && help
# LOCATION="${1:?LOCATION missing}"
# RESOURCE_GROUP="${2:?RESOURCE_GROUP missing}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-$RESOURCE_GROUP}"
# KEYVAULT_NAME="${3:-${KEYVAULT_NAME:-}}"
APP_NAME="${KIND_CLUSTER_NAME}-radius-app"

###############################################################################
# 3. Storage account – reuse or create
###############################################################################
[[ -f "$WI_ENV" ]] && source <(grep -E '^(AZURE_STORAGE_ACCOUNT|KEYVAULT_NAME)=' "$WI_ENV") || true
STG_ARGS=()   # set when AZURE_STORAGE_ACCOUNT is final

storage_oidc_valid() {
  local ep issuer
  ep=$(az storage account show -n "$AZURE_STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" \
        --query "primaryEndpoints.web" -otsv 2>/dev/null) || return 1
  az storage blob service-properties show --account-name "$AZURE_STORAGE_ACCOUNT" \
        --auth-mode login --query "staticWebsite.enabled" -otsv | grep -q true || return 1
  issuer=$(az storage blob download --auth-mode login -c "$AZURE_STORAGE_CONTAINER" \
            --account-name "$AZURE_STORAGE_ACCOUNT" \
            -n ".well-known/openid-configuration" --file - --no-progress 2>/dev/null \
          | jq -r '.issuer' 2>/dev/null) || return 1
  [[ "$issuer" == "$ep" ]] || return 1
  az storage blob show --auth-mode login -c "$AZURE_STORAGE_CONTAINER" \
       --account-name "$AZURE_STORAGE_ACCOUNT" -n "openid/v1/jwks" &>/dev/null
}

clear_saved_sa_if_invalid() {
  [[ -z "${AZURE_STORAGE_ACCOUNT:-}" ]] && return
  STG_ARGS=(--account-name "$AZURE_STORAGE_ACCOUNT" --auth-mode login)
  if ! storage_oidc_valid; then
    log "⚠️  Stored account '$AZURE_STORAGE_ACCOUNT' is absent or OIDC-incomplete – recreating"
    sed -i '/^AZURE_STORAGE_ACCOUNT=/d' "$WI_ENV" 2>/dev/null || true
    unset AZURE_STORAGE_ACCOUNT
  fi
}
clear_saved_sa_if_invalid

AZURE_STORAGE_ACCOUNT=${AZURE_STORAGE_ACCOUNT:-"oidcissuer$(openssl rand -hex 4)"}
STG_ARGS=(--account-name "$AZURE_STORAGE_ACCOUNT" --auth-mode login)

ensure_blob_contrib() {
  local me; me=$(az ad signed-in-user show --query id -o tsv)
  az role assignment list --assignee "$me" \
      --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
      --query "[?roleDefinitionName=='Storage Blob Data Contributor']" -o tsv \
      | grep -q . && return
  log "🔑  Granting *Storage Blob Data Contributor* on RG '$RESOURCE_GROUP' to you…"
  az role assignment create --assignee "$me" \
      --role 'Storage Blob Data Contributor' \
      --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" -o none
}

create_azure_blob_storage_account() {
  log "🔧  Preparing Azure Storage…"
  az group show -n "$RESOURCE_GROUP" -o none 2>/dev/null \
      || az group create -n "$RESOURCE_GROUP" -l "$LOCATION" -o none

  for _ in {1..5}; do
    if az storage account show -n "$AZURE_STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" \
          --auth-mode login &>/dev/null; then
      log "ℹ️  Storage account '$AZURE_STORAGE_ACCOUNT' already exists – re-using"
      break
    fi
    if az storage account check-name --name "$AZURE_STORAGE_ACCOUNT" \
          --query nameAvailable -o tsv | grep -q true; then
      az storage account create -n "$AZURE_STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" \
         --allow-blob-public-access true -o none && break
    fi
    AZURE_STORAGE_ACCOUNT="oidcissuer$(openssl rand -hex 4)"
    STG_ARGS=(--account-name "$AZURE_STORAGE_ACCOUNT" --auth-mode login)
  done

  az storage account show -n "$AZURE_STORAGE_ACCOUNT" -g "$RESOURCE_GROUP" &>/dev/null \
      || { echo "❌  Could not allocate a unique storage account name"; exit 1; }

  az storage blob service-properties update "${STG_ARGS[@]}" --static-website -o none
  az storage container show "${STG_ARGS[@]}" -n "$AZURE_STORAGE_CONTAINER" &>/dev/null || \
      az storage container create "${STG_ARGS[@]}" -n "$AZURE_STORAGE_CONTAINER" \
          --public-access blob -o none
  log "✅  Storage account ready: $AZURE_STORAGE_ACCOUNT"
  ensure_blob_contrib

  grep -q '^AZURE_STORAGE_ACCOUNT=' "$WI_ENV" 2>/dev/null \
      && sed -i "s|^AZURE_STORAGE_ACCOUNT=.*|AZURE_STORAGE_ACCOUNT=$AZURE_STORAGE_ACCOUNT|" "$WI_ENV" \
      || echo "AZURE_STORAGE_ACCOUNT=$AZURE_STORAGE_ACCOUNT" >> "$WI_ENV"
}

###############################################################################
# 4. OIDC discovery + JWKS blobs
###############################################################################
SERVICE_ACCOUNT_ISSUER=""

upload_or_replace() {
  az storage blob upload "${STG_ARGS[@]}" -c "$AZURE_STORAGE_CONTAINER" \
     -f "$1" -n "$2" --overwrite true --only-show-errors
}

upload_openid_docs() {
  SERVICE_ACCOUNT_ISSUER=$(az storage account show -n "$AZURE_STORAGE_ACCOUNT" \
                           -o json | jq -r '.primaryEndpoints.web')
  cat >"$SCRIPT_PATH/openid-configuration.json" <<EOF
{
  "issuer": "${SERVICE_ACCOUNT_ISSUER}",
  "jwks_uri": "${SERVICE_ACCOUNT_ISSUER}openid/v1/jwks",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
EOF
  upload_or_replace "$SCRIPT_PATH/openid-configuration.json" ".well-known/openid-configuration"
  kubectl get --raw /openid/v1/jwks 2>/dev/null | jq -c . >"$SCRIPT_PATH/jwks.json" || echo '{ "keys": [] }' >"$SCRIPT_PATH/jwks.json"
  upload_or_replace "$SCRIPT_PATH/jwks.json" "openid/v1/jwks"
}

###############################################################################
# 5. Kind + proxy helpers
###############################################################################
create_kind_cluster() {
  SERVICE_ACCOUNT_ISSUER=$(az storage account show -n "$AZURE_STORAGE_ACCOUNT" \
                           -o json | jq -r '.primaryEndpoints.web')
  log "☸️  (re)creating Kind cluster '$KIND_CLUSTER_NAME'"
  kind delete cluster --name "$KIND_CLUSTER_NAME" &>/dev/null || true
  cat <<EOF | kind create cluster --name "$KIND_CLUSTER_NAME" \
                   --image "kindest/node:${KIND_IMAGE_VERSION}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        service-account-issuer: ${SERVICE_ACCOUNT_ISSUER}
      certSANs:
      - host.docker.internal
      - localhost
EOF
}

source "$SCRIPT_PATH/kind-proxy.sh"

retry_proxy() {
  for i in 1 2; do
    launch_kind_api_proxy && return
    log "⚠️  Proxy launch failed (attempt $i) – retrying in 3 s"; sleep 3
  done
  log "❌  Proxy failed twice – continuing without stream-proxy"
}

install_workload_identity_webhook() {
  log "📦  Installing Azure Workload-Identity webhook"
  helm repo add azure-workload-identity https://azure.github.io/azure-workload-identity/charts >/dev/null || true
  helm repo update >/dev/null
  helm upgrade --install workload-identity-webhook azure-workload-identity/workload-identity-webhook \
      --namespace azure-workload-identity-system --create-namespace \
      --set "azureTenantID=$(az account show --query tenantId -o tsv)" --wait
}

###############################################################################
# 6.  Radius / App-registration consistency
###############################################################################
ensure_radius_app_registration() {
  
  local APP_ID OBJECT_ID FIC_ISSUER

  APP_ID=$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv || true)
  [[ -z "$APP_ID" ]] && { log "ℹ️  No existing Radius app – will create fresh"; return; }

  OBJECT_ID=$(az ad app show --id "$APP_ID" --query id -o tsv)
  FIC_ISSUER=$(az ad app federated-credential list --id "$OBJECT_ID" \
                 --query '[0].issuer' -o tsv 2>/dev/null || echo "")

  if [[ "$FIC_ISSUER" != "$SERVICE_ACCOUNT_ISSUER" ]]; then
    log "⚠️  Existing app '$APP_NAME' uses issuer '$FIC_ISSUER' – deleting to avoid drift"
    az ad sp delete --id "$APP_ID" --output none 2>/dev/null || true
    az ad app delete --id "$APP_ID" --output none 2>/dev/null || true

   else
    log "ℹ️  Existing Radius app already aligned with issuer – keeping"
  fi
}

run_rad_identity() {
  local sub
  sub=$(az account show --query id -o tsv)
  "$SCRIPT_PATH/../.devcontainer/rad-identity.sh" \
      "$KIND_CLUSTER_NAME" "$RESOURCE_GROUP" "$sub" "$SERVICE_ACCOUNT_ISSUER"
}

install_radius() {
  log "📦  Installing Radius control-plane and wiring Azure creds"
  local CTX="kind-${KIND_CLUSTER_NAME}"

  rm -f "$HOME/.rad/config.yaml" 2>/dev/null || true
  rad install kubernetes --set global.azureWorkloadIdentity.enabled=true \
                         --set 'rp.publicEndpointOverride=localhost:8080'
  for d in applications-rp bicep-de controller ucp; do
    kubectl --context "$CTX" -n radius-system rollout status deployment/"$d" --timeout=300s
  done
  # --- local workspace wiring (unchanged) ---
  local APP_NAME="${KIND_CLUSTER_NAME}-radius-app"
  local APP_ID
  APP_ID=$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv)

  rad group create local  2>/dev/null || true
  rad env   create local --group local 2>/dev/null || true
  rad workspace create kubernetes --context "$CTX" --group local --environment local 2>/dev/null || true
  rad env update local --group local --azure-subscription-id "$SUBSCRIPTION_ID" \
        --azure-resource-group "$RESOURCE_GROUP" --workspace "$CTX"
  rad credential register azure wi --client-id "$APP_ID" --tenant-id "$TENANT_ID" --workspace "$CTX"
}

first_kid() { jq -r '.keys[0].kid // ""' <<<"$1"; }

ensure_cluster_oidc_matches_storage() {
  local cluster_issuer storage_issuer cluster_jwks storage_jwks
  cluster_issuer=$(kubectl --context "kind-${KIND_CLUSTER_NAME}" \
                     get --raw /.well-known/openid-configuration 2>/dev/null \
                   | jq -r '.issuer // empty')
  [[ -n "$cluster_issuer" ]] || { echo "❌  Cluster did not expose discovery doc" >&2; exit 1; }
  storage_issuer=$(curl -fsSL "${SERVICE_ACCOUNT_ISSUER}.well-known/openid-configuration" | jq -r .issuer)
  log "› cluster_issuer : $cluster_issuer"; log "› storage_issuer : $storage_issuer"
  [[ "$cluster_issuer" == "$SERVICE_ACCOUNT_ISSUER" && "$storage_issuer" == "$SERVICE_ACCOUNT_ISSUER" ]] || {
    echo "❌  Issuer mismatch between cluster/storage/current" >&2; exit 1; }
  cluster_jwks=$(kubectl --context "kind-${KIND_CLUSTER_NAME}" get --raw /openid/v1/jwks | jq -cS .)
  storage_jwks=$(curl -fsSL "${SERVICE_ACCOUNT_ISSUER}openid/v1/jwks"                  | jq -cS .)
  log "› cluster_kid   : $(first_kid "$cluster_jwks")"
  log "› storage_kid   : $(first_kid "$storage_jwks")"
  [[ "$cluster_jwks" == "$storage_jwks" ]] || { echo "❌  JWKS mismatch" >&2; exit 1; }
  log "🔒  Cluster OIDC settings verified against storage (issuer & keys match)"
  
}

###############################################################################
# 7. External-Secrets / Workload-Identity integration
###############################################################################
ESO_NS="${ESO_NS:-external-secrets}"
SA_NAME="${SA_NAME:-workload-identity-sa}"
APP_NAME="${KIND_CLUSTER_NAME}-radius-app"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv)
TARGET_KV_ROLE="${TARGET_KV_ROLE:-Key Vault Secrets User}"
NAMESPACE="${NAMESPACE:-external-secrets}"
TEST_ES_NAME="${TEST_ES_NAME:-kv-demo-es}"
TEST_K8S_SECRET_NAME="${TEST_K8S_SECRET_NAME:-kv-demo-secret}"
K8S_SECRET_KEY_NAME="${K8S_SECRET_KEY_NAME:-demo}"
KV_SECRET_NAME_TO_TEST="${KV_SECRET_NAME_TO_TEST:-demo}"

resolve_keyvault() {
  if [[ -z "$KEYVAULT_NAME" ]]; then
    KEYVAULT_NAME=$(az keyvault list -g "$RESOURCE_GROUP" --query '[0].name' -o tsv 2>/dev/null || true)
  fi
  [[ -n "$KEYVAULT_NAME" ]] || { echo "❌  Key Vault name not provided and none found in RG" >&2; exit 1; }
  VAULT_ID=$(az keyvault show -n "$KEYVAULT_NAME" --query id -o tsv)
  VAULT_URL="https://${KEYVAULT_NAME}.vault.azure.net"
  grep -q '^KEYVAULT_NAME=' "$WI_ENV" 2>/dev/null \
      && sed -i "s|^KEYVAULT_NAME=.*|KEYVAULT_NAME=$KEYVAULT_NAME|" "$WI_ENV" \
      || echo "KEYVAULT_NAME=$KEYVAULT_NAME" >> "$WI_ENV"
}

install_external_secrets_operator() {
  log "📦  Installing External Secrets Operator"
  helm repo add external-secrets https://charts.external-secrets.io >/dev/null || true
  helm repo update >/dev/null
  helm upgrade --install external-secrets external-secrets/external-secrets \
       -n "$ESO_NS" --create-namespace --wait
}

create_eso_service_account() {
  local current_app_id sp_object_id existing_assignment

  SERVICE_ACCOUNT_ISSUER=$(az storage account show -n "$AZURE_STORAGE_ACCOUNT" \
                               -o json | jq -r '.primaryEndpoints.web')
  
  log "🔧 Preparing to set up ServiceAccount '$SA_NAME' for AAD App '$APP_NAME' with Workload Identity."

  # Step 1: Use azwi to manage AAD App, Service Principal, and Federated Identity.
  # We will let it attempt the role assignment, but we'll verify/ensure it ourselves later.
  log "⚙️  Running 'azwi serviceaccount create' to manage AAD app, SP, and federated identity..."
  # Note: $APP_NAME, $ESO_NS, $SA_NAME, $SERVICE_ACCOUNT_ISSUER, $VAULT_ID, $TARGET_KV_ROLE 
  # are expected to be set before this function is called or globally.
  azwi serviceaccount create phase federated-identity \
  --aad-application-name "$APP_NAME" \
  --service-account-namespace "$ESO_NS" \
  --service-account-name "$SA_NAME" \
  --service-account-issuer-url "$SERVICE_ACCOUNT_ISSUER"

  azwi serviceaccount create phase sa \
    --aad-application-name "$APP_NAME" \
    --service-account-namespace "$ESO_NS" \
    --service-account-name "$SA_NAME"

  if [[ -n "$REGISTRY_NS" && -n "$REGISTRY_NAME" ]]; then
    # make sure namespace exists
    kubectl get ns "$REGISTRY_NS" >/dev/null 2>&1 || kubectl create ns "$REGISTRY_NS"

    azwi serviceaccount create phase federated-identity \
      --aad-application-name "$APP_NAME" \
      --service-account-namespace "$REGISTRY_NS" \
      --service-account-name "$REGISTRY_NAME" \
      --service-account-issuer-url "$SERVICE_ACCOUNT_ISSUER"

    azwi serviceaccount create phase sa \
      --aad-application-name "$APP_NAME" \
      --service-account-namespace "$REGISTRY_NS" \
      --service-account-name "$REGISTRY_NAME"
  fi

  # Step 2: Get the App ID for the application.
  # $APP_NAME is typically ${KIND_CLUSTER_NAME}-radius-app
  log "🔎 Fetching App ID for application: '$APP_NAME'..."
  current_app_id="$(az ad sp list --display-name "${APP_NAME}" --query '[0].appId' -otsv)"

  if [[ -z "$current_app_id" ]]; then
    log "❌ ERROR: Could not find App ID for application named '$APP_NAME' after azwi execution. Cannot proceed with explicit Key Vault role assignment."
    return 1 
  fi
  log "ℹ️  App ID for '$APP_NAME' is '$current_app_id'."

  # Step 3: Get the Service Principal Object ID for the App ID.
  # This can sometimes take a few moments to be consistently available after SP creation.
  log "🔎 Fetching Service Principal Object ID for App ID '$current_app_id'..."
  for i in {1..4}; do # Increased retries slightly
    sp_object_id=$(az ad sp show --id "$current_app_id" --query "id" -o tsv 2>/dev/null)
    if [[ -n "$sp_object_id" ]]; then
      log "ℹ️  Service Principal Object ID is '$sp_object_id'."
      break
    fi
    if [[ "$i" -lt 4 ]]; then
        log "⏳ WARN: Service Principal for App ID '$current_app_id' not found (attempt $i/4). Waiting 15 seconds for AAD replication..."
        sleep 15
    fi
  done

  if [[ -z "$sp_object_id" ]]; then
    log "❌ ERROR: Could not find Service Principal Object ID for App ID '$current_app_id' after multiple attempts. Cannot proceed with explicit Key Vault role assignment."
    log "ℹ️  This might indicate an issue with the AAD app/SP creation by 'azwi' or significant AAD replication delays."
    log "ℹ️  Please check Azure portal for Service Principal related to App ID '$current_app_id'."
    return 1 
  fi

  # Step 4: Explicitly ensure the "Key Vault Secrets User" role assignment.
  # VAULT_ID is the full resource ID of the Key Vault.
  # TARGET_KV_ROLE is typically "Key Vault Secrets User".
  log "🔐 Ensuring '$TARGET_KV_ROLE' role for Service Principal '$sp_object_id' on Key Vault scope '$VAULT_ID'..."
  
  # Check if the assignment already exists.
  # Suppress errors for the list command if it returns empty, which is not an error for this check.
  existing_assignment=$(az role assignment list --assignee "$sp_object_id" --role "$TARGET_KV_ROLE" --scope "$VAULT_ID" --query "[0].id" -o tsv 2>/dev/null)
  
  if [[ -n "$existing_assignment" ]]; then
    log "✅ Role assignment '$TARGET_KV_ROLE' already exists for Service Principal '$sp_object_id' on the Key Vault."
  else
    log "⏳ Role assignment '$TARGET_KV_ROLE' not found or not yet visible for SP '$sp_object_id'. Attempting to create it..."
    # Add a specific delay before attempting to create the role assignment,
    # as the Service Principal might have just become queryable.
    sleep 20 # Increased delay before attempting assignment
    if az role assignment create --assignee "$sp_object_id" --role "$TARGET_KV_ROLE" --scope "$VAULT_ID" --output none; then
      log "✅ Successfully created '$TARGET_KV_ROLE' role assignment for Service Principal '$sp_object_id' on the Key Vault."
    else
      log "❌ ERROR: Failed to create '$TARGET_KV_ROLE' role assignment for Service Principal '$sp_object_id' on the Key Vault. Please check permissions and Azure activity logs."
      # Depending on strictness, you might want to make this a fatal error (return 1)
      # For now, logging as an error but allowing script to continue, assuming other parts might still work
      # or that azwi might have done something that eventually propagates.
      # However, if ESO needs this, this is a critical failure for ESO.
      return 1 # Making this a failure as it's critical for ESO
    fi
  fi
  log "✅ Key Vault permissions setup for Service Principal '$sp_object_id' appears complete."
}

apply_template() {
  local tpl="$1"
  [[ -f "$tpl" ]] || { echo "❌  Template not found: $tpl" >&2; exit 1; }

  # Ensure all variables used by any .tpl file in DEPLOY_DIR are exported
  # APP_ID should be the client ID of rg3-radius-app, set globally in Section 7.
  # TENANT_ID should be from devcontainer.env.
  log "ℹ️  Applying template: $tpl"
  # For debugging, you can log the values:
  # log "DEBUG: Using APP_ID=${APP_ID}, TENANT_ID=${TENANT_ID}, ESO_NS=${ESO_NS}, REGISTRY_NAME=${REGISTRY_NAME}, REGISTRY_NS=${REGISTRY_NS}, VAULT_URL=${VAULT_URL}, VAULT_ID=${VAULT_ID}, SA_NAME=${SA_NAME}"

  export APP_ID TENANT_ID ESO_NS REGISTRY_NAME REGISTRY_NS VAULT_URL VAULT_ID SA_NAME

  # Capture envsubst output for debugging if needed and to check if it's empty
  local substituted_yaml
  substituted_yaml=$(envsubst < "$tpl")

  if [[ -z "$substituted_yaml" || "$substituted_yaml" =~ ^[[:space:]]*$ ]]; then
    log "⚠️  WARN: envsubst resulted in empty or whitespace-only output for template $tpl. Skipping apply."
    log "DEBUG INFO for $tpl: APP_ID='${APP_ID}', TENANT_ID='${TENANT_ID}' (other vars: ESO_NS='${ESO_NS}', REGISTRY_NAME='${REGISTRY_NAME}', REGISTRY_NS='${REGISTRY_NS}', VAULT_URL='${VAULT_URL}', VAULT_ID='${VAULT_ID}', SA_NAME='${SA_NAME}')"
  else
    echo "$substituted_yaml" | kubectl apply -f -
  fi
}

apply_deployments() {                         # <── NEW
  log "📦  Applying all manifests in '$DEPLOY_DIR'"
  shopt -s nullglob
  local file
  for file in "$DEPLOY_DIR"/*.yaml.tpl "$DEPLOY_DIR"/*.yml.tpl; do
    [[ -e "$file" ]] || { log "⚠️  No YAMLs found in $DEPLOY_DIR"; break; }
    if [[ "$file" == *.tpl ]]; then
      apply_template "$file"
    else
      kubectl apply -f "$file"
    fi
  done
  shopt -u nullglob
}

###############################################################################
# 8. Execution order
###############################################################################
create_azure_blob_storage_account
create_kind_cluster
retry_proxy
patch_kubeconfigs
upload_openid_docs
install_workload_identity_webhook
ensure_radius_app_registration
run_rad_identity
install_radius
ensure_cluster_oidc_matches_storage

resolve_keyvault
install_external_secrets_operator
create_eso_service_account

# ▶ Apply every manifest in /workspaces/samples/deployments
apply_deployments  

log "🎉  wi-kind-setup complete – cluster ‘$KIND_CLUSTER_NAME’, storage ‘$AZURE_STORAGE_ACCOUNT’, Key Vault ‘$KEYVAULT_NAME’"