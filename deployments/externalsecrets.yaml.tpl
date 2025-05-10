apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: kv-vault
  namespace: ${REGISTRY_NS}
spec:
  refreshInterval: 1m
  secretStoreRef:
    kind: ClusterSecretStore
    name: azure-keyvault-store
  target:
    name: kv-vault
    creationPolicy: Owner
  dataFrom:
    - find:
        name:
          regexp: ".*"
