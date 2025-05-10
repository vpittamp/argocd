apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: azure-keyvault-store
spec:
  provider:
    azurekv:
      authType: WorkloadIdentity
      vaultUrl: ${VAULT_URL}
      serviceAccountRef:
        name: ${SA_NAME}
        namespace: ${ESO_NS}

