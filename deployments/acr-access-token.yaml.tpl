apiVersion: generators.external-secrets.io/v1alpha1
kind: ACRAccessToken
metadata:
  name: vpittamp-acr-token
  namespace: ${REGISTRY_NS}
spec:
  tenantId: ${TENANT_ID}
  registry: vpittamp.azurecr.io
  # scope: "repository:my-app:pull"
  environmentType: PublicCloud
  auth:
    workloadIdentity:
      serviceAccountRef:
        name: ${REGISTRY_NAME}
        namespace: ${REGISTRY_NS}
        audiences:
          - api://AzureADTokenExchange

