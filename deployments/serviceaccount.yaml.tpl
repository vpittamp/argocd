apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${REGISTRY_NAME}
  namespace: ${REGISTRY_NS}
  labels:
    azure.workload.identity/use: "true"
  annotations:
    azure.workload.identity/client-id: ${APP_ID}
    azure.workload.identity/tenant-id: ${TENANT_ID}