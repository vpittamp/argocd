apiVersion: external-secrets.io/v1beta1 
kind: ExternalSecret
metadata:
  name: vpittamp-acr-credentials
  namespace: ${REGISTRY_NS}
spec:
  refreshInterval: 3h
  dataFrom:
    - sourceRef:
        generatorRef:
          apiVersion: generators.external-secrets.io/v1alpha1
          kind: ACRAccessToken
          name: vpittamp-acr-token
 
  target:
    name: vpittamp-acr-dockercfg
    creationPolicy: Owner
    template:
      type: kubernetes.io/dockerconfigjson
      engineVersion: v2
      data:
        .dockerconfigjson: |
          {
            "auths": {
              "vpittamp.azurecr.io": {
                "username": "{{ .username }}",
                "password": "{{ .password }}"
              }
            }
          }
